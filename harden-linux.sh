#!/bin/bash
# secure-setup: Linux hardening for Ubuntu/Debian (apt) and Fedora/RHEL (dnf)
# Reports hardware, storage and security status, shows planned changes,
# applies them after one "yes", and asks separately for anything risky.
# Usage: bash harden-linux.sh [--report-only]
set -u

REPORT="$HOME/security-report-$(date +%Y%m%d-%H%M%S).txt"
REPORT_ONLY=0
[ "${1:-}" = "--report-only" ] && REPORT_ONLY=1

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
hdr() { log ""; log "=== $* ==="; }
ask() { local a; printf '%s [y/N] ' "$1"; read -r a </dev/tty; [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(uname)" = "Linux" ] || { echo "This script is for Linux only."; exit 1; }
if have apt-get; then PM=apt; elif have dnf; then PM=dnf; else echo "Unsupported distro (need apt or dnf)."; exit 1; fi
. /etc/os-release 2>/dev/null

log "secure-setup Linux report - $(date)"

hdr "Hardware"
log "Distro:  ${PRETTY_NAME:-unknown} (package manager: $PM)"
log "Kernel:  $(uname -r)"
log "CPU:     $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
log "Memory:  $(free -h | awk '/^Mem:/{print $2}')"

hdr "Storage"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null | tee -a "$REPORT" || lsblk | tee -a "$REPORT"
df -h / | tee -a "$REPORT"

hdr "Security status"
if lsblk -o TYPE 2>/dev/null | grep -q crypt; then ENC="yes (LUKS)"; else ENC="NO - disk is not encrypted"; fi
log "Disk encryption: $ENC"
if have mokutil; then log "Secure Boot:     $(mokutil --sb-state 2>/dev/null)"; fi
if have ufw; then log "Firewall (ufw):  $(ufw status 2>/dev/null | head -1 || echo 'needs sudo to check')"; fi
if have firewall-cmd; then log "Firewall (firewalld): $(firewall-cmd --state 2>/dev/null || echo 'not running')"; fi
have aa-status && log "AppArmor:        $(aa-enabled 2>/dev/null || echo unknown)"
have getenforce && log "SELinux:         $(getenforce)"
SSH_ON=0; systemctl is-active --quiet ssh 2>/dev/null && SSH_ON=1; systemctl is-active --quiet sshd 2>/dev/null && SSH_ON=1
log "SSH server:      $([ $SSH_ON = 1 ] && echo running || echo 'not running')"

if [ $REPORT_ONLY = 1 ]; then log ""; log "Report only. Saved to $REPORT"; exit 0; fi

hdr "Planned changes"
log " 1. Install all package updates"
log " 2. Firewall on: block incoming connections, allow outgoing (SSH kept open if it is running)"
log " 3. Automatic security updates"
log " 4. Safer kernel network settings (ignore redirects, SYN-flood protection, hide kernel pointers)"
log " 5. If SSH is running: forbid root login and limit password attempts"
log "Asked separately: turning SSH off. Disk encryption can only be set up at install time (advice given)."
echo
ask "Apply changes 1-5?" || { log "No changes made. Report saved to $REPORT"; exit 0; }

echo "Your password is needed for admin changes (typed into sudo, not stored)."
sudo -v || { echo "sudo failed; nothing changed."; exit 1; }
while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done 2>/dev/null &

hdr "Applying"
if [ $PM = apt ]; then
  sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade && log "[ok] Packages updated"
  sudo DEBIAN_FRONTEND=noninteractive apt-get -y install ufw unattended-upgrades >/dev/null
  sudo ufw default deny incoming >/dev/null
  sudo ufw default allow outgoing >/dev/null
  [ $SSH_ON = 1 ] && sudo ufw allow OpenSSH >/dev/null 2>&1
  sudo ufw --force enable >/dev/null && log "[ok] ufw firewall on"
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null
  log "[ok] Automatic security updates on (unattended-upgrades)"
else
  sudo dnf -y upgrade --refresh && log "[ok] Packages updated"
  sudo dnf -y install firewalld dnf-automatic >/dev/null 2>&1 || sudo dnf -y install firewalld dnf5-plugin-automatic >/dev/null 2>&1
  sudo systemctl enable --now firewalld >/dev/null 2>&1
  # Fedora Workstation's default zone opens ports 1025-65535; "public" only allows ssh/dhcpv6-client
  sudo firewall-cmd --set-default-zone=public >/dev/null 2>&1
  [ $SSH_ON = 0 ] && sudo firewall-cmd --permanent --zone=public --remove-service=ssh >/dev/null 2>&1
  sudo firewall-cmd --reload >/dev/null 2>&1 && log "[ok] firewalld on (zone: public)"
  if [ -f /etc/dnf/automatic.conf ]; then
    sudo sed -i 's/^apply_updates.*/apply_updates = yes/; s/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
  else
    printf '[commands]\nupgrade_type = security\napply_updates = yes\n' | sudo tee /etc/dnf/automatic.conf >/dev/null
  fi
  sudo systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || sudo systemctl enable --now dnf5-automatic.timer >/dev/null 2>&1
  log "[ok] Automatic security updates on (dnf-automatic)"
fi

sudo tee /etc/sysctl.d/99-secure-setup.conf >/dev/null <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
sudo sysctl --system >/dev/null 2>&1 && log "[ok] Kernel network hardening applied"

if [ $SSH_ON = 1 ]; then
  if ask "SSH server is running. Turn it off? (say No if you connect to this machine remotely)"; then
    sudo systemctl disable --now ssh 2>/dev/null; sudo systemctl disable --now sshd 2>/dev/null
    log "[ok] SSH off"
  else
    sudo mkdir -p /etc/ssh/sshd_config.d
    printf 'PermitRootLogin no\nMaxAuthTries 3\n' | sudo tee /etc/ssh/sshd_config.d/99-secure-setup.conf >/dev/null
    if sudo sshd -t 2>/dev/null; then
      sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null
      log "[ok] SSH: root login off, max 3 attempts"
    else
      sudo rm -f /etc/ssh/sshd_config.d/99-secure-setup.conf
      log "[skip] SSH config test failed; left SSH settings unchanged"
    fi
  fi
fi

hdr "Done"
case "$ENC" in NO*) log "Your disk is NOT encrypted. Linux can only encrypt the system disk at install time:"
                    log " back up, reinstall, and tick 'Encrypt the new installation' (Ubuntu) / 'Encrypt my data' (Fedora).";; esac
log "Recommended: reboot once to finish updates. Use a password manager and two-factor authentication."
log "Report saved to $REPORT"

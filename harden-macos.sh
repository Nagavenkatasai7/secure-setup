#!/bin/bash
# secure-setup: macOS hardening
# Reports hardware, storage and security status, shows planned changes,
# applies them after one "yes", and asks separately for anything risky.
# Usage: bash harden-macos.sh [--report-only]
set -u

REPORT="$HOME/security-report-$(date +%Y%m%d-%H%M%S).txt"
REPORT_ONLY=0
[ "${1:-}" = "--report-only" ] && REPORT_ONLY=1

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
hdr() { log ""; log "=== $* ==="; }
ask() { # ask "question" -> 0 if yes
  local a; printf '%s [y/N] ' "$1"; read -r a </dev/tty
  [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]
}

if [ "$(uname)" != "Darwin" ]; then echo "This script is for macOS only."; exit 1; fi

log "secure-setup macOS report - $(date)"

hdr "Hardware"
log "Model:   $(sysctl -n hw.model)"
log "Chip:    $(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
log "Memory:  $(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
log "macOS:   $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
log "Serial:  (not recorded)"

hdr "Storage"
df -h / | tee -a "$REPORT"
diskutil info / | grep -E "Device Node|File System Personality|Disk Size|Container Free Space|Solid State|SMART" | tee -a "$REPORT"

hdr "Security status"
FV=$(fdesetup status 2>/dev/null | head -1)
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
SIP=$(csrutil status 2>/dev/null)
GK=$(spctl --status 2>/dev/null)
AUTOCHECK=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "default")
SSH_ON=0; launchctl print system/com.openssh.sshd >/dev/null 2>&1 && SSH_ON=1
SCREENSHARE_ON=0; launchctl print system/com.apple.screensharing >/dev/null 2>&1 && SCREENSHARE_ON=1
log "FileVault:          $FV"
log "Firewall:           $FW"
log "Stealth mode:       $STEALTH"
log "SIP:                $SIP"
log "Gatekeeper:         $GK"
log "Auto update check:  $AUTOCHECK"
log "Remote Login (SSH): $([ $SSH_ON = 1 ] && echo ON || echo off)"
log "Screen Sharing:     $([ $SCREENSHARE_ON = 1 ] && echo ON || echo off)"

hdr "Pending software updates"
softwareupdate -l 2>&1 | tail -n +4 | tee -a "$REPORT"

if [ $REPORT_ONLY = 1 ]; then log ""; log "Report only. Saved to $REPORT"; exit 0; fi

hdr "Planned changes"
log " 1. Turn on the firewall and stealth mode (Mac ignores pings/probes)"
log " 2. Make sure Gatekeeper is on (only signed apps run)"
log " 3. Turn on automatic update checks, downloads, security responses and macOS updates"
log " 4. Turn off the guest account"
log " 5. Ask for the password immediately after sleep/screen saver"
log " 6. Turn off sending crash/analytics data to Apple and developers"
log "Asked separately: FileVault disk encryption, turning off SSH/Screen Sharing."
echo
if ! ask "Apply changes 1-6?"; then log "No changes made. Report saved to $REPORT"; exit 0; fi

echo "Your Mac password is needed for admin changes (typed into sudo, not stored)."
sudo -v || { echo "sudo failed; nothing changed."; exit 1; }
# keep sudo alive while the script runs
while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done 2>/dev/null &

hdr "Applying"
FWB=/usr/libexec/ApplicationFirewall/socketfilterfw
if echo "$FW" | grep -qi "disabled\|State = 0"; then
  sudo $FWB --setglobalstate on >/dev/null && log "[ok] Firewall on"
else
  log "[ok] Firewall already on (left at its current level)"
fi
sudo $FWB --setstealthmode on >/dev/null && log "[ok] Stealth mode on"
sudo spctl --global-enable 2>/dev/null || sudo spctl --master-enable 2>/dev/null
log "[ok] Gatekeeper: $(spctl --status 2>/dev/null)"
SU=/Library/Preferences/com.apple.SoftwareUpdate
for k in AutomaticCheckEnabled AutomaticDownload CriticalUpdateInstall ConfigDataInstall AutomaticallyInstallMacOSUpdates; do
  sudo defaults write $SU $k -bool true
done
sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
log "[ok] Automatic updates on"
sudo sysadminctl -guestAccount off >/dev/null 2>&1 && log "[ok] Guest account off"
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0
log "[ok] Password required immediately after sleep (if not applied, set it in System Settings > Lock Screen)"
DM="/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
sudo defaults write "$DM" AutoSubmit -bool false 2>/dev/null
sudo defaults write "$DM" ThirdPartyDataSubmit -bool false 2>/dev/null
log "[ok] Analytics sharing off"

if [ $SSH_ON = 1 ] && ask "Remote Login (SSH) is ON. Turn it off? (say No if you connect to this Mac remotely)"; then
  sudo launchctl disable system/com.openssh.sshd && sudo launchctl bootout system/com.openssh.sshd 2>/dev/null
  log "[ok] SSH off"
fi
if [ $SCREENSHARE_ON = 1 ] && ask "Screen Sharing is ON. Turn it off?"; then
  sudo launchctl disable system/com.apple.screensharing && sudo launchctl bootout system/com.apple.screensharing 2>/dev/null
  log "[ok] Screen Sharing off"
fi

if ! fdesetup status | grep -q "On"; then
  echo
  echo "FileVault encrypts your whole disk. It shows a RECOVERY KEY once; write it down"
  echo "or store it in your password manager. Losing both your password and the key = losing your data."
  if ask "Turn on FileVault now?"; then
    sudo fdesetup enable && log "[ok] FileVault enabling (finishes in background; may ask to restart)"
  fi
fi

hdr "Done"
log "Recommended manual steps:"
log " - Install pending updates: System Settings > General > Software Update"
log " - Review System Settings > Privacy & Security (camera, mic, Full Disk Access)"
log " - Use a password manager and turn on two-factor authentication everywhere"
log "Report saved to $REPORT"

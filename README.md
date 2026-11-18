# secure-setup

Security hardening scripts for a new or existing computer, made to be started from a
Flipper Zero BadUSB payload (or run by hand). Each script:

1. Reports hardware, storage and security status (encryption, firewall, updates, remote access).
2. Lists the changes it will make and applies them only after you answer **yes**.
3. Asks separately before disk encryption and before turning off remote access (SSH / RDP / Screen Sharing).
4. Saves a report to `~/security-report-<date>.txt`.

Passwords go only into the system's own `sudo` / UAC prompt; the scripts never read or store them.

| System | Script | Run by hand |
|---|---|---|
| macOS | `harden-macos.sh` | `bash harden-macos.sh` (`--report-only` to change nothing) |
| Ubuntu/Debian, Fedora/RHEL | `harden-linux.sh` | `bash harden-linux.sh` (`--report-only`) |
| Windows 10/11 | `harden-windows.ps1` | elevated PowerShell: `powershell -ExecutionPolicy Bypass -File harden-windows.ps1` (`-ReportOnly`) |

Only run these on computers you own or are allowed to administer.

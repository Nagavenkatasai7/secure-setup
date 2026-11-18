# secure-setup: Windows 10/11 hardening
# Reports hardware, storage and security status, shows planned changes,
# applies them after one "yes", and asks separately for anything risky.
# Run from an elevated PowerShell (the Flipper payload opens one through UAC).
# Usage: powershell -ExecutionPolicy Bypass -File harden-windows.ps1 [-ReportOnly]
param([switch]$ReportOnly)
$ErrorActionPreference = 'Continue'

$Report = Join-Path $env:USERPROFILE ("security-report-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
function Log($m) { Write-Host $m; Add-Content -Path $Report -Value $m }
function Hdr($m) { Log ""; Log "=== $m ===" }
function Ask($q) { $a = Read-Host "$q [y/N]"; return ($a -match '^(y|yes)$') }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Log "secure-setup Windows report - $(Get-Date)"

Hdr "Hardware"
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
Log ("Model:   {0} {1}" -f $cs.Manufacturer, $cs.Model)
Log "CPU:     $cpu"
Log ("Memory:  {0} GB" -f [math]::Round($cs.TotalPhysicalMemory / 1GB))
Log ("Windows: {0} build {1}" -f $os.Caption, $os.BuildNumber)

Hdr "Storage"
Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
  Log ("Disk: {0}  {1} GB  {2}  health={3}" -f $_.FriendlyName, [math]::Round($_.Size / 1GB), $_.MediaType, $_.HealthStatus) }
Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter | ForEach-Object {
  Log ("Volume {0}: {1} GB free of {2} GB ({3})" -f $_.DriveLetter, [math]::Round($_.SizeRemaining / 1GB), [math]::Round($_.Size / 1GB), $_.FileSystem) }

Hdr "Security status"
$blOK = $false
try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; $blOK = $true
      Log ("BitLocker ({0}): {1}, {2}%" -f $env:SystemDrive, $bl.ProtectionStatus, $bl.EncryptionPercentage) }
catch { Log "BitLocker: not available (Windows Home? check Settings > Privacy & security > Device encryption)" }
try { $tpm = Get-Tpm -ErrorAction Stop; Log "TPM: present=$($tpm.TpmPresent) ready=$($tpm.TpmReady)" } catch { Log "TPM: unknown" }
try { Log "Secure Boot: $(Confirm-SecureBootUEFI -ErrorAction Stop)" } catch { Log "Secure Boot: unknown / not UEFI" }
try { $mp = Get-MpComputerStatus -ErrorAction Stop
      Log "Defender: antivirus=$($mp.AntivirusEnabled) realtime=$($mp.RealTimeProtectionEnabled) signatures=$($mp.AntivirusSignatureLastUpdated)" }
catch { Log "Defender: unavailable (another antivirus may be installed)" }
Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { Log "Firewall $($_.Name): $($_.Enabled)" }
$smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
Log "SMBv1 (old, insecure file sharing): $smb1"
$rdpOn = ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0)
Log "Remote Desktop: $(if ($rdpOn) {'ON'} else {'off'})"
$lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
Log "UAC enabled: $($lua -eq 1)"

if ($ReportOnly) { Log ""; Log "Report only. Saved to $Report"; return }
if (-not $isAdmin) { Log "Not running as administrator; re-run from an elevated PowerShell to apply changes."; return }

Hdr "Planned changes"
Log " 1. Firewall on for all profiles (Domain, Private, Public)"
Log " 2. Defender real-time protection, cloud protection, block potentially unwanted apps; update signatures"
Log " 3. Turn off SMBv1"
Log " 4. Make sure UAC is on (admin prompts)"
Log " 5. Turn off AutoRun/AutoPlay for all drives (stops USB autorun malware)"
Log " 6. Lower telemetry, turn off advertising ID"
Log "Asked separately: BitLocker disk encryption, turning off Remote Desktop."
if (-not (Ask "Apply changes 1-6?")) { Log "No changes made. Report saved to $Report"; return }

Hdr "Applying"
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True; Log "[ok] Firewall on"
try {
  Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled -ErrorAction Stop
  Update-MpSignature -ErrorAction SilentlyContinue
  Log "[ok] Defender protection on, signatures updated"
} catch { Log "[skip] Defender settings: $($_.Exception.Message)" }
if ($smb1 -eq 'Enabled') { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null; Log "[ok] SMBv1 off (restart to finish)" }
else { Log "[ok] SMBv1 already off" }
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $sys -Name EnableLUA -Value 1 -Type DWord
$cpba = (Get-ItemProperty $sys -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
if ($null -eq $cpba -or $cpba -eq 0) { Set-ItemProperty $sys -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord; Log "[ok] UAC on (default prompt level)" }
else { Log "[ok] UAC on (kept your existing prompt level $cpba)" }
$exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
if (-not (Test-Path $exp)) { New-Item $exp -Force | Out-Null }
Set-ItemProperty $exp -Name NoDriveTypeAutoRun -Value 255 -Type DWord
Set-ItemProperty $exp -Name NoAutorun -Value 1 -Type DWord
Log "[ok] AutoRun off"
$dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
if (-not (Test-Path $dc)) { New-Item $dc -Force | Out-Null }
$tel = (Get-ItemProperty $dc -ErrorAction SilentlyContinue).AllowTelemetry
if ($null -eq $tel -or $tel -gt 1) { Set-ItemProperty $dc -Name AllowTelemetry -Value 1 -Type DWord }
$adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
if (-not (Test-Path $adv)) { New-Item $adv -Force | Out-Null }
Set-ItemProperty $adv -Name Enabled -Value 0 -Type DWord
Log "[ok] Telemetry lowered, advertising ID off"

if ($rdpOn -and (Ask "Remote Desktop is ON. Turn it off? (say No if you connect to this PC remotely)")) {
  Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Type DWord
  Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
  Log "[ok] Remote Desktop off"
}

if ($blOK -and $bl.VolumeStatus -ne 'FullyDecrypted' -and $bl.ProtectionStatus -ne 'On') {
  Log "[note] BitLocker is set up but suspended or still encrypting ($($bl.VolumeStatus)). Not adding another key. If suspended, run: Resume-BitLocker -MountPoint $($env:SystemDrive)"
}
if ($blOK -and $bl.VolumeStatus -eq 'FullyDecrypted') {
  Write-Host ""
  Write-Host "BitLocker encrypts the system drive. It creates a RECOVERY KEY (48 digits)."
  Write-Host "Save it in your password manager or Microsoft account. Without it you can lose your data."
  if (Ask "Turn on BitLocker for $($env:SystemDrive) now?") {
    try {
      $kp = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
      $rk = ($kp.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -Last 1).RecoveryPassword
      Write-Host ""; Write-Host "RECOVERY KEY: $rk" -ForegroundColor Yellow; Write-Host ""
      do { $c = Read-Host "Type SAVED once you have stored the recovery key" } until ($c -eq 'SAVED')
      Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -TpmProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
      Log "[ok] BitLocker encryption started (recovery key shown on screen, not saved in this report)"
    } catch { Log "[skip] BitLocker: $($_.Exception.Message)" }
  }
}

Hdr "Done"
Log "Recommended manual steps:"
Log " - Settings > Windows Update: install everything, then restart"
Log " - Use a password manager and turn on two-factor authentication everywhere"
Log "Report saved to $Report"

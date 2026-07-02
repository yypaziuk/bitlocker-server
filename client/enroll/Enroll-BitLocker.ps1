# ============================================================
# Enroll-BitLocker.ps1  -  enable BitLocker on a workstation and escrow the
# recovery key(s) to the on-prem escrow server (over HTTPS, cert-pinned).
#
# Run on each workstation WHILE it can reach the server (LAN). Portable.
#   right-click -> Run with PowerShell   (self-elevates)
#
# It will: pre-flight (admin/edition/TPM/server) -> enable BitLocker on C:
# (TPM + recovery password) and fixed data drives (recovery + auto-unlock) ->
# read the recovery key(s) -> POST to /enroll and WAIT for confirmation ->
# also save a local failsafe copy for the admin.
# ============================================================

# ---------------- CONFIG (edit per deployment) ----------------
# >>>ESCROW-CONFIG (managed by Apply-Config.ps1 - edit escrow.config.ps1, not here) >>>
$Server       = 'https://YOUR_SERVER_IP'
$EnrollSecret = 'YOUR_ENROLL_SECRET'
$CertSha256   = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
# <<<ESCROW-CONFIG<<<
$EncryptionMethod = "XtsAes256"     # fixed drives
$UsedSpaceOnly    = $true           # fast on freshly-installed machines
# --------------------------------------------------------------

$ErrorActionPreference = "Stop"

# ---- self-elevate ----
$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"")
    exit
}

function Fail($m) { Write-Host "`n[FAIL] $m" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
function Info($m) { Write-Host $m -ForegroundColor Cyan }

# ---- cert pinning for all HTTPS calls (compiled .NET delegate: robust on PS 5.1) ----
$pin = ($CertSha256 -replace '[^0-9A-Fa-f]', '').ToUpper()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
if (-not ('CertPin' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class CertPin {
    public static string Pin = "";
    public static bool Validate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors e) {
        try {
            byte[] h = SHA256.Create().ComputeHash(cert.GetRawCertData());
            return string.Equals(BitConverter.ToString(h).Replace("-",""), Pin, StringComparison.OrdinalIgnoreCase);
        } catch { return false; }
    }
}
"@
}
[CertPin]::Pin = $pin
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = `
    [System.Delegate]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback], [CertPin].GetMethod('Validate'))

function Invoke-Escrow($path, $method, $obj) {
    $json = $obj | ConvertTo-Json -Depth 6 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)   # force UTF-8 (Cyrillic OS caption)
    return Invoke-RestMethod -Uri "$Server$path" -Method $method -Body $bytes `
        -ContentType "application/json; charset=utf-8" -Headers @{ "X-Enroll-Secret" = $EnrollSecret } -TimeoutSec 30
}

# raw TLS connect to read the cert fingerprint the server actually presents (diagnostic)
function Get-ServerCertFingerprint {
    try {
        $u = [uri]$Server
        $p = $(if ($u.Port -gt 0) { $u.Port } else { 443 })
        $tcp = New-Object Net.Sockets.TcpClient($u.Host, $p)
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ([Net.Security.RemoteCertificateValidationCallback] { $true }))
        $ssl.AuthenticateAsClient($u.Host)
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($ssl.RemoteCertificate.GetRawCertData())
        $ssl.Close(); $tcp.Close()
        return [BitConverter]::ToString($hash).Replace("-", "")
    } catch { return $null }
}

# collect hardware/software inventory (CIM/WMI, no extra tools) for the Inventory tab
function Get-Inventory {
    $inv = @{}
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        if ($cpu) { $inv.cpu = "$($cpu.Name)".Trim(); $inv.cpu_cores = [int]$cpu.NumberOfCores; $inv.cpu_threads = [int]$cpu.NumberOfLogicalProcessors }
        if ($cs)  { $inv.ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB); $inv.last_user = "$($cs.UserName)"; $inv.domain = "$($cs.Domain)" }
        if ($bios) { $inv.bios_version = "$($bios.SMBIOSBIOSVersion)".Trim() }
        if ($bb)   { $inv.board = ("$($bb.Manufacturer) $($bb.Product)").Trim() }
        $inv.disks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object {
            @{ model = "$($_.Model)".Trim(); size_gb = [math]::Round($_.Size / 1GB) } })
        $cvol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($cvol) { $inv.c_size_gb = [math]::Round($cvol.Size / 1GB); $inv.c_free_gb = [math]::Round($cvol.FreeSpace / 1GB) }
        if ($os) {
            $inv.os_caption = "$($os.Caption)".Trim(); $inv.os_build = "$($os.BuildNumber)"; $inv.os_arch = "$($os.OSArchitecture)"
            try { $inv.os_install = $os.InstallDate.ToString('yyyy-MM-dd') } catch {}
            try { $inv.last_boot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'); $inv.uptime_days = [int]((Get-Date) - $os.LastBootUpTime).TotalDays } catch {}
        }
        $net = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($net) { $inv.ipv4 = ($net.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1); $inv.mac = "$($net.MACAddress)" }
        try { $t = Get-Tpm -ErrorAction SilentlyContinue; if ($t) { $inv.tpm_present = [bool]$t.TpmPresent; $inv.tpm_version = "$($t.ManufacturerVersion)".Trim([char]0) } } catch {}
        try { $inv.secure_boot = [bool](Confirm-SecureBootUEFI) } catch {}
        try { $inv.os_ubr = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -EA SilentlyContinue).UBR)" } catch {}
        try { $inv.last_logon = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser -EA SilentlyContinue).LastLoggedOnUser)" } catch {}
        try { $inv.pending_reboot = ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) } catch {}
        try { $mp = Get-MpComputerStatus -EA SilentlyContinue; if ($mp) { $inv.av_name = 'Defender'; $inv.av_rtp = [bool]$mp.RealTimeProtectionEnabled; $inv.av_age_days = [int]$mp.AntivirusSignatureAge } } catch {}
        try { $inv.disk_health = "$((Get-PhysicalDisk -EA SilentlyContinue | Select-Object -First 1).HealthStatus)" } catch {}
    } catch {}
    return $inv
}

Info "=== BitLocker enrollment ==="

# ---- pre-flight ----
$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -match "Home") { Fail "Windows Home does not support BitLocker. Use Pro/LTSC/Enterprise." }

$tpm = Get-Tpm
if (-not $tpm.TpmPresent)  { Fail "No TPM found. Enable TPM in BIOS/UEFI before enrolling." }
if (-not $tpm.TpmReady)    { Fail "TPM present but not ready. Initialize/enable TPM in BIOS, then retry." }
Info "TPM: present and ready."

# verify server reachable + cert pin BEFORE touching disks
try {
    $h = Invoke-RestMethod -Uri "$Server/healthz" -TimeoutSec 15
} catch {
    $seen = Get-ServerCertFingerprint
    if ($seen) {
        Write-Host "Expected cert (pin): $pin" -ForegroundColor Yellow
        Write-Host "Server presented   : $seen" -ForegroundColor Yellow
        if ($seen -ne $pin) {
            Fail "Cert fingerprint MISMATCH. If you trust this server, set `$CertSha256 in the script to the 'Server presented' value above and retry."
        }
        Fail "TLS/connection problem to $Server (fingerprint matches). $($_.Exception.Message)"
    }
    Fail "Cannot reach escrow server $Server (network). $($_.Exception.Message)"
}
if ($h.setup -ne $true)    { Fail "Escrow server is not initialized (master not set). Tell the admin to run escrow-unlock." }
if ($h.unlocked -ne $true) { Fail "Escrow server is LOCKED. Tell the admin to run escrow-unlock, then retry." }
Info "Escrow server reachable, unlocked, cert pinned OK."

# ---- machine identity ----
$bios = Get-CimInstance Win32_BIOS
$cs   = Get-CimInstance Win32_ComputerSystem
$csp  = Get-CimInstance Win32_ComputerSystemProduct
$machine = @{
    hostname     = $env:COMPUTERNAME
    serial       = $bios.SerialNumber
    manufacturer = $cs.Manufacturer
    model        = $cs.Model
    product      = $csp.Version    # friendly name, e.g. "ThinkPad L470"
    os_version   = "$($os.Caption) $($os.Version)"
}
$machine.inventory = Get-Inventory

# ---- system drive ----
$osDrive = $env:SystemDrive          # usually C:

function Enable-Vol($mount, $isOs) {
    $bv = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
    if ($bv.VolumeStatus -eq 'FullyDecrypted') {
        Info "Enabling BitLocker on $mount ..."
        if ($isOs) {
            Enable-BitLocker -MountPoint $mount -EncryptionMethod $EncryptionMethod -UsedSpaceOnly:$UsedSpaceOnly -TpmProtector -SkipHardwareTest | Out-Null
        } else {
            Enable-BitLocker -MountPoint $mount -EncryptionMethod $EncryptionMethod -UsedSpaceOnly:$UsedSpaceOnly -RecoveryPasswordProtector | Out-Null
        }
    } else {
        Info "$mount already encrypted ($($bv.VolumeStatus), protection $($bv.ProtectionStatus)) - ensuring protectors + activation."
    }
    # OS drive needs a TPM protector so it unlocks at boot AND protection can activate
    # (covers OEM 'Automatic Device Encryption' drives left waiting-for-activation with a clear key)
    $bv = Get-BitLockerVolume -MountPoint $mount
    if ($isOs -and -not ($bv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' })) {
        try { Add-BitLockerKeyProtector -MountPoint $mount -TpmProtector | Out-Null } catch {}
    }
    # ensure a recovery password protector exists
    $bv = Get-BitLockerVolume -MountPoint $mount
    if (-not ($bv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })) {
        Add-BitLockerKeyProtector -MountPoint $mount -RecoveryPasswordProtector | Out-Null
    }
    if (-not $isOs) {
        try { Enable-BitLockerAutoUnlock -MountPoint $mount | Out-Null } catch {}
    }
    # encrypted but protection OFF (clear key / 'waiting for activation') => activate protection
    $bv = Get-BitLockerVolume -MountPoint $mount
    if ($bv.VolumeStatus -ne 'FullyDecrypted' -and $bv.ProtectionStatus -ne 'On') {
        Info "$mount was 'waiting for activation' - enabling protection (removing clear key)."
        try { Resume-BitLocker -MountPoint $mount | Out-Null } catch {}
        try { & manage-bde.exe -protectors -enable $mount 2>$null | Out-Null } catch {}
    }
    $bv = Get-BitLockerVolume -MountPoint $mount
    $rp = $bv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
    $guid = (Get-Volume -DriveLetter $mount.TrimEnd(':') -ErrorAction SilentlyContinue).UniqueId
    return @{
        mount             = $mount
        volume_guid       = $guid
        protector_id      = $rp.KeyProtectorId
        recovery_password = $rp.RecoveryPassword
        enc_method        = "$($bv.EncryptionMethod)"
        status            = "$($bv.VolumeStatus)"
        protection        = "$($bv.ProtectionStatus)"
        pct               = [int]$bv.EncryptionPercentage
    }
}

# ---- choose which drives to encrypt (interactive) ----
$cands = @()
$cands += [pscustomobject]@{ Mount = $osDrive; IsOs = $true; Label = "System" }
Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and ("$($_.DriveLetter):" -ne $osDrive) } | ForEach-Object {
    $lbl = "Data"
    if ($_.FileSystemLabel) { $lbl = "Data '" + $_.FileSystemLabel + "'" }
    $cands += [pscustomobject]@{ Mount = "$($_.DriveLetter):"; IsOs = $false; Label = $lbl }
}

Write-Host ""
Write-Host "Drives available for BitLocker:" -ForegroundColor Cyan
for ($i = 0; $i -lt $cands.Count; $i++) {
    $c = $cands[$i]
    $st = (Get-BitLockerVolume -MountPoint $c.Mount -ErrorAction SilentlyContinue).VolumeStatus
    if ($c.IsOs) { $how = "TPM unlock at boot" } else { $how = "auto-unlock, no password" }
    Write-Host ("  [{0}] {1}  {2}  ->  {3}   (now: {4})" -f ($i + 1), $c.Mount, $c.Label, $how, $st)
}
Write-Host ""
$sel = Read-Host "Encrypt which?  [Enter]=ALL   S=system only   or numbers e.g. 1,2"

$chosen = @()
if ([string]::IsNullOrWhiteSpace($sel)) {
    $chosen = $cands
} elseif ($sel.Trim().ToUpper() -eq 'S') {
    $chosen = @($cands | Where-Object { $_.IsOs })
} else {
    foreach ($n in ($sel -split '[,\s]+' | Where-Object { $_ })) {
        $idx = 0
        if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $cands.Count) { $chosen += $cands[$idx - 1] }
    }
}
if (-not $chosen) { Fail "Nothing selected." }

# data-drive auto-unlock requires the system drive to be BitLocker-protected
$osChosen = @($chosen | Where-Object { $_.IsOs })
$dataChosen = @($chosen | Where-Object { -not $_.IsOs })
if ($dataChosen.Count -gt 0 -and $osChosen.Count -eq 0) {
    $osBv = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction SilentlyContinue
    if (-not $osBv -or $osBv.ProtectionStatus -ne 'On') {
        Write-Host "Data-drive auto-unlock needs the SYSTEM drive ($osDrive) encrypted." -ForegroundColor Yellow
        $ans = Read-Host "Include the system drive too? [Y/n]"
        if ($ans -match '^[Nn]') { Fail "Aborted: encrypt the system drive first (or include it)." }
        $chosen = @($cands | Where-Object { $_.IsOs }) + $chosen
    }
}

Write-Host ("Will encrypt: " + (($chosen | ForEach-Object { $_.Mount }) -join ', ')) -ForegroundColor Cyan

# OS first (so data auto-unlock can bind to it)
$volumes = @()
foreach ($c in ($chosen | Sort-Object -Property @{ Expression = { -not $_.IsOs } })) {
    $volumes += Enable-Vol $c.Mount $c.IsOs
}

# ---- failsafe local copy (before sending) ----
$failsafe = Join-Path ([Environment]::GetFolderPath('Desktop')) "BitLocker-Recovery-$($env:COMPUTERNAME)-$(Get-Date -Format yyyyMMdd-HHmmss).txt"
$dump = @"
BitLocker Recovery Information   (KEEP SAFE / hand to admin)
============================================================
Computer : $($machine.hostname)
MBO/User : ____________________________
Device   : $($machine.manufacturer) $($machine.product)
Model    : $($machine.model)
Serial   : $($machine.serial)
OS       : $($machine.os_version)
Date     : $(Get-Date)

"@
foreach ($v in $volumes) {
    $dump += "[$($v.mount)]  status=$($v.status)  method=$($v.enc_method)`r`n"
    $dump += "  Recovery Key ID : $($v.protector_id)`r`n"
    $dump += "  Recovery Key    : $($v.recovery_password)`r`n`r`n"
}
$dump | Out-File -FilePath $failsafe -Encoding UTF8
Info "Failsafe copy saved: $failsafe"

# ---- escrow to server (REQUIRE confirmation) ----
$payload = $machine.Clone()
$payload.volumes = $volumes
Info "Sending recovery key(s) to escrow server ..."
try {
    $resp = Invoke-Escrow "/enroll" "POST" $payload
} catch {
    Write-Host "`n[ERROR] Escrow upload FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "BitLocker IS enabled and the key IS saved locally:" -ForegroundColor Yellow
    Write-Host "  $failsafe" -ForegroundColor Yellow
    Write-Host "Re-run this script when the server is reachable to complete escrow." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"; exit 2
}
if ($resp.status -ne "stored") { Fail "Server did not confirm storage. Response: $($resp | ConvertTo-Json -Compress)" }

Write-Host "`n[OK] Escrow confirmed by server (machine_id $($resp.machine_id), volumes $($resp.volumes))." -ForegroundColor Green
foreach ($v in $volumes) { Write-Host ("  {0}  {1}  {2}" -f $v.mount, $v.status, $v.recovery_password) }

# ---- deploy phone-home audit (keeps last_seen / status fresh) ----
try {
    $dir = Join-Path $env:ProgramData "BLEscrow"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $auditPs = Join-Path $dir "audit.ps1"
    $content = @'
# Auto-generated phone-home audit. Pins server cert via scriptblock callback:
# NO Add-Type (avoids csc.exe under app-control), NO cert-store, NO raw SslStream.
# Logs every attempt (incl. LanguageMode) to C:\ProgramData\BLEscrow\audit.log.
$ErrorActionPreference='Stop'
$Server='__SERVER__'; $EnrollSecret='__SECRET__'
$LogDir=Join-Path $env:ProgramData 'BLEscrow'
$Log=Join-Path $LogDir 'audit.log'
if(-not(Test-Path $LogDir)){New-Item -ItemType Directory -Force -Path $LogDir|Out-Null}
function Write-Log($m){Add-Content -Path $Log -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+'  '+$m) -Encoding UTF8}
function Get-Inv{
  $i=@{}
  try{
    $cs=Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    $os=Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
    $bios=Get-CimInstance Win32_BIOS -EA SilentlyContinue
    $cpu=Get-CimInstance Win32_Processor -EA SilentlyContinue|Select-Object -First 1
    $bb=Get-CimInstance Win32_BaseBoard -EA SilentlyContinue
    if($cpu){$i.cpu="$($cpu.Name)".Trim();$i.cpu_cores=[int]$cpu.NumberOfCores;$i.cpu_threads=[int]$cpu.NumberOfLogicalProcessors}
    if($cs){$i.ram_gb=[math]::Round($cs.TotalPhysicalMemory/1GB);$i.last_user="$($cs.UserName)";$i.domain="$($cs.Domain)"}
    if($bios){$i.bios_version="$($bios.SMBIOSBIOSVersion)".Trim()}
    if($bb){$i.board=("$($bb.Manufacturer) $($bb.Product)").Trim()}
    $i.disks=@(Get-CimInstance Win32_DiskDrive -EA SilentlyContinue|ForEach-Object{@{model="$($_.Model)".Trim();size_gb=[math]::Round($_.Size/1GB)}})
    $cv=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA SilentlyContinue
    if($cv){$i.c_size_gb=[math]::Round($cv.Size/1GB);$i.c_free_gb=[math]::Round($cv.FreeSpace/1GB)}
    if($os){$i.os_caption="$($os.Caption)".Trim();$i.os_build="$($os.BuildNumber)";$i.os_arch="$($os.OSArchitecture)";try{$i.os_install=$os.InstallDate.ToString('yyyy-MM-dd')}catch{};try{$i.last_boot=$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm');$i.uptime_days=[int]((Get-Date)-$os.LastBootUpTime).TotalDays}catch{}}
    $n=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -EA SilentlyContinue|Where-Object{$_.IPAddress}|Select-Object -First 1
    if($n){$i.ipv4=($n.IPAddress|Where-Object{$_ -match '^\d+\.\d+\.\d+\.\d+$'}|Select-Object -First 1);$i.mac="$($n.MACAddress)"}
    try{$t=Get-Tpm -EA SilentlyContinue;if($t){$i.tpm_present=[bool]$t.TpmPresent;$i.tpm_version="$($t.ManufacturerVersion)".Trim([char]0)}}catch{}
    try{$i.secure_boot=[bool](Confirm-SecureBootUEFI)}catch{}
    try{$i.os_ubr="$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -EA SilentlyContinue).UBR)"}catch{}
    try{$i.last_logon="$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser -EA SilentlyContinue).LastLoggedOnUser)"}catch{}
    try{$i.pending_reboot=((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'))}catch{}
    try{$mp=Get-MpComputerStatus -EA SilentlyContinue;if($mp){$i.av_name='Defender';$i.av_rtp=[bool]$mp.RealTimeProtectionEnabled;$i.av_age_days=[int]$mp.AntivirusSignatureAge}}catch{}
    try{$i.disk_health="$((Get-PhysicalDisk -EA SilentlyContinue|Select-Object -First 1).HealthStatus)"}catch{}
  }catch{}
  $i
}
$lang=$ExecutionContext.SessionState.LanguageMode
try{$who=[Security.Principal.WindowsIdentity]::GetCurrent().Name}catch{$who='?'}
try{
  [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
  [Net.ServicePointManager]::ServerCertificateValidationCallback={
    param($s,$cert,$chain,$errs)
    $h=[Security.Cryptography.SHA256]::Create().ComputeHash($cert.GetRawCertData())
    ([BitConverter]::ToString($h)-replace'-','') -eq '__PIN__'
  }
  $vols=@()
  foreach($bv in (Get-BitLockerVolume)){
    if($bv.KeyProtector|Where-Object{$_.KeyProtectorType -eq 'RecoveryPassword'}){
      $vols+=@{mount=$bv.MountPoint;status=[string]$bv.VolumeStatus;protection=[string]$bv.ProtectionStatus;pct=[int]$bv.EncryptionPercentage}
    }
  }
  $body=@{hostname=$env:COMPUTERNAME;volumes=$vols;inventory=(Get-Inv)}|ConvertTo-Json -Depth 6 -Compress
  $resp=Invoke-RestMethod -Uri "$Server/audit" -Method POST -Body $body -ContentType 'application/json; charset=utf-8' -Headers @{'X-Enroll-Secret'=$EnrollSecret} -TimeoutSec 25
  Write-Log "OK lang=$lang user=$who status=$($resp.status) vols=$($vols.Count)"
}catch{
  $code=''
  if($_.Exception.Response){$code=" http=$([int]$_.Exception.Response.StatusCode)"}
  Write-Log "ERR lang=$lang user=$who$code msg=$($_.Exception.Message)"
}finally{
  [Net.ServicePointManager]::ServerCertificateValidationCallback=$null
}
'@
    $content = $content.Replace("__SERVER__", $Server).Replace("__SECRET__", $EnrollSecret).Replace("__PIN__", $pin)
    Set-Content -Path $auditPs -Value $content -Encoding UTF8
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$auditPs`""
    $tDaily  = New-ScheduledTaskTrigger -Daily -At 12:00pm
    $tStart  = New-ScheduledTaskTrigger -AtStartup
    $tLogon  = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable
    Register-ScheduledTask -TaskName "BLEscrow-Audit" -Action $action -Trigger $tDaily,$tStart,$tLogon -Principal $principal -Settings $settings -Force | Out-Null
    Info "Phone-home audit task installed (BLEscrow-Audit: startup + logon + daily 12:00, network-aware)."
} catch {
    Write-Host "[warn] could not install phone-home task: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`nDone. BitLocker enabled and recovery key escrowed." -ForegroundColor Green
Read-Host "Press Enter to close"

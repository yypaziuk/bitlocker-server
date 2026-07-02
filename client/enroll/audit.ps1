# BLEscrow phone-home audit (reports BitLocker status to the escrow server).
# Pins the server cert via a scriptblock validation callback - NO Add-Type
# (avoids csc.exe under app-control), NO cert-store dependency, NO raw SslStream.
# Logs every attempt (incl. LanguageMode) to C:\ProgramData\BLEscrow\audit.log.
$ErrorActionPreference = 'Stop'
# >>>ESCROW-CONFIG (managed by Apply-Config.ps1 - edit escrow.config.ps1, not here) >>>
$Server       = 'https://YOUR_SERVER_IP'
$EnrollSecret = 'YOUR_ENROLL_SECRET'
$Pin          = 'YOUR_CERT_SHA256_NO_COLONS'
# <<<ESCROW-CONFIG<<<
$LogDir = Join-Path $env:ProgramData 'BLEscrow'
$Log    = Join-Path $LogDir 'audit.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

function Write-Log($m) {
    Add-Content -Path $Log -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $m) -Encoding UTF8
}
function Get-Inv {
    $i = @{}
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
        $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -EA SilentlyContinue
        $cpu = Get-CimInstance Win32_Processor -EA SilentlyContinue | Select-Object -First 1
        $bb = Get-CimInstance Win32_BaseBoard -EA SilentlyContinue
        if ($cpu) { $i.cpu = "$($cpu.Name)".Trim(); $i.cpu_cores = [int]$cpu.NumberOfCores; $i.cpu_threads = [int]$cpu.NumberOfLogicalProcessors }
        if ($cs)  { $i.ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB); $i.last_user = "$($cs.UserName)"; $i.domain = "$($cs.Domain)" }
        if ($bios) { $i.bios_version = "$($bios.SMBIOSBIOSVersion)".Trim() }
        if ($bb)   { $i.board = ("$($bb.Manufacturer) $($bb.Product)").Trim() }
        $i.disks = @(Get-CimInstance Win32_DiskDrive -EA SilentlyContinue | ForEach-Object { @{ model = "$($_.Model)".Trim(); size_gb = [math]::Round($_.Size / 1GB) } })
        $cv = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA SilentlyContinue
        if ($cv) { $i.c_size_gb = [math]::Round($cv.Size / 1GB); $i.c_free_gb = [math]::Round($cv.FreeSpace / 1GB) }
        if ($os) {
            $i.os_caption = "$($os.Caption)".Trim(); $i.os_build = "$($os.BuildNumber)"; $i.os_arch = "$($os.OSArchitecture)"
            try { $i.os_install = $os.InstallDate.ToString('yyyy-MM-dd') } catch {}
            try { $i.last_boot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'); $i.uptime_days = [int]((Get-Date) - $os.LastBootUpTime).TotalDays } catch {}
        }
        $n = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -EA SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($n) { $i.ipv4 = ($n.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1); $i.mac = "$($n.MACAddress)" }
        try { $t = Get-Tpm -EA SilentlyContinue; if ($t) { $i.tpm_present = [bool]$t.TpmPresent; $i.tpm_version = "$($t.ManufacturerVersion)".Trim([char]0) } } catch {}
        try { $i.secure_boot = [bool](Confirm-SecureBootUEFI) } catch {}
        try { $i.os_ubr = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -EA SilentlyContinue).UBR)" } catch {}
        try { $i.last_logon = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser -EA SilentlyContinue).LastLoggedOnUser)" } catch {}
        try { $i.pending_reboot = ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) } catch {}
        try { $mp = Get-MpComputerStatus -EA SilentlyContinue; if ($mp) { $i.av_name = 'Defender'; $i.av_rtp = [bool]$mp.RealTimeProtectionEnabled; $i.av_age_days = [int]$mp.AntivirusSignatureAge } } catch {}
        try { $i.disk_health = "$((Get-PhysicalDisk -EA SilentlyContinue | Select-Object -First 1).HealthStatus)" } catch {}
    } catch {}
    $i
}

$lang = $ExecutionContext.SessionState.LanguageMode
try { $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = '?' }

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($s, $cert, $chain, $errs)
        $h = [Security.Cryptography.SHA256]::Create().ComputeHash($cert.GetRawCertData())
        ([BitConverter]::ToString($h) -replace '-', '') -eq 'YOUR_CERT_SHA256_NO_COLONS'
    }
    $vols = @()
    foreach ($bv in (Get-BitLockerVolume)) {
        $rp = $bv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
        if ($rp) {
            $vols += @{ mount = $bv.MountPoint; status = [string]$bv.VolumeStatus; protection = [string]$bv.ProtectionStatus; pct = [int]$bv.EncryptionPercentage; protector_id = [string]$rp.KeyProtectorId }
        }
    }
    $body = @{ hostname = $env:COMPUTERNAME; volumes = $vols; inventory = (Get-Inv) } | ConvertTo-Json -Depth 6 -Compress
    $resp = Invoke-RestMethod -Uri "$Server/audit" -Method POST -Body $body `
        -ContentType 'application/json; charset=utf-8' `
        -Headers @{ 'X-Enroll-Secret' = $EnrollSecret } -TimeoutSec 25
    Write-Log "OK lang=$lang user=$who status=$($resp.status) vols=$($vols.Count)"
} catch {
    $code = ''
    if ($_.Exception.Response) { $code = " http=$([int]$_.Exception.Response.StatusCode)" }
    Write-Log "ERR lang=$lang user=$who$code msg=$($_.Exception.Message)"
} finally {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

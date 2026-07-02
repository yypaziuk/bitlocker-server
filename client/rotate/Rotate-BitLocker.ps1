# ============================================================
# Rotate-BitLocker.ps1  -  rotate (re-issue) the BitLocker recovery password
# on a workstation and re-escrow the new one. Use after a key was revealed/used.
#
# Per volume: add a NEW recovery protector -> re-escrow it (wait for confirm) ->
# remove the OLD recovery protector(s). The escrowed key always matches the live one.
#   right-click -> Run with PowerShell   (self-elevates)
# ============================================================

# ---------------- CONFIG (same as Enroll-BitLocker.ps1) ----------------
# >>>ESCROW-CONFIG (managed by Apply-Config.ps1 - edit escrow.config.ps1, not here) >>>
$Server       = 'https://YOUR_SERVER_IP'
$EnrollSecret = 'YOUR_ENROLL_SECRET'
$CertSha256   = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
# <<<ESCROW-CONFIG<<<
# ----------------------------------------------------------------------
$ErrorActionPreference = "Stop"

$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"")
    exit
}
function Fail($m) { Write-Host "`n[FAIL] $m" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
function Info($m) { Write-Host $m -ForegroundColor Cyan }

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
function Invoke-Escrow($path, $obj) {
    $json = $obj | ConvertTo-Json -Depth 6 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)   # force UTF-8 (Cyrillic OS caption)
    return Invoke-RestMethod -Uri "$Server$path" -Method POST -Body $bytes `
        -ContentType "application/json; charset=utf-8" -Headers @{ "X-Enroll-Secret" = $EnrollSecret } -TimeoutSec 30
}

Info "=== BitLocker key rotation ==="
try { $h = Invoke-RestMethod -Uri "$Server/healthz" -TimeoutSec 15 } catch { Fail "Cannot reach server / cert mismatch. $($_.Exception.Message)" }
if ($h.unlocked -ne $true) { Fail "Escrow server is LOCKED. Ask admin to run escrow-unlock, then retry." }

$bios = Get-CimInstance Win32_BIOS; $cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
$csp = Get-CimInstance Win32_ComputerSystemProduct
$machine = @{ hostname=$env:COMPUTERNAME; serial=$bios.SerialNumber; manufacturer=$cs.Manufacturer; model=$cs.Model; product=$csp.Version; os_version="$($os.Caption) $($os.Version)" }

# encrypted volumes with a recovery protector
$targets = Get-BitLockerVolume | Where-Object { $_.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } }
if (-not $targets) { Fail "No BitLocker volumes with a recovery password found (run Enroll-BitLocker.ps1 first)." }

$volumes = @()
foreach ($bv in $targets) {
    $mp = $bv.MountPoint
    $old = @($bv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
    Info "Rotating $mp ..."
    Add-BitLockerKeyProtector -MountPoint $mp -RecoveryPasswordProtector | Out-Null
    $after = (Get-BitLockerVolume -MountPoint $mp).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    $new = $after | Where-Object { $_.KeyProtectorId -notin ($old | ForEach-Object KeyProtectorId) } | Select-Object -First 1
    if (-not $new) { Fail "Could not add a new recovery protector on $mp." }
    $guid = (Get-Volume -DriveLetter $mp.TrimEnd(':') -ErrorAction SilentlyContinue).UniqueId
    $volumes += @{ mount=$mp; volume_guid=$guid; protector_id=$new.KeyProtectorId; recovery_password=$new.RecoveryPassword;
                   enc_method="$($bv.EncryptionMethod)"; status="$($bv.VolumeStatus)"; _old=$old; _bv=$mp }
}

# escrow the NEW keys (server upserts by mount -> replaces old stored key)
$payload = $machine.Clone()
$payload.volumes = $volumes | ForEach-Object { @{ mount=$_.mount; volume_guid=$_.volume_guid; protector_id=$_.protector_id; recovery_password=$_.recovery_password; enc_method=$_.enc_method; status=$_.status } }
Info "Re-escrowing new key(s)..."
try { $resp = Invoke-Escrow "/enroll" $payload } catch { Fail "Escrow upload failed - OLD keys NOT removed (still valid). $($_.Exception.Message)" }
if ($resp.status -ne "stored") { Fail "Server did not confirm storage - OLD keys NOT removed." }
Info "New key(s) escrowed and confirmed."

# only now remove the OLD recovery protectors
foreach ($v in $volumes) {
    foreach ($o in $v._old) {
        Remove-BitLockerKeyProtector -MountPoint $v.mount -KeyProtectorId $o.KeyProtectorId | Out-Null
    }
    Write-Host ("  {0}  new key: {1}" -f $v.mount, $v.recovery_password) -ForegroundColor Green
}
Write-Host "`n[OK] Rotation complete. Old recovery keys removed; new ones escrowed." -ForegroundColor Green
Read-Host "Press Enter to close"

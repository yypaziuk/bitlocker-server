# Propagate escrow.config.ps1 into the client scripts (single source of truth).
# Rewrites only the region between the  >>>ESCROW-CONFIG ... <<<ESCROW-CONFIG<<<
# markers (so runtime heredoc placeholders are never touched), plus the pinned
# fingerprint literal inside audit.ps1's TLS callback.
#   .\Apply-Config.ps1     then rebuild EXEs.
param([string]$ConfigPath)
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $dir 'escrow.config.ps1' }
. $ConfigPath
$pin = ($CertSha256 -replace '[^0-9A-Fa-f]', '').ToUpper()

$utf8 = New-Object System.Text.UTF8Encoding $false   # no BOM

function Set-ConfigBlock($file, $body) {
    if (-not (Test-Path $file)) { Write-Host "skip (missing): $file"; return }
    $t = [IO.File]::ReadAllText($file)
    $pat = '(?s)(#\s*>>>ESCROW-CONFIG[^\r\n]*\r?\n).*?(#\s*<<<ESCROW-CONFIG<<<)'
    if (-not [regex]::IsMatch($t, $pat)) { throw "no ESCROW-CONFIG markers in $file" }
    $t = [regex]::Replace($t, $pat, { param($m) $m.Groups[1].Value + $body + "`r`n" + $m.Groups[2].Value })
    [IO.File]::WriteAllText($file, $t, $utf8)
    Write-Host "updated: $file"
}

# enroll + rotate use the colon-form fingerprint in $CertSha256
$ers = "`$Server       = '$Server'`r`n`$EnrollSecret = '$EnrollSecret'`r`n`$CertSha256   = '$CertSha256'"
Set-ConfigBlock (Join-Path $dir 'enroll\Enroll-BitLocker.ps1') $ers
Set-ConfigBlock (Join-Path $dir 'rotate\Rotate-BitLocker.ps1') $ers

# audit.ps1 uses the colon-stripped fingerprint in $Pin (+ a literal in the callback)
$audit = Join-Path $dir 'enroll\audit.ps1'
$auf = "`$Server       = '$Server'`r`n`$EnrollSecret = '$EnrollSecret'`r`n`$Pin          = '$pin'"
Set-ConfigBlock $audit $auf
if (Test-Path $audit) {
    $t = [IO.File]::ReadAllText($audit)
    $t = [regex]::Replace($t, "-eq '[0-9A-Fa-f]{64}'", "-eq '$pin'")
    [IO.File]::WriteAllText($audit, $t, $utf8)
}

Write-Host "`nDone. Now rebuild the EXEs:"
Write-Host "  enroll\Build-EnrollExe.ps1 -Thumbprint <codesign-thumbprint>"
Write-Host "  rotate\Build-RotateExe.ps1 -Thumbprint <codesign-thumbprint>"

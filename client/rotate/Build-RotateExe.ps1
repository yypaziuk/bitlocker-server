# Build a single signed Rotate-BitLocker.exe from Rotate-BitLocker.ps1 (PS2EXE).
# One file, double-click, AppLocker-friendly (signed). Requires ps2exe module.
#   .\Build-RotateExe.ps1 -Thumbprint F2AAFBF70F7585FC6762C67D782F138B034FE500
#   .\Build-RotateExe.ps1 -Pfx "C:\path	o\CodeSign.pfx" -Password "***"
param(
    [string]$Pfx,
    [string]$Password,
    [string]$Thumbprint
)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $dir "Rotate-BitLocker.ps1"
$out = Join-Path $dir "Rotate-BitLocker.exe"

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "Installing ps2exe..."; Install-Module ps2exe -Scope CurrentUser -Force
}
Import-Module ps2exe
Write-Host "Compiling -> Rotate-BitLocker.exe"
Invoke-ps2exe -inputFile $src -outputFile $out -requireAdmin `
    -title "BitLocker Key Rotation" -product "BitLocker Escrow Rotate" -company "YourOrg" -version "1.0.0.0" -noConfigFile

if ($Pfx -or $Thumbprint) {
    if ($Pfx) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, $Password, 'Exportable,PersistKeySet')
    } else {
        $cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint"
    }
    $r = Set-AuthenticodeSignature -FilePath $out -Certificate $cert -HashAlgorithm SHA256 `
            -TimestampServer "http://timestamp.digicert.com" -ErrorAction Stop
    Write-Host ("Signature: " + $r.Status)
} else {
    Write-Host "NOTE: built UNSIGNED (pass -Pfx/-Password or -Thumbprint to sign)."
}
Write-Host "Done: $out"

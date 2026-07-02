# Auto-generated phone-home audit (reports BitLocker status to escrow server).
$Server = "https://YOUR_SERVER_IP"; $EnrollSecret = "YOUR_ENROLL_SECRET"; $pin = "YOUR_CERT_SHA256_NO_COLONS"
[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12
if(-not('CertPin' -as [type])){Add-Type -TypeDefinition @"
using System;using System.Net.Security;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;
public static class CertPin{public static string Pin="";public static bool Validate(object s,X509Certificate c,X509Chain ch,SslPolicyErrors e){try{byte[] h=SHA256.Create().ComputeHash(c.GetRawCertData());return string.Equals(BitConverter.ToString(h).Replace("-",""),Pin,StringComparison.OrdinalIgnoreCase);}catch{return false;}}}
"@}
[CertPin]::Pin=$pin
[System.Net.ServicePointManager]::ServerCertificateValidationCallback=[System.Delegate]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback],[CertPin].GetMethod('Validate'))
try{
  $vols=@(Get-BitLockerVolume | Where-Object {$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}} | ForEach-Object {@{mount=$_.MountPoint;status="$($_.VolumeStatus)";protection="$($_.ProtectionStatus)"}})
  $body=@{hostname=$env:COMPUTERNAME;volumes=$vols} | ConvertTo-Json -Depth 5 -Compress
  $bytes=[System.Text.Encoding]::UTF8.GetBytes($body)
  Invoke-RestMethod -Uri "$Server/audit" -Method POST -Body $bytes -ContentType "application/json; charset=utf-8" -Headers @{"X-Enroll-Secret"=$EnrollSecret} -TimeoutSec 20 | Out-Null
}catch{}

# escrow.config.ps1 - single source of truth for client scripts.
# Copy this file to escrow.config.ps1 and fill in real values from the server.
# Run  .\Apply-Config.ps1  after editing to propagate values into enroll/rotate scripts,
# then rebuild EXEs: enroll\Build-EnrollExe.ps1 + rotate\Build-RotateExe.ps1

# Values are printed by provision.py after first bootstrap.
$Server       = 'https://YOUR_SERVER_IP'
$EnrollSecret = 'ENROLL_SECRET_FROM_BOOTSTRAP'
# Server TLS cert SHA-256 fingerprint (colon form: openssl x509 -noout -fingerprint -sha256 -in cert.pem)
$CertSha256   = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'

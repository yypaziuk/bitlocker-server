#!/usr/bin/env python3
"""Create a web-portal admin (username + password + TOTP 2FA).
Run on the server:  sudo escrow-adduser
Shows an ASCII QR + otpauth URI to add into Google Authenticator / Aegis.
"""
import sys, getpass
import qrcode
import db, auth

db.init()
print("=== Create BitLocker Escrow admin ===")
username = input("Username: ").strip()
if not username:
    print("empty username"); sys.exit(1)
if db.get_admin(username):
    print("Admin already exists."); sys.exit(1)
p1 = getpass.getpass("Password (min 10): ")
p2 = getpass.getpass("Repeat password : ")
if p1 != p2:
    print("Passwords do not match."); sys.exit(1)
if len(p1) < 10:
    print("Password too short (min 10)."); sys.exit(1)

role = (input("Role [admin/helpdesk] (default admin): ").strip().lower() or "admin")
if role not in ("admin", "helpdesk"):
    print("invalid role"); sys.exit(1)
secret = auth.new_totp_secret()
db.create_admin(username, auth.hash_pw(p1), secret, role)
codes = auth.gen_backup_codes(8)
db.set_backup_codes(username, [auth.hash_code(c) for c in codes])
uri = auth.provisioning_uri(secret, username)

print("\nScan this QR in your authenticator app (Google Authenticator / Aegis):\n")
qr = qrcode.QRCode(border=1)
qr.add_data(uri)
qr.print_ascii(invert=True)
print("\nIf you cannot scan, add manually:")
print("  account :", username)
print("  secret  :", secret)
print("  otpauth :", uri)
print("\nBACKUP CODES (each works ONCE instead of the 2FA code; store them safely):")
for c in codes:
    print("   ", c)
print("\nAdmin created. Log in at the web portal with username + password + the 6-digit code.")

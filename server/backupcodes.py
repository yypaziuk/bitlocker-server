#!/usr/bin/env python3
"""(Re)generate 2FA backup codes for an existing admin (invalidates old ones).
Usage: sudo escrow-backupcodes <username>
"""
import sys
import db, auth

db.init()
if len(sys.argv) < 2:
    print("usage: escrow-backupcodes <username>"); sys.exit(1)
username = sys.argv[1].strip()
if not db.get_admin(username):
    print("No such admin:", username); sys.exit(1)

codes = auth.gen_backup_codes(8)
db.set_backup_codes(username, [auth.hash_code(c) for c in codes])
print(f"New backup codes for '{username}' (old ones invalidated). Each works ONCE:")
for c in codes:
    print("   ", c)

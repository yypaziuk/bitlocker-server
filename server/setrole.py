#!/usr/bin/env python3
"""Change an existing admin's role.  Usage: sudo escrow-setrole <username> <admin|helpdesk>"""
import sys
import db

db.init()
if len(sys.argv) != 3 or sys.argv[2] not in ("admin", "helpdesk"):
    print("usage: escrow-setrole <username> <admin|helpdesk>"); sys.exit(1)
user, role = sys.argv[1], sys.argv[2]
if not db.get_admin(user):
    print("No such admin:", user); sys.exit(1)
db.set_role(user, role)
print(f"Role of '{user}' set to '{role}'.")

#!/usr/bin/env python3
"""Rotate the escrow MASTER passphrase (variant A2) - re-encrypt every recovery
key under a new key. Run LOCALLY on the server (interactive):  sudo escrow-rekey

It asks the CURRENT passphrase (to decrypt) and a NEW one (to re-encrypt), backs
up data/ first, re-encrypts all volumes in one transaction, then swaps
salt/verifier. The running service still holds the OLD key in RAM, so AFTER this:
  1) systemctl restart escrow      2) escrow-unlock  with the NEW passphrase
  3) store the NEW passphrase OFFLINE; delete the data backup once confirmed.
Do it in a maintenance moment (no key reveals between rekey and restart).
"""
import os, sys, shutil, sqlite3, getpass, datetime
import crypto

DATA = crypto.DATA_DIR
DB = os.environ.get("ESCROW_DB", os.path.join(DATA, "escrow.db"))

if not crypto.vault.is_setup():
    print("master not initialized - nothing to rotate."); sys.exit(1)

print("=== Rotate BitLocker escrow MASTER passphrase ===")
old = getpass.getpass("CURRENT master passphrase : ")
salt_old = open(crypto.SALT_FILE, "rb").read()
key_old = crypto.derive_key(old, salt_old)
if not crypto.check_verifier(key_old, open(crypto.VERIFIER_FILE, "rb").read()):
    print("Wrong current passphrase - aborted."); sys.exit(1)

n1 = getpass.getpass("NEW master passphrase (min 10): ")
n2 = getpass.getpass("Repeat NEW passphrase         : ")
if n1 != n2:
    print("Passphrases do not match - aborted."); sys.exit(1)
if len(n1) < 10:
    print("Too short (min 10) - aborted."); sys.exit(1)

bdir = os.path.join(os.path.dirname(DATA),
                    f"data_bak_rekey_{datetime.datetime.now():%Y%m%d-%H%M%S}")
shutil.copytree(DATA, bdir)
print("Data backup:", bdir)

salt_new = os.urandom(16)
key_new = crypto.derive_key(n1, salt_new)

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
rows = con.execute("SELECT id, rec_pw_enc FROM volumes WHERE rec_pw_enc IS NOT NULL").fetchall()
done = 0
try:
    con.execute("BEGIN")
    for r in rows:
        pt = crypto.dec_with(key_old, r["rec_pw_enc"])   # decrypt with OLD
        ct = crypto.enc_with(key_new, pt)                # re-encrypt with NEW
        con.execute("UPDATE volumes SET rec_pw_enc=? WHERE id=?", (ct, r["id"]))
        done += 1
    con.commit()
except Exception as e:
    con.rollback(); con.close()
    print(f"REKEY FAILED, rolled back: {e}")
    print("Nothing changed. Data backup kept at", bdir)
    sys.exit(1)
con.close()

with open(crypto.SALT_FILE, "wb") as f:
    f.write(salt_new)
with open(crypto.VERIFIER_FILE, "wb") as f:
    f.write(crypto.make_verifier(key_new))
os.chmod(crypto.SALT_FILE, 0o600)
os.chmod(crypto.VERIFIER_FILE, 0o600)

print(f"\nOK: re-encrypted {done} recovery key(s) under the NEW master passphrase.")
print("NEXT:  1) sudo systemctl restart escrow")
print("       2) escrow-unlock   (enter the NEW passphrase)")
print("       3) verify a key reveal works, then store the NEW passphrase OFFLINE")
print("       4) delete the data backup:", bdir)

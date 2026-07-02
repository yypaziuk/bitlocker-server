#!/usr/bin/env python3
"""Smoke tests for the escrow core (crypto vault + db). No network, no live
service - runs against a throwaway temp data dir/db, so it never touches prod.

Run:  /opt/escrow/venv/bin/python test_smoke.py     (exit 0 = all passed)
"""
import os, sys, tempfile, shutil

_tmp = tempfile.mkdtemp(prefix="escrow-test-")
os.environ["ESCROW_DATA"] = _tmp
os.environ["ESCROW_DB"] = os.path.join(_tmp, "test.db")

import crypto
import db

_pass = _fail = 0


def check(name, cond):
    global _pass, _fail
    if cond:
        _pass += 1; print(f"  PASS  {name}")
    else:
        _fail += 1; print(f"  FAIL  {name}")


try:
    # ---- crypto vault (variant A2) ----
    MASTER = "test-master-passphrase-123"
    crypto.vault.setup(MASTER)
    check("vault setup -> is_setup", crypto.vault.is_setup())
    check("vault setup -> is_unlocked", crypto.vault.is_unlocked())

    rp = "012345-678901-234567-890123-456789-012345-678901-234567"
    blob = crypto.vault.encrypt(rp)
    check("encrypt: bytes, ciphertext != plaintext", isinstance(blob, bytes) and rp.encode() not in blob)
    check("decrypt: round-trips to original", crypto.vault.decrypt(blob) == rp)

    crypto.vault.lock()
    check("lock -> not unlocked", not crypto.vault.is_unlocked())
    check("unlock with WRONG passphrase fails", crypto.vault.unlock("nope") is False)
    check("unlock with correct passphrase ok", crypto.vault.unlock(MASTER) is True)
    check("decrypt after re-unlock still works", crypto.vault.decrypt(blob) == rp)

    # ---- db flow: enroll -> store key -> retrieve ----
    db.init()
    mid = db.upsert_machine({"hostname": "TEST-PC", "serial": "SN1", "manufacturer": "HP",
                             "model": "L580", "product": "ThinkPad", "os_version": "Win10"}, "10.0.0.9")
    check("upsert_machine returns id", bool(mid))
    db.upsert_volume(mid, "C:", "guid-c", "prot-c", crypto.vault.encrypt("AAA-111"),
                     "XtsAes256", "FullyEncrypted", "On")

    data = db.get_keys(machine_id=mid)
    check("get_keys by id -> machine", bool(data) and data["machine"]["hostname"] == "TEST-PC")
    check("get_keys decrypts to stored key", crypto.vault.decrypt(data["volumes"][0]["rec_pw_enc"]) == "AAA-111")
    check("get_keys by serial", db.get_keys(serial="SN1")["machine"]["id"] == mid)
    check("get_keys by keyid prefix", db.get_keys(keyid="prot-c")["machine"]["id"] == mid)

    # ---- audit_update: logs only on a real status/protection change ----
    n0 = sum(1 for r in db.audit_tail(200) if r["action"] == "audit")
    db.audit_update("TEST-PC", [{"mount": "C:", "status": "FullyEncrypted", "protection": "On"}], "10.0.0.9")
    n1 = sum(1 for r in db.audit_tail(200) if r["action"] == "audit")
    check("audit no-change -> no audit_log row", n1 == n0)
    db.audit_update("TEST-PC", [{"mount": "C:", "status": "FullyEncrypted", "protection": "Off"}], "10.0.0.9")
    n2 = sum(1 for r in db.audit_tail(200) if r["action"] == "audit")
    check("audit change (On->Off) -> one audit_log row", n2 == n1 + 1)
    check("audit unknown host -> False", db.audit_update("NO-SUCH-HOST", []) is False)

    # ---- inventory store + report ----
    db.set_inventory(mid, {"cpu": "i7-8550U", "ram_gb": 16, "disks": [{"model": "SSD", "size_gb": 256}]})
    rep = next(m for m in db.report() if m["id"] == mid)
    check("report includes parsed inventory", bool(rep["inventory"]) and rep["inventory"]["cpu"] == "i7-8550U")
    check("report keeps updated protection (Off)", rep["volumes"][0]["protection"] == "Off")
    check("volume row exposes enc_pct field", "enc_pct" in rep["volumes"][0])

    # ---- at_risk (monitor view) ----
    risk = db.at_risk(stale_days=3650)
    check("at_risk flags suspended (FullyEncrypted + protection Off)", "TEST-PC" in risk["suspended"])
    check("at_risk not stale with huge threshold", "TEST-PC" not in risk["stale"])

    print(f"\n{_pass} passed, {_fail} failed")
finally:
    shutil.rmtree(_tmp, ignore_errors=True)

sys.exit(1 if _fail else 0)

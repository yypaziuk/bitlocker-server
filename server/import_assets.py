#!/usr/bin/env python3
"""Import the expected-asset list (for the coverage report).
CSV columns (case-insensitive, any order): hostname, serial, note.
Usage: sudo escrow-import-assets <file.csv>
"""
import sys, csv
import db

db.init()
if len(sys.argv) < 2:
    print("usage: escrow-import-assets <file.csv>"); sys.exit(1)

rows = []
with open(sys.argv[1], newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    for r in reader:
        rl = {(k or "").lower().strip(): (v or "").strip() for k, v in r.items()}
        host = rl.get("hostname") or rl.get("host") or rl.get("name") or rl.get("computer")
        ser = rl.get("serial") or rl.get("serialnumber") or rl.get("sn")
        note = rl.get("note") or rl.get("department") or rl.get("user") or ""
        if host or ser:
            rows.append({"hostname": host, "serial": ser, "note": note})

db.set_expected(rows)
print(f"Imported {len(rows)} expected machines into the coverage list.")

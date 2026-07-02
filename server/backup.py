#!/usr/bin/env python3
"""Encrypted backup of escrow data (db + salt + verifier).

Consistent SQLite snapshot -> tar -> age-encrypt to the recipient in
/opt/escrow/backup_recipient.txt (public key). Only the OFFLINE age private
key can decrypt. Keeps backups from the last RETENTION_DAYS (4 weeks).
Also prunes audit_log older than AUDIT_DAYS.

Callable as run_backup() (used by the web panel) or as a CLI / cron script.
"""
import os, sqlite3, subprocess, tarfile, tempfile, datetime, glob, time

ESC = "/opt/escrow"
DATA = os.path.join(ESC, "data")
BK = os.path.join(ESC, "backups")
RECIP = os.path.join(ESC, "backup_recipient.txt")
RETENTION_DAYS = 28      # keep last 4 weeks
AUDIT_DAYS = 180         # prune audit_log older than this


def run_backup():
    os.makedirs(BK, exist_ok=True)
    if not os.path.exists(RECIP):
        return {"ok": False, "msg": "no backup recipient configured"}
    recipient = open(RECIP).read().strip()
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "escrow.db")
        src = sqlite3.connect(os.path.join(DATA, "escrow.db"))
        dst = sqlite3.connect(snap)
        with dst:
            src.backup(dst)
        dst.close(); src.close()

        # verify the snapshot is sound BEFORE we bake it into an encrypted backup
        chk = sqlite3.connect(snap)
        try:
            ic = chk.execute("PRAGMA integrity_check").fetchone()
            fk = chk.execute("PRAGMA foreign_key_check").fetchall()
        finally:
            chk.close()
        if not ic or ic[0] != "ok":
            return {"ok": False, "msg": f"integrity_check failed: {ic[0] if ic else '?'}"}
        if fk:
            return {"ok": False, "msg": f"foreign_key_check found {len(fk)} broken row(s)"}

        tarp = os.path.join(tmp, "bk.tar")
        with tarfile.open(tarp, "w") as t:
            t.add(snap, arcname="escrow.db")
            for f in ("salt.bin", "verifier.bin"):
                p = os.path.join(DATA, f)
                if os.path.exists(p):
                    t.add(p, arcname=f)

        out = os.path.join(BK, f"escrow-{ts}.tar.age")
        subprocess.run(["age", "-r", recipient, "-o", out, tarp], check=True)
        os.chmod(out, 0o600)

        # sanity: the produced file must be a real age container, non-trivial size
        with open(out, "rb") as fh:
            head = fh.read(64)
        if not head.startswith(b"age-encryption.org/v1") or os.path.getsize(out) < 200:
            os.remove(out)
            return {"ok": False, "msg": "produced backup is not a valid age file"}

    # retention: delete backups older than RETENTION_DAYS (today's just-made stays)
    cutoff = time.time() - RETENTION_DAYS * 86400
    for f in glob.glob(os.path.join(BK, "escrow-*.tar.age")):
        if os.path.getmtime(f) < cutoff:
            try: os.remove(f)
            except OSError: pass

    # prune old audit_log
    pruned = 0
    try:
        acut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=AUDIT_DAYS)).isoformat()
        con = sqlite3.connect(os.path.join(DATA, "escrow.db"))
        pruned = con.execute("DELETE FROM audit_log WHERE ts < ?", (acut,)).rowcount
        con.commit(); con.close()
    except Exception:
        pass

    kept = len(glob.glob(os.path.join(BK, "escrow-*.tar.age")))
    return {"ok": True, "file": os.path.basename(out), "kept": kept, "pruned_audit": pruned}


if __name__ == "__main__":
    r = run_backup()
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    if r["ok"]:
        msg = f"{stamp} backup OK: {r['file']} ({r['kept']} kept)"
        if r.get("pruned_audit"):
            msg += f"; pruned {r['pruned_audit']} audit rows"
        print(msg)
    else:
        print(f"{stamp} backup FAILED: {r['msg']}")
        try:
            import platform
            import monitor
            monitor.notify(f"🔴 BitLocker escrow [{platform.node()}]: БЕКАП НЕ ВДАВСЯ — {r['msg']}")
        except Exception:
            pass

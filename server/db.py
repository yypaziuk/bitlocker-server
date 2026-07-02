"""SQLite (WAL) storage for the BitLocker escrow service."""
import os, sqlite3, uuid, datetime, json
from contextlib import contextmanager

DB_PATH = os.environ.get("ESCROW_DB", "/opt/escrow/data/escrow.db")


@contextmanager
def _conn():
    """Open a SQLite connection, yield it, commit on success, rollback on error, always close."""
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def init():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS machines(
            id TEXT PRIMARY KEY,
            hostname TEXT, serial TEXT, manufacturer TEXT, model TEXT,
            os_version TEXT, enrolled_at TEXT, last_seen TEXT, source_ip TEXT
        );
        CREATE TABLE IF NOT EXISTS volumes(
            id TEXT PRIMARY KEY,
            machine_id TEXT REFERENCES machines(id) ON DELETE CASCADE,
            mount TEXT, volume_guid TEXT, protector_id TEXT,
            rec_pw_enc BLOB, enc_method TEXT, status TEXT, updated_at TEXT,
            UNIQUE(machine_id, mount)
        );
        CREATE TABLE IF NOT EXISTS audit_log(
            ts TEXT, action TEXT, machine_id TEXT, actor TEXT, detail TEXT
        );
        CREATE TABLE IF NOT EXISTS admins(
            username TEXT PRIMARY KEY, pw_hash TEXT, totp_secret TEXT, created TEXT
        );
        CREATE TABLE IF NOT EXISTS expected(
            hostname TEXT, serial TEXT, note TEXT
        );
        CREATE TABLE IF NOT EXISTS backup_codes(
            username TEXT, code_hash TEXT, used INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY, value TEXT
        );
        """)
        # migrations (idempotent)
        for stmt in (
            "ALTER TABLE machines ADD COLUMN product TEXT",
            "ALTER TABLE machines ADD COLUMN assignee TEXT",
            "ALTER TABLE machines ADD COLUMN note TEXT",
            "ALTER TABLE volumes ADD COLUMN protection TEXT",
            "ALTER TABLE admins ADD COLUMN role TEXT DEFAULT 'admin'",
            "ALTER TABLE machines ADD COLUMN inventory_json TEXT",
            "ALTER TABLE machines ADD COLUMN inventory_at TEXT",
            "ALTER TABLE volumes ADD COLUMN enc_pct INTEGER",
            "ALTER TABLE admins ADD COLUMN last_login TEXT",
            "ALTER TABLE volumes ADD COLUMN reported_protector_id TEXT",
        ):
            try:
                c.execute(stmt)
            except Exception:
                pass
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def log(action, machine_id=None, actor=None, detail=None):
    with _conn() as c:
        c.execute("INSERT INTO audit_log(ts,action,machine_id,actor,detail) VALUES(?,?,?,?,?)",
                  (now(), action, machine_id, actor, detail))


def find_machine_id(hostname, serial):
    with _conn() as c:
        if serial:
            r = c.execute("SELECT id FROM machines WHERE serial=?", (serial,)).fetchone()
            if r:
                return r["id"]
        r = c.execute("SELECT id FROM machines WHERE hostname=? AND (serial IS NULL OR serial='')", (hostname,)).fetchone()
        return r["id"] if r else None


def upsert_machine(info: dict, source_ip: str) -> str:
    mid = find_machine_id(info.get("hostname"), info.get("serial"))
    with _conn() as c:
        if mid:
            c.execute("""UPDATE machines SET hostname=?,serial=?,manufacturer=?,model=?,product=?,
                         os_version=?,last_seen=?,source_ip=? WHERE id=?""",
                      (info.get("hostname"), info.get("serial"), info.get("manufacturer"),
                       info.get("model"), info.get("product"), info.get("os_version"), now(), source_ip, mid))
        else:
            mid = str(uuid.uuid4())
            c.execute("""INSERT INTO machines(id,hostname,serial,manufacturer,model,product,
                         os_version,enrolled_at,last_seen,source_ip)
                         VALUES(?,?,?,?,?,?,?,?,?,?)""",
                      (mid, info.get("hostname"), info.get("serial"), info.get("manufacturer"),
                       info.get("model"), info.get("product"), info.get("os_version"), now(), now(), source_ip))
    return mid


def upsert_volume(machine_id, mount, volume_guid, protector_id, rec_pw_enc, enc_method, status, protection=None, enc_pct=None):
    with _conn() as c:
        r = c.execute("SELECT id FROM volumes WHERE machine_id=? AND mount=?", (machine_id, mount)).fetchone()
        if r:
            c.execute("""UPDATE volumes SET volume_guid=?,protector_id=?,rec_pw_enc=?,
                         enc_method=?,status=?,protection=?,enc_pct=?,updated_at=? WHERE id=?""",
                      (volume_guid, protector_id, rec_pw_enc, enc_method, status, protection, enc_pct, now(), r["id"]))
        else:
            c.execute("""INSERT INTO volumes(id,machine_id,mount,volume_guid,protector_id,
                         rec_pw_enc,enc_method,status,protection,enc_pct,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                      (str(uuid.uuid4()), machine_id, mount, volume_guid, protector_id,
                       rec_pw_enc, enc_method, status, protection, enc_pct, now()))


def touch(hostname):
    with _conn() as c:
        c.execute("UPDATE machines SET last_seen=? WHERE hostname=?", (now(), hostname))


def set_inventory(machine_id, inv: dict):
    """Store the latest hardware/software inventory (JSON blob) for a machine."""
    with _conn() as c:
        c.execute("UPDATE machines SET inventory_json=?, inventory_at=? WHERE id=?",
                  (json.dumps(inv, ensure_ascii=False), now(), machine_id))


def audit_update(hostname, vols, source_ip=None, inventory=None):
    """Phone-home: update last_seen, per-volume status, and (if sent) inventory.

    Logs an 'audit' row to audit_log ONLY when a volume's status/protection
    actually changes (not on every heartbeat) - keeps the audit view meaningful
    while still recording real transitions (e.g. EncryptionInProgress->FullyEncrypted).
    """
    with _conn() as c:
        r = c.execute("SELECT id FROM machines WHERE hostname=? ORDER BY last_seen DESC", (hostname,)).fetchone()
        if not r:
            return False
        mid = r["id"]
        c.execute("UPDATE machines SET last_seen=? WHERE id=?", (now(), mid))
        if inventory:
            c.execute("UPDATE machines SET inventory_json=?, inventory_at=? WHERE id=?",
                      (json.dumps(inventory, ensure_ascii=False), now(), mid))
        changes = []
        mismatches = []
        for v in vols:
            if v.get("status") is None and not v.get("protector_id"):
                continue
            mount = v["mount"]
            new_status, new_prot = v["status"], v.get("protection")
            reported_pid = v.get("protector_id")
            cur = c.execute("SELECT status, protection, protector_id, reported_protector_id "
                            "FROM volumes WHERE machine_id=? AND mount=?", (mid, mount)).fetchone()
            if cur and (cur["status"] != new_status or cur["protection"] != new_prot):
                changes.append(f"{mount}: {cur['status']}/{cur['protection']} -> {new_status}/{new_prot}")
            # stored protector_id is the one we hold a key for; if the machine now
            # reports a DIFFERENT recovery protector, our stored key is stale (wrong).
            if cur and reported_pid:
                stored_pid = (cur["protector_id"] or "").strip().strip("{}").lower()
                rep_norm = reported_pid.strip().strip("{}").lower()
                changed = (cur["reported_protector_id"] or "").strip().strip("{}").lower() != rep_norm
                if stored_pid and rep_norm and stored_pid != rep_norm and changed:
                    mismatches.append(f"{mount}: stored {cur['protector_id']} != reported {reported_pid}")
            c.execute("UPDATE volumes SET status=?, protection=?, enc_pct=?, reported_protector_id=?, "
                      "updated_at=? WHERE machine_id=? AND mount=?",
                      (new_status, new_prot, v.get("pct"), reported_pid, now(), mid, mount))
        if changes:
            c.execute("INSERT INTO audit_log(ts,action,machine_id,actor,detail) VALUES(?,?,?,?,?)",
                      (now(), "audit", mid, source_ip, "; ".join(changes)))
        if mismatches:
            c.execute("INSERT INTO audit_log(ts,action,machine_id,actor,detail) VALUES(?,?,?,?,?)",
                      (now(), "key_mismatch", mid, source_ip, "; ".join(mismatches)))
        return True


def report():
    with _conn() as c:
        out = []
        for m in c.execute("SELECT * FROM machines ORDER BY hostname").fetchall():
            vols = c.execute("SELECT mount,status,protection,enc_pct,enc_method,updated_at,"
                             "protector_id,reported_protector_id FROM volumes WHERE machine_id=?",
                             (m["id"],)).fetchall()
            out.append({
                "id": m["id"], "hostname": m["hostname"], "serial": m["serial"],
                "manufacturer": m["manufacturer"], "model": m["model"], "product": m["product"],
                "os_version": m["os_version"], "assignee": m["assignee"], "note": m["note"],
                "enrolled_at": m["enrolled_at"], "last_seen": m["last_seen"],
                "inventory": json.loads(m["inventory_json"]) if m["inventory_json"] else None,
                "inventory_at": m["inventory_at"],
                "volumes": [dict(v) for v in vols],
            })
        return out


def at_risk(stale_days=21):
    """Plaintext-metadata view for the health monitor (no keys; works while locked):
    machines with protection suspended, gone silent, or mid-encryption."""
    out = {"suspended": [], "stale": [], "in_progress": [], "mismatch": []}
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    with _conn() as c:
        for m in c.execute("SELECT id,hostname,last_seen FROM machines").fetchall():
            host = m["hostname"]
            try:
                ls = datetime.datetime.fromisoformat(m["last_seen"])
                if ls.tzinfo is None:
                    ls = ls.replace(tzinfo=datetime.timezone.utc)
                if (now_dt - ls).days >= stale_days:
                    out["stale"].append(host)
            except Exception:
                pass
            vols = c.execute("SELECT status,protection,protector_id,reported_protector_id "
                             "FROM volumes WHERE machine_id=?", (m["id"],)).fetchall()
            if any("FullyEncrypted" in (v["status"] or "") and (v["protection"] or "").lower() in ("off", "0") for v in vols):
                out["suspended"].append(host)
            if any("Progress" in (v["status"] or "") for v in vols):
                out["in_progress"].append(host)
            if any(volume_key_mismatch(v) for v in vols):
                out["mismatch"].append(host)
    return out


def volume_key_mismatch(v):
    """True when the machine reports a recovery protector different from the one
    we hold a key for => our stored recovery key is stale/wrong for that volume."""
    stored = (v["protector_id"] or "").strip().strip("{}").lower()
    rep = (v["reported_protector_id"] or "").strip().strip("{}").lower()
    return bool(stored and rep and stored != rep)


def get_keys(machine_id=None, hostname=None, serial=None, keyid=None):
    with _conn() as c:
        if not machine_id:
            if keyid:
                kid = keyid.strip().strip("{}").lower()
                r = c.execute("SELECT machine_id AS id FROM volumes "
                              "WHERE lower(replace(replace(protector_id,'{',''),'}','')) LIKE ?",
                              (kid + "%",)).fetchone()
            elif serial:
                r = c.execute("SELECT id FROM machines WHERE serial=?", (serial,)).fetchone()
            else:
                r = c.execute("SELECT id FROM machines WHERE hostname=?", (hostname,)).fetchone()
            if not r:
                return None
            machine_id = r["id"]
        m = c.execute("SELECT * FROM machines WHERE id=?", (machine_id,)).fetchone()
        if not m:
            return None
        vols = c.execute("SELECT mount,volume_guid,protector_id,rec_pw_enc FROM volumes WHERE machine_id=?",
                         (machine_id,)).fetchall()
        mdict = dict(m)
        mdict["inventory"] = json.loads(mdict["inventory_json"]) if mdict.get("inventory_json") else None
        return {"machine": mdict, "volumes": [dict(v) for v in vols]}


def delete_machine(machine_id):
    with _conn() as c:
        c.execute("DELETE FROM volumes WHERE machine_id=?", (machine_id,))
        c.execute("DELETE FROM machines WHERE id=?", (machine_id,))


def update_machine_meta(machine_id, assignee, note):
    with _conn() as c:
        c.execute("UPDATE machines SET assignee=?, note=? WHERE id=?", (assignee, note, machine_id))


def machine_ids_by_keyid(q):
    qq = q.strip().strip("{}").lower()
    if not qq:
        return set()
    with _conn() as c:
        rows = c.execute("SELECT DISTINCT machine_id FROM volumes WHERE lower(protector_id) LIKE ?",
                         ("%" + qq + "%",)).fetchall()
        return {r["machine_id"] for r in rows}


# ---- admins (web portal) ----
def get_admin(username):
    with _conn() as c:
        r = c.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None


def create_admin(username, pw_hash, totp_secret, role="admin"):
    with _conn() as c:
        c.execute("INSERT INTO admins(username,pw_hash,totp_secret,created,role) VALUES(?,?,?,?,?)",
                  (username, pw_hash, totp_secret, now(), role))


def set_role(username, role):
    with _conn() as c:
        return c.execute("UPDATE admins SET role=? WHERE username=?", (role, username)).rowcount


def set_password(username, pw_hash):
    with _conn() as c:
        return c.execute("UPDATE admins SET pw_hash=? WHERE username=?", (pw_hash, username)).rowcount


def set_totp_secret(username, secret):
    with _conn() as c:
        return c.execute("UPDATE admins SET totp_secret=? WHERE username=?", (secret, username)).rowcount


def set_last_login(username):
    with _conn() as c:
        c.execute("UPDATE admins SET last_login=? WHERE username=?", (now(), username))


def delete_admin(username):
    with _conn() as c:
        c.execute("DELETE FROM backup_codes WHERE username=?", (username,))
        return c.execute("DELETE FROM admins WHERE username=?", (username,)).rowcount


def list_admins():
    with _conn() as c:
        out = []
        for r in c.execute("SELECT username,role,created,last_login FROM admins ORDER BY username").fetchall():
            d = dict(r)
            d["backup_left"] = c.execute(
                "SELECT COUNT(*) n FROM backup_codes WHERE username=? AND used=0",
                (r["username"],)).fetchone()["n"]
            out.append(d)
        return out


def count_admins():
    with _conn() as c:
        return c.execute("SELECT COUNT(*) n FROM admins").fetchone()["n"]


def count_full_admins():
    with _conn() as c:
        return c.execute("SELECT COUNT(*) n FROM admins WHERE role='admin'").fetchone()["n"]


# ---- settings (key/value) ----
def get_setting(key, default=None):
    with _conn() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default


def set_setting(key, value):
    with _conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def set_backup_codes(username, hashes):
    with _conn() as c:
        c.execute("DELETE FROM backup_codes WHERE username=?", (username,))
        c.executemany("INSERT INTO backup_codes(username,code_hash,used) VALUES(?,?,0)",
                      [(username, h) for h in hashes])


def use_backup_code(username, code_hash):
    with _conn() as c:
        r = c.execute("SELECT rowid FROM backup_codes WHERE username=? AND code_hash=? AND used=0",
                      (username, code_hash)).fetchone()
        if not r:
            return False
        c.execute("UPDATE backup_codes SET used=1 WHERE rowid=?", (r["rowid"],))
        return True


def audit_for_machine(machine_id, limit=50):
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT ts,action,actor,detail FROM audit_log WHERE machine_id=? ORDER BY ts DESC LIMIT ?",
            (machine_id, limit)).fetchall()]


def audit_tail(limit=200):
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT ts,action,machine_id,actor,detail FROM audit_log ORDER BY ts DESC LIMIT ?",
            (limit,)).fetchall()]


# ---- coverage (expected vs enrolled) ----
def set_expected(rows):
    with _conn() as c:
        c.execute("DELETE FROM expected")
        c.executemany("INSERT INTO expected(hostname,serial,note) VALUES(?,?,?)",
                      [(r.get("hostname"), r.get("serial"), r.get("note")) for r in rows])


def coverage():
    with _conn() as c:
        machines = c.execute("SELECT hostname,serial,last_seen FROM machines").fetchall()
        by_host = {(m["hostname"] or "").lower(): m for m in machines if m["hostname"]}
        by_ser = {(m["serial"] or "").lower(): m for m in machines if m["serial"]}
        out = []
        for e in c.execute("SELECT hostname,serial,note FROM expected ORDER BY hostname").fetchall():
            mm = by_host.get((e["hostname"] or "").lower())
            if not mm and e["serial"]:
                mm = by_ser.get((e["serial"] or "").lower())
            out.append({"hostname": e["hostname"], "serial": e["serial"], "note": e["note"],
                        "enrolled": mm is not None, "last_seen": mm["last_seen"] if mm else None})
        return out

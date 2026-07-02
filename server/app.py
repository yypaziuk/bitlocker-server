"""BitLocker recovery-key escrow API (no domain, on-prem).

Endpoints (see README.md):
  GET  /healthz              public  - liveness + locked/setup state
  POST /unlock               LOCAL   - provide master passphrase (A2); first call initializes
  POST /enroll   X-Enroll-Secret     - store a machine's recovery key(s) (requires unlocked)
  POST /audit    X-Enroll-Secret     - update status / last_seen
  GET  /report   X-Admin-Token       - list machines + volume status (no secrets)
  GET  /key/...  X-Admin-Token LOCAL - return recovery passwords (requires unlocked; audited)

Auth secrets are compared by SHA-256 hash (env ESCROW_ENROLL_HASH / ESCROW_ADMIN_HASH).
The master passphrase is never stored (variant A2) - see crypto.py.
/unlock and /key are intended to be reachable only locally (nginx does not proxy them).
"""
import os, hashlib, hmac
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

import db
import crypto
import web

ENROLL_HASH = os.environ.get("ESCROW_ENROLL_HASH", "")
ADMIN_HASH = os.environ.get("ESCROW_ADMIN_HASH", "")
SESSION_SECRET = os.environ.get("ESCROW_SESSION_SECRET", os.urandom(32).hex())

app = FastAPI(title="BitLocker Escrow", docs_url=None, redoc_url=None)
# Cookie lifetime is the hard ceiling; the real (configurable) idle timeout is
# enforced in web.py via a per-request last-activity check (setting idle_timeout_min).
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, https_only=True,
                   same_site="lax", max_age=12 * 3600)
app.include_router(web.router)
db.init()


def _ok(secret: str | None, stored_hash: str) -> bool:
    if not secret or not stored_hash:
        return False
    h = hashlib.sha256(secret.encode()).hexdigest()
    return hmac.compare_digest(h, stored_hash)


def _need_enroll(x):
    if not _ok(x, ENROLL_HASH):
        raise HTTPException(401, "bad enroll secret")


def _need_admin(x):
    if not _ok(x, ADMIN_HASH):
        raise HTTPException(401, "bad admin token")


def _need_unlocked():
    if not crypto.vault.is_unlocked():
        raise HTTPException(503, "service is locked - run unlock first")


# ---------- models ----------
class VolumeIn(BaseModel):
    mount: str
    volume_guid: str | None = None
    protector_id: str | None = None
    recovery_password: str
    enc_method: str | None = None
    status: str | None = None
    protection: str | None = None
    pct: int | None = None


class EnrollIn(BaseModel):
    hostname: str
    serial: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    product: str | None = None
    os_version: str | None = None
    inventory: dict | None = None
    volumes: list[VolumeIn]


class UnlockIn(BaseModel):
    passphrase: str


class AuditVol(BaseModel):
    mount: str
    status: str | None = None
    protection: str | None = None
    pct: int | None = None
    protector_id: str | None = None


class AuditIn(BaseModel):
    hostname: str
    inventory: dict | None = None
    volumes: list[AuditVol] = []


# ---------- endpoints ----------
@app.get("/healthz")
def healthz():
    return {"status": "ok" if crypto.vault.is_unlocked() else "locked",
            "setup": crypto.vault.is_setup(),
            "unlocked": crypto.vault.is_unlocked()}


@app.get("/monitor/alerts")
def monitor_alerts():
    # plaintext metadata only (no keys) - reachable on localhost; nginx blocks it
    # over the network. Used by monitor.py for per-machine alerting (works locked).
    return db.at_risk()


@app.post("/unlock")
def unlock(body: UnlockIn):
    if not crypto.vault.is_setup():
        crypto.vault.setup(body.passphrase)
        db.log("master_init", actor="local")
        return {"initialized": True, "unlocked": True}
    if crypto.vault.unlock(body.passphrase):
        db.log("unlock", actor="local")
        return {"unlocked": True}
    raise HTTPException(401, "wrong passphrase")


@app.post("/lock")
def lock(request: Request):
    # LOCAL only (nginx does not proxy /lock) - drops the master key from RAM.
    # Used by `escrow-relock` (optional scheduled relock). Unlock again via escrow-unlock.
    crypto.vault.lock()
    db.log("service_lock", actor="local")
    return {"unlocked": False}


@app.post("/enroll")
def enroll(body: EnrollIn, request: Request, x_enroll_secret: str | None = Header(None)):
    _need_enroll(x_enroll_secret)
    _need_unlocked()
    info = body.model_dump(exclude={"volumes", "inventory"})
    src = request.client.host if request.client else None
    mid = db.upsert_machine(info, src)
    for v in body.volumes:
        enc = crypto.vault.encrypt(v.recovery_password)
        db.upsert_volume(mid, v.mount, v.volume_guid, v.protector_id, enc, v.enc_method, v.status, v.protection, v.pct)
    if body.inventory:
        db.set_inventory(mid, body.inventory)
    db.log("enroll", machine_id=mid, actor=src, detail=f"{body.hostname}; vols={len(body.volumes)}")
    return {"status": "stored", "machine_id": mid, "volumes": len(body.volumes)}


@app.post("/audit")
def audit(body: AuditIn, request: Request, x_enroll_secret: str | None = Header(None)):
    _need_enroll(x_enroll_secret)
    src = request.client.host if request.client else None
    ok = db.audit_update(body.hostname, [v.model_dump() for v in body.volumes], src, body.inventory)
    return {"status": "ok" if ok else "unknown_host"}


@app.get("/report")
def report(x_admin_token: str | None = Header(None)):
    _need_admin(x_admin_token)
    return {"machines": db.report()}


@app.get("/key/{machine_id}")
def get_key(machine_id: str, request: Request, x_admin_token: str | None = Header(None)):
    _need_admin(x_admin_token)
    _need_unlocked()
    data = db.get_keys(machine_id=machine_id)
    if not data:
        raise HTTPException(404, "not found")
    src = request.client.host if request.client else None
    out = []
    for v in data["volumes"]:
        out.append({"mount": v["mount"], "volume_guid": v["volume_guid"],
                    "protector_id": v["protector_id"],
                    "recovery_password": crypto.vault.decrypt(v["rec_pw_enc"])})
    db.log("key_read", machine_id=machine_id, actor=src, detail=data["machine"]["hostname"])
    web.alert(f"🔑 BitLocker: показано ключ '{data['machine']['hostname']}' (CLI/API, {src or '?'})")
    return {"machine": {k: data["machine"][k] for k in ("id", "hostname", "serial", "model")},
            "volumes": out}


@app.get("/key")
def find_key(request: Request, hostname: str | None = None, serial: str | None = None,
             keyid: str | None = None, x_admin_token: str | None = Header(None)):
    _need_admin(x_admin_token)
    _need_unlocked()
    if not (hostname or serial or keyid):
        raise HTTPException(400, "hostname, serial or keyid required")
    data = db.get_keys(hostname=hostname, serial=serial, keyid=keyid)
    if not data:
        raise HTTPException(404, "not found")
    return get_key(data["machine"]["id"], request, x_admin_token)

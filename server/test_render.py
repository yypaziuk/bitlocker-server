#!/usr/bin/env python3
"""Full portal render + i18n + button-wiring test (no HTTP, no httpx needed).

1) Renders every page template in UK and EN with rich sample data, and asserts the
   EN output contains NO Ukrainian (Cyrillic) leftover -> proves full translation.
2) Extracts every href/action in the templates and checks each resolves to a real
   route in app.py/web.py -> proves no dead buttons.
Run with the server venv python. Sample data is ASCII, so any Cyrillic in EN = a gap.
"""
import os, re, tempfile, sys
tmp = tempfile.mkdtemp(prefix="escrow-render-")
os.environ.setdefault("ESCROW_DATA", tmp)
os.environ.setdefault("ESCROW_DB", os.path.join(tmp, "t.db"))

import web

_p = _f = 0
def ok(n, c, extra=""):
    global _p, _f
    if c: _p += 1; print(f"  PASS  {n}")
    else: _f += 1; print(f"  FAIL  {n}  {extra}")

CYR = re.compile('[Ѐ-ӿ]')
TOK = re.compile(r'\S*[Ѐ-ӿ]\S*')

INV = {"cpu": "Intel i7-8550U", "cpu_cores": 4, "cpu_threads": 8, "ram_gb": 16,
       "disks": [{"model": "Samsung SSD", "size_gb": 256}], "c_free_gb": 8, "c_size_gb": 110,
       "board": "HP 837F", "bios_version": "Q85", "ipv4": "10.0.0.5", "mac": "AA:BB",
       "os_caption": "Windows 10 Enterprise LTSC", "os_build": "19045", "os_ubr": "4046",
       "os_arch": "64-bit", "os_install": "2026-01-20", "last_boot": "2026-06-23 09:00",
       "uptime_days": 0, "last_user": "DOMAIN\\user", "last_logon": "DOMAIN\\user",
       "domain": "dom.local", "tpm_version": "7.62", "secure_boot": False,
       "av_name": "Defender", "av_rtp": False, "av_age_days": 3, "disk_health": "Warning",
       "pending_reboot": True}
VOLS = [{"mount": "C:", "status": "FullyEncrypted", "protection": "On", "enc_pct": 100, "protector_id": "p1", "reported_protector_id": "p1"},
        {"mount": "D:", "status": "EncryptionInProgress", "protection": "Off", "enc_pct": 47, "protector_id": "p2", "reported_protector_id": None},
        {"mount": "E:", "status": "FullyEncrypted", "protection": "Off", "enc_pct": 100, "protector_id": "p3", "reported_protector_id": "p9"}]
M = {"id": "abc", "hostname": "PORTAL-PC", "assignee": "Owner X", "serial": "SNX", "manufacturer": "HP",
     "model": "L580", "product": "ThinkPad", "os_version": "Win10", "note": "n", "enrolled_at": "2026-06-20T10:00:00",
     "last_seen": "2026-06-23T09:50:00", "inventory": INV, "inventory_at": "2026-06-23T09:50:00",
     "volumes": VOLS, "suspended": True, "stale_days": 40}
HIST = [{"ts": "2026-06-23T09:50:00", "action": a, "actor": "x", "detail": "d"}
        for a in ("enroll", "key_read", "audit", "update_meta", "machine_delete", "login_fail")]
BK = {"time": "2026-06-23 02:30", "age_h": 5, "count": 7}
STATS = {"total": 3, "full": 1, "progress": 1, "suspended": 1, "stale": 1, "mismatch": 1}

CTX = {
    web.DASH:   dict(machines=[M], q="", status="all", sort="host", unlocked=True, bk=BK, stats=STATS),
    web.MACHINE: dict(m=M, vols=[{"mount": "C:", "protector_id": "p1"}], revealed=[{"rp": "111-222"}],
                      unlocked=True, history=HIST, full=True),
    web.AUDIT:  dict(rows=HIST),
    web.INVENTORY: dict(machines=[M], q=""),
    web.COVERAGE: dict(rows=[{"hostname": "PORTAL-PC", "serial": "SNX", "note": "Dept", "enrolled": True, "last_seen": "2026-06-23T09:50:00"},
                             {"hostname": "OTHER", "serial": "S2", "note": "", "enrolled": False, "last_seen": None}],
                       total=2, enrolled=1, full=True),
    web.BACKUPS: dict(items=[{"name": "escrow-x.tar.age", "mtime": "2026-06-23 02:30", "size": 12}], full=True, flash="ok:escrow-x.tar.age"),
    web.SERVER: dict(me="admin1", full=True, unlocked=True, idle_timeout_min="60",
                     flash="ok:Налаштування збережено",
                     admins=[{"username": "admin1", "role": "admin", "last_login": "2026-06-23T09:50:00", "backup_left": 8},
                             {"username": "help1", "role": "helpdesk", "last_login": None, "backup_left": 5}]),
    web.SERVER_CRED: dict(title="Новий адміністратор", username="admin1", secret="ABCDEF234567",
                          uri="otpauth://totp/BitLocker%20Escrow:admin1?secret=ABCDEF234567",
                          qr="<svg xmlns='http://www.w3.org/2000/svg'></svg>", codes=["aaaa11", "bbbb22"]),
    web.LOGIN:  dict(error="Невірний логін, пароль або код 2FA", locked=True),
}
NAMES = {id(web.DASH): "DASH", id(web.MACHINE): "MACHINE", id(web.AUDIT): "AUDIT",
         id(web.INVENTORY): "INVENTORY", id(web.COVERAGE): "COVERAGE", id(web.BACKUPS): "BACKUPS",
         id(web.SERVER): "SERVER", id(web.SERVER_CRED): "SERVER_CRED", id(web.LOGIN): "LOGIN"}

print("=== 1) language: EN must contain NO Cyrillic ===")
for tpl, ctx in CTX.items():
    name = NAMES[id(tpl)]
    for lang in ("uk", "en"):
        body = web._render(tpl, user="tester", role_name="admin", lang=lang, **ctx)
        full = web._render(web.BASE, user="tester", body=body, role="admin", lang=lang)
        full = web._translate(full, lang)
        if lang == "en":
            toks = sorted(set(TOK.findall(full)))
            ok(f"EN {name}: no Cyrillic", not toks, f"leftover: {toks[:12]}")

print("\n=== 2) buttons/links resolve to real routes ===")
src = open(web.__file__, encoding="utf-8").read()
app_src = open(os.path.join(os.path.dirname(web.__file__), "app.py"), encoding="utf-8").read()
routes = set(re.findall(r'@(?:router|app)\.(?:get|post)\(\s*"([^"]+)"', src + "\n" + app_src))
route_res = [re.compile("^" + re.sub(r"\{[^}]+\}", r"[^/]+", rt) + "$") for rt in routes]
targets = set(re.findall(r'(?:href|action)="(/[^"]*)"', src))
for t in sorted(targets):
    norm = re.sub(r"\{\{[^}]+\}\}", "1", t)          # jinja expr -> placeholder
    norm = re.sub(r"\{[^}]+\}", "1", norm)
    norm = norm.split("?")[0]                          # ignore query string
    hit = any(rx.match(norm) for rx in route_res)
    ok(f"link {t}", hit, "-> no matching route")

print(f"\nroutes found: {len(routes)}")
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)

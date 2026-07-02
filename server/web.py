"""Admin web portal (session login + TOTP 2FA): dashboard, search, key reveal, audit."""
from fastapi import APIRouter, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response
import os, glob, datetime, re, csv, io, time
import jinja2

import db
import crypto
import auth
import backup

router = APIRouter()
BACKUP_DIR = os.path.join(os.path.dirname(crypto.DATA_DIR), "backups")


_BK_RE = re.compile(r"^escrow-\d{8}-\d{6}\.tar\.age$")


def _safe_backup_name(name):
    return bool(_BK_RE.match(name or ""))


def _list_backups():
    out = []
    for f in sorted(glob.glob(os.path.join(BACKUP_DIR, "escrow-*.tar.age")), reverse=True):
        st = os.stat(f)
        out.append({"name": os.path.basename(f),
                    "size": round(st.st_size / 1024, 1),
                    "mtime": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
    return out


def _last_backup():
    try:
        files = glob.glob(os.path.join(BACKUP_DIR, "escrow-*.tar.age"))
        if not files:
            return None
        newest = max(files, key=os.path.getmtime)
        ts = datetime.datetime.fromtimestamp(os.path.getmtime(newest))
        age_h = (datetime.datetime.now() - ts).total_seconds() / 3600
        return {"time": ts.strftime("%Y-%m-%d %H:%M"), "age_h": age_h, "count": len(files)}
    except Exception:
        return None
_env = jinja2.Environment(autoescape=True)


try:
    from zoneinfo import ZoneInfo
    _KYIV = ZoneInfo("Europe/Kyiv")
except Exception:
    _KYIV = datetime.timezone(datetime.timedelta(hours=3))


def _kyiv(iso, withsec=False):
    """Render a stored UTC ISO timestamp as local Kyiv time 'YYYY-MM-DD HH:MM'."""
    if not iso:
        return "—"
    try:
        t = datetime.datetime.fromisoformat(iso)
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        t = t.astimezone(_KYIV)
        return t.strftime("%Y-%m-%d %H:%M:%S" if withsec else "%Y-%m-%d %H:%M")
    except Exception:
        return str(iso)[:16].replace("T", " ")


_env.filters["kyiv"] = _kyiv


def _render(tpl, **ctx):
    return _env.from_string(tpl).render(**ctx)


def _user(request):
    """Return the logged-in admin, enforcing the configurable idle timeout.

    Idle timeout (minutes) is read from settings on every request; the session is
    cleared once inactivity exceeds it. last-activity is refreshed here on use."""
    u = request.session.get("admin")
    if not u:
        return None
    try:
        timeout = int(db.get_setting("idle_timeout_min", "60")) * 60
    except (TypeError, ValueError):
        timeout = 3600
    nowt = time.time()
    last = request.session.get("ts")
    if last and (nowt - last) > timeout:
        request.session.clear()
        return None
    request.session["ts"] = nowt
    return u


def _role(request):
    return request.session.get("role", "admin")


def _is_full(request):
    return _role(request) == "admin"


def alert(msg):
    """Fire-and-forget notification to all configured channels (Telegram/email).
    Runs in a daemon thread so it never blocks the request; safe if monitor/config
    is absent (e.g. local tests)."""
    def _send():
        try:
            import monitor
            monitor.notify(msg)
        except Exception:
            pass
    try:
        import threading
        threading.Thread(target=_send, daemon=True).start()
    except Exception:
        pass


# ---------------- templates ----------------
BASE = """
<!doctype html><html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BitLocker Escrow</title>
<link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJnIiB4MT0iMCIgeTE9IjAiIHgyPSIxIiB5Mj0iMSI+PHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjNWVmMGEwIi8+PHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMzhiZGY4Ii8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzBiMTIyMiIvPjxwYXRoIGQ9Ik0xMSAxNC41di0zLjVhNSA1IDAgMCAxIDEwIDB2My41IiBmaWxsPSJub25lIiBzdHJva2U9InVybCgjZykiIHN0cm9rZS13aWR0aD0iMi42IiBzdHJva2UtbGluZWNhcD0icm91bmQiLz48cmVjdCB4PSI4LjUiIHk9IjE0IiB3aWR0aD0iMTUiIGhlaWdodD0iMTEuNSIgcng9IjIuNiIgZmlsbD0idXJsKCNnKSIvPjxjaXJjbGUgY3g9IjE2IiBjeT0iMTkiIHI9IjIiIGZpbGw9IiMwYjEyMjIiLz48cmVjdCB4PSIxNS4xIiB5PSIxOS40IiB3aWR0aD0iMS44IiBoZWlnaHQ9IjMuNiIgcng9IjAuOSIgZmlsbD0iIzBiMTIyMiIvPjwvc3ZnPg==">
<style>
:root{--bg:#0f172a;--card:#1e293b;--ink:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;color:var(--ink);min-height:100vh;
  background-color:#0a1226;
  background-image:
    radial-gradient(1100px 760px at 6% -12%, rgba(56,189,248,.28), transparent 55%),
    radial-gradient(1000px 720px at 116% 4%, rgba(16,185,129,.22), transparent 52%),
    radial-gradient(900px 680px at 50% 128%, rgba(139,92,246,.26), transparent 55%),
    linear-gradient(155deg,#0a1226 0%,#101f3c 45%,#0a1020 100%);
  background-attachment:fixed;background-repeat:no-repeat;background-size:cover}
.card{background:rgba(30,41,59,.86);backdrop-filter:blur(3px)}
.tiles{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.tile{display:block;flex:1;min-width:150px;background:rgba(30,41,59,.86);border:1px solid #2c3a52;border-radius:12px;padding:14px 16px;backdrop-filter:blur(3px);color:inherit;text-decoration:none}
a.tile:hover{border-color:var(--acc)}
.tile .n{font-size:28px;font-weight:700;line-height:1.1}
.tile .l{color:var(--mut);font-size:13px;margin-top:2px}
.tile.g .n{color:#5ef0a0}.tile.r .n{color:#ff9a9a}.tile.b .n{color:var(--acc)}.tile.y .n{color:#f4c54e}
header{background:#0b1222;padding:12px 20px;display:flex;align-items:center;gap:18px;border-bottom:1px solid #233}
header b{color:var(--acc)}header a{color:var(--mut);text-decoration:none}header a:hover{color:var(--ink)}
.sp{flex:1}.wrap{max-width:1000px;margin:24px auto;padding:0 16px}
.wrap.wide{max-width:min(1600px,96vw)}
.card{background:var(--card);border:1px solid #2c3a52;border-radius:12px;padding:18px;margin-bottom:18px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #2c3a52}
th{color:var(--mut);font-weight:600;font-size:13px}tr:hover td{background:#243049}
input,button,select{font:inherit}input[type=text],input[type=password]{background:#0b1222;border:1px solid #334;color:var(--ink);border-radius:8px;padding:9px 11px;width:100%}
select{background:#0b1222;border:1px solid #334;color:var(--ink);border-radius:8px;padding:9px 11px}
.btn{background:var(--acc);color:#04222e;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer}
.btn:hover{filter:brightness(1.08)}.btn.warn{background:var(--warn);color:#3a2a00}
a.lnk{color:var(--acc);text-decoration:none}.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{background:#0c3a22;color:#5ef0a0}.warn2{background:#3a2e0c;color:#f4c54e}.bad{background:#3a1414;color:#ff9a9a}
.key{display:block;font:18px/1.4 ui-monospace,Consolas,monospace;background:#0b1222;border:1px dashed var(--ok);color:#9af7c4;padding:12px 14px;border-radius:8px;letter-spacing:2px;white-space:nowrap;overflow-x:auto;user-select:all;-webkit-user-select:all}
.muted{color:var(--mut)}.err{background:#3a1414;color:#ff9a9a;padding:10px;border-radius:8px;margin-bottom:12px}
h1{font-size:20px;margin:0 0 14px}.mono{font-family:ui-monospace,Consolas,monospace}
@keyframes bkmove{0%{margin-left:-45%}100%{margin-left:100%}}
</style></head><body>
{% if user %}<header><b>🔐 BitLocker Escrow</b>
<a href="/">Dashboard</a><a href="/coverage">Coverage</a><a href="/backups">Backups</a><a href="/auditlog">Audit</a><a href="/inventory">Інвентар</a><a href="/server">Керування</a><span class="sp"></span>
<span class="muted">{{user}}{% if role and role!='admin' %} <span class="pill warn2">{{role}}</span>{% endif %}</span><a href="/lang/uk"{% if lang!='en' %} style="color:var(--acc);font-weight:700"{% endif %}>UA</a><a href="/lang/en"{% if lang=='en' %} style="color:var(--acc);font-weight:700"{% endif %}>EN</a><a href="/logout">Logout</a></header>{% endif %}
<div class="wrap{% if wide %} wide{% endif %}">{{ body|safe }}</div></body></html>
"""

LOGIN = """
<div class="card" style="max-width:380px;margin:8vh auto">
<h1>🔐 Вхід</h1>
{% if locked %}<div style="background:#3a2e0c;color:#f4c54e;padding:10px;border-radius:8px;margin-bottom:12px">⚠ Сервіс LOCKED — видача ключів не працює, доки не виконано escrow-unlock на сервері.</div>{% endif %}
{% if error %}<div class="err">{{error}}</div>{% endif %}
<form method="post" action="/login">
<p><label class="muted">Користувач</label><input type="text" name="username" autofocus></p>
<p><label class="muted">Пароль</label><input type="password" name="password"></p>
<p><label class="muted">Код 2FA (TOTP)</label><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></p>
<button class="btn" type="submit" style="width:100%">Увійти</button>
</form></div>
"""

DASH = """
<h1>Робочі станції <span class="muted">({{machines|length}})</span>
{% if not unlocked %}<span class="pill bad">сервіс LOCKED — ключі недоступні</span>{% endif %}
<a class="lnk" style="float:right;font-size:14px" href="/export/machines.csv">↓ експорт CSV</a></h1>
<div class="tiles">
  <a class="tile b" href="/?status=all"><div class="n">{{stats.total}}</div><div class="l">всього станцій</div></a>
  <a class="tile g" href="/?status=full"><div class="n">{{stats.full}}</div><div class="l">зашифровано</div></a>
  <a class="tile y" href="/?status=progress"><div class="n">{{stats.progress}}</div><div class="l">шифрується</div></a>
  <a class="tile {{ 'r' if stats.suspended else 'g' }}" href="/?status=suspended"><div class="n">{{stats.suspended}}</div><div class="l">захист призупинено</div></a>
  <a class="tile {{ 'r' if stats.mismatch else 'g' }}" href="/?status=mismatch"><div class="n">{{stats.mismatch}}</div><div class="l">ключ застарів</div></a>
  <a class="tile {{ 'r' if stats.stale else 'g' }}" href="/?status=stale"><div class="n">{{stats.stale}}</div><div class="l">зниклі (&gt;30 дн)</div></a>
  <div class="tile {{ 'g' if unlocked else 'r' }}"><div class="n">{{ 'OK' if unlocked else 'LOCKED' }}</div><div class="l">стан сервісу</div></div>
  <a class="tile {{ 'g' if bk and bk.age_h < 26 else 'r' }}" href="/backups"><div class="n">{{ bk.time[5:] if bk else '—' }}</div><div class="l">останній бекап</div></a>
</div>
<p class="muted" style="margin:-6px 0 14px">🗄 Останній бекап:
{% if bk %}{{bk.time}}
{% if bk.age_h < 26 %}<span class="pill ok">свіжий</span>
{% else %}<span class="pill bad">застарів ({{ (bk.age_h/24)|round(1) }} дн тому)</span>{% endif %}
<span class="muted">· збережено {{bk.count}}</span>
{% else %}<span class="pill bad">бекапів немає!</span>{% endif %}</p>
<div class="card">
<form method="get" action="/" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
  <input type="text" name="q" value="{{q}}" placeholder="пошук: hostname / серійник / Recovery Key ID..." style="flex:1;min-width:200px">
  <select name="status">
    <option value="all" {{ 'selected' if status=='all' else '' }}>усі статуси</option>
    <option value="full" {{ 'selected' if status=='full' else '' }}>зашифровані</option>
    <option value="progress" {{ 'selected' if status=='progress' else '' }}>шифрується</option>
    <option value="stale" {{ 'selected' if status=='stale' else '' }}>зниклі (&gt;30 дн)</option>
    <option value="suspended" {{ 'selected' if status=='suspended' else '' }}>захист призупинено</option>
    <option value="mismatch" {{ 'selected' if status=='mismatch' else '' }}>ключ застарів</option>
  </select>
  <select name="sort">
    <option value="host" {{ 'selected' if sort=='host' else '' }}>сорт: hostname</option>
    <option value="seen" {{ 'selected' if sort=='seen' else '' }}>сорт: last seen</option>
    <option value="enrolled" {{ 'selected' if sort=='enrolled' else '' }}>сорт: дата enroll</option>
  </select>
  <button class="btn" type="submit">Застосувати</button>
</form>
</div>
<div class="card">
<table><tr><th>Hostname</th><th>МВО</th><th>Серійник</th><th>Модель</th><th>Диски</th><th>Last seen</th><th></th></tr>
{% for m in machines %}
<tr><td class="mono">{{m.hostname}}</td><td>{{m.assignee or '-'}}</td><td class="mono">{{m.serial or '-'}}</td>
<td>{{m.product or m.model or '-'}}{% if m.product and m.model %}<br><span class="muted mono" style="font-size:12px">{{m.model}}</span>{% endif %}</td>
<td>{% for v in m.volumes %}<div style="margin:2px 0;white-space:nowrap"><span class="pill {{ 'ok' if 'FullyEncrypted' in (v.status or '') else ('warn2' if 'Progress' in (v.status or '') else 'bad') }}">{{v.mount}}</span> <span class="muted" style="font-size:12px">{% if 'FullyEncrypted' in (v.status or '') %}зашифровано{% elif 'Progress' in (v.status or '') %}шифрується{% if v.enc_pct is not none %} {{v.enc_pct}}%{% endif %}{% elif 'Decrypt' in (v.status or '') %}не зашифр.{% else %}{{v.status or '?'}}{% endif %}</span>{% if (v.protection or '')|lower == 'off' and 'FullyEncrypted' in (v.status or '') %} <span class="pill bad" style="font-size:11px">захист OFF</span>{% endif %}{% if v.protector_id and v.reported_protector_id and (v.protector_id|lower).replace('{','').replace('}','') != (v.reported_protector_id|lower).replace('{','').replace('}','') %} <span class="pill bad" style="font-size:11px">ключ застарів</span>{% endif %}</div>{% endfor %}{% if not m.volumes %}<span class="muted">—</span>{% endif %}</td>
<td class="muted">{{ m.last_seen|kyiv }}
{% if m.stale_days is not none and m.stale_days >= 30 %}<br><span class="pill bad">зник {{m.stale_days}} дн</span>{% endif %}</td>
<td><a class="lnk" href="/machine/{{m.id}}">відкрити →</a></td></tr>
{% endfor %}
{% if not machines %}<tr><td colspan="7" class="muted">Поки немає записів.</td></tr>{% endif %}
</table></div>
"""

MACHINE = """
<p><a class="lnk" href="/">← усі станції</a></p>
<h1 class="mono">{{m.hostname}}</h1>
<div class="card">
<p><span class="muted">Серійник:</span> <span class="mono">{{m.serial or '-'}}</span><br>
<span class="muted">Пристрій:</span> {{m.manufacturer or ''}} {{m.product or m.model or '-'}}
{% if m.product and m.model %}<span class="muted mono"> ({{m.model}})</span>{% endif %}<br>
<span class="muted">ОС:</span> {{m.os_version or '-'}}</p>
<form method="post" action="/machine/{{m.id}}/update" style="margin:4px 0 6px">
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
    <div><label class="muted">МВО (відповідальний)</label><br><input type="text" name="assignee" value="{{m.assignee or ''}}" style="min-width:240px"></div>
    <div style="flex:1;min-width:240px"><label class="muted">Примітки</label><br><input type="text" name="note" value="{{m.note or ''}}" style="width:100%"></div>
    <button class="btn" type="submit">Зберегти</button>
  </div>
</form>
{% if m.inventory %}{% set i = m.inventory %}
<h3 style="margin:16px 0 6px">Інвентар <span class="muted" style="font-size:13px">(оновлено {{ m.inventory_at|kyiv }})</span></h3>
<table>
<tr><td class="muted" style="width:150px">CPU</td><td>{{i.cpu or '-'}}{% if i.cpu_cores %} · {{i.cpu_cores}}c/{{i.cpu_threads}}t{% endif %}</td></tr>
<tr><td class="muted">RAM</td><td>{{ (i.ram_gb ~ ' ГБ') if i.ram_gb else '-' }}</td></tr>
<tr><td class="muted">Диски</td><td>{% for d in i.disks or [] %}{{d.model}} ({{d.size_gb}} ГБ){% if not loop.last %}<br>{% endif %}{% endfor %}{% if i.c_size_gb %}<br><span class="muted">C:: вільно {{i.c_free_gb}}/{{i.c_size_gb}} ГБ</span>{% endif %}</td></tr>
<tr><td class="muted">Мережа</td><td class="mono">{{i.ipv4 or '-'}}{% if i.mac %} · {{i.mac}}{% endif %}</td></tr>
<tr><td class="muted">ОС</td><td>{{i.os_caption or m.os_version or '-'}}{% if i.os_build %} (build {{i.os_build}}{% if i.os_ubr %}.{{i.os_ubr}}{% endif %}, {{i.os_arch}}){% endif %}{% if i.os_install %}<br><span class="muted">встановлено {{i.os_install}}</span>{% endif %}</td></tr>
<tr><td class="muted">Користувач</td><td>{{i.last_user or i.last_logon or '-'}}{% if i.domain %} · {{i.domain}}{% endif %}</td></tr>
<tr><td class="muted">Аптайм</td><td>{% if i.uptime_days is not none %}{{i.uptime_days}} дн{% if i.last_boot %} · {{i.last_boot}}{% endif %}{% else %}-{% endif %}</td></tr>
<tr><td class="muted">Безпека</td><td>TPM {{i.tpm_version or '?'}}{% if i.secure_boot is not none %} · Secure Boot: {{ 'Увімк' if i.secure_boot else 'Вимк' }}{% endif %}{% if i.av_name %} · AV: {{i.av_name}}{% if i.av_rtp is false %} (RTP ВИМК!){% endif %}{% if i.av_age_days is not none %}, сигнатури {{i.av_age_days}} дн{% endif %}{% endif %}{% if i.disk_health %} · диск: {{i.disk_health}}{% endif %}{% if i.pending_reboot %} · ⚠ очікує перезавантаження{% endif %}</td></tr>
<tr><td class="muted">BIOS / плата</td><td>{{i.bios_version or '-'}}{% if i.board %} · {{i.board}}{% endif %}</td></tr>
</table>
{% endif %}
<table><tr><th>Диск</th><th>Recovery key ID (protector)</th><th>Статус</th></tr>
{% for v in vols %}
<tr><td class="mono">{{v.mount}}</td><td class="mono muted">{{v.protector_id}}</td>
<td>{% if revealed %}<span class="pill ok">показано</span>{% else %}<span class="muted">приховано</span>{% endif %}</td></tr>
{% endfor %}
</table>

{% if revealed %}
<h3 style="margin:18px 0 6px">Ключі відновлення</h3>
{% for v in vols %}
<div style="margin:12px 0">
  <div class="muted mono" style="margin-bottom:4px">Диск {{v.mount}}</div>
  <div class="key" id="k{{loop.index0}}">{{ revealed[loop.index0].rp }}</div>
  <button class="btn" type="button" style="margin-top:6px"
    onclick="var b=this;navigator.clipboard.writeText(document.getElementById('k{{loop.index0}}').innerText).then(function(){b.textContent='Скопійовано ✓';setTimeout(function(){b.textContent='Копіювати ключ'},2000)})">Копіювати ключ</button>
</div>
{% endfor %}
<p class="muted" style="margin-top:12px">Клік по ключу виділяє його повністю. Перегляд записано в аудит.
Введи код на екрані відновлення BitLocker залоченого ПК.</p>
<textarea id="allinfo" style="position:absolute;left:-9999px">BitLocker - {{m.hostname}}
MBO: {{m.assignee or '-'}}
Device: {{m.manufacturer or ''}} {{m.product or m.model or '-'}}
Model: {{m.model or '-'}}
Serial: {{m.serial or '-'}}
OS: {{m.os_version or '-'}}
Note: {{m.note or '-'}}
{% for v in vols %}[{{v.mount}}] KeyID: {{v.protector_id}}
[{{v.mount}}] Recovery: {{ revealed[loop.index0].rp }}
{% endfor %}</textarea>
<button class="btn" type="button" style="margin-top:6px"
  onclick="var b=this;navigator.clipboard.writeText(document.getElementById('allinfo').value).then(function(){b.textContent='Скопійовано ✓';setTimeout(function(){b.textContent='📋 Копіювати всю інфо'},2000)})">📋 Копіювати всю інфо</button>
{% else %}
{% if full %}
<form method="post" action="/machine/{{m.id}}/reveal" style="margin-top:14px">
{% if unlocked %}<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
<input type="text" name="reason" required placeholder="причина / тікет (напр. користувач залочився)" style="flex:1;min-width:260px">
<button class="btn warn" type="submit">🔑 Показати ключ(і) відновлення</button></div>
<span class="muted">  (хто, коли й причина — пишуться в журнал аудиту)</span>
{% else %}<span class="pill bad">Сервіс LOCKED — спершу escrow-unlock на сервері</span>{% endif %}
</form>
{% else %}<p class="muted" style="margin-top:14px">🔒 Перегляд ключів доступний лише ролі «admin».</p>{% endif %}
<textarea id="allinfo" style="position:absolute;left:-9999px">BitLocker - {{m.hostname}}
MBO: {{m.assignee or '-'}}
Device: {{m.manufacturer or ''}} {{m.product or m.model or '-'}}
Model: {{m.model or '-'}}
Serial: {{m.serial or '-'}}
OS: {{m.os_version or '-'}}
Note: {{m.note or '-'}}
{% for v in vols %}[{{v.mount}}] KeyID: {{v.protector_id}}
{% endfor %}</textarea>
<button class="btn" type="button" style="margin-top:10px"
  onclick="var b=this;navigator.clipboard.writeText(document.getElementById('allinfo').value).then(function(){b.textContent='Скопійовано ✓';setTimeout(function(){b.textContent='📋 Копіювати інфо (без ключів)'},2000)})">📋 Копіювати інфо (без ключів)</button>
{% endif %}
<h3 style="margin:18px 0 6px">Історія</h3>
<table><tr><th>Час (Київ)</th><th>Дія</th><th>Хто</th><th>Деталі</th></tr>
{% for h in history %}
<tr><td class="muted mono">{{ h.ts|kyiv(true) }}</td>
<td><span class="pill {{ 'warn2' if h.action=='key_read' else ('bad' if ('fail' in h.action or h.action=='machine_delete') else 'ok') }}">{{h.action}}</span></td>
<td class="mono">{{h.actor or '-'}}</td><td class="muted">{{h.detail or ''}}</td></tr>
{% endfor %}
{% if not history %}<tr><td colspan="4" class="muted">Подій ще немає.</td></tr>{% endif %}
</table>

{% if full %}
<hr style="border:0;border-top:1px solid #2c3a52;margin:18px 0">
<form method="post" action="/machine/{{m.id}}/delete"
      onsubmit="return confirm('Списати цю машину? Запис і збережений ключ буде ВИДАЛЕНО назавжди.')">
  <button type="submit" style="background:none;border:1px solid var(--bad);color:#ff9a9a;border-radius:8px;padding:7px 14px;cursor:pointer">🗑 Списати машину</button>
  <span class="muted">  видаляє запис + ключ із сервера (для виведених з експлуатації АРМ)</span>
</form>
{% endif %}
</div>
"""

AUDIT = """
<h1>Журнал аудиту <span class="muted">(останні {{rows|length}})</span>
<a class="lnk" style="float:right;font-size:14px" href="/export/audit.csv">↓ експорт CSV</a></h1>
<div class="card"><table><tr><th>Час (Київ)</th><th>Дія</th><th>Хто</th><th>Деталі</th></tr>
{% for r in rows %}
<tr><td class="muted mono">{{ r.ts|kyiv(true) }}</td>
<td><span class="pill {{'bad' if 'fail' in r.action else ('warn2' if r.action=='key_read' else 'ok')}}">{{r.action}}</span></td>
<td class="mono">{{r.actor or '-'}}</td><td class="muted">{{r.detail or '-'}}</td></tr>
{% endfor %}</table></div>
"""


INVENTORY = """
<h1>Інвентар <span class="muted">({{machines|length}})</span>
<a class="lnk" style="float:right;font-size:14px" href="/export/inventory.csv">↓ експорт CSV</a></h1>
<div class="card">
<form method="get" action="/inventory" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
  <input type="text" name="q" value="{{q}}" placeholder="пошук: hostname / МВО / серійник / CPU / користувач / IP / модель..." style="flex:1;min-width:220px">
  <button class="btn" type="submit">Знайти</button>
</form>
</div>
<div class="card" style="overflow-x:auto">
<table><tr><th>Hostname</th><th>МВО</th><th>Модель</th><th>CPU</th><th>RAM</th><th>Диск C:</th><th>IPv4</th><th>Користувач</th><th>ОС (білд)</th><th>Безпека</th><th>Оновлено</th><th></th></tr>
{% for m in machines %}{% set i = m.inventory or {} %}
<tr><td class="mono">{{m.hostname}}</td>
<td>{{m.assignee or '-'}}</td>
<td>{{m.product or m.model or '-'}}</td>
<td>{{i.cpu or '-'}}{% if i.cpu_cores %}<br><span class="muted" style="font-size:12px">{{i.cpu_cores}}c/{{i.cpu_threads}}t</span>{% endif %}</td>
<td>{{ (i.ram_gb ~ ' ГБ') if i.ram_gb else '-' }}</td>
<td>{% if i.c_size_gb %}<span{% if i.c_free_gb is not none and i.c_free_gb < 15 %} class="pill bad"{% endif %}>{{i.c_free_gb}}/{{i.c_size_gb}} ГБ</span>{% else %}-{% endif %}</td>
<td class="mono">{{i.ipv4 or '-'}}</td>
<td>{{i.last_user or i.last_logon or '-'}}</td>
<td>{{i.os_caption or m.os_version or '-'}}{% if i.os_build %}<br><span class="muted" style="font-size:12px">build {{i.os_build}}{% if i.os_ubr %}.{{i.os_ubr}}{% endif %}</span>{% endif %}</td>
<td>{% if i.av_rtp is false %}<span class="pill bad">AV OFF</span>{% elif i.av_name %}<span class="pill ok" title="{{i.av_name}}">AV</span>{% endif %}{% if i.disk_health and i.disk_health != 'Healthy' %} <span class="pill warn2">диск: {{i.disk_health}}</span>{% endif %}{% if i.pending_reboot %} <span class="pill warn2">reboot?</span>{% endif %}{% if i.secure_boot is false %} <span class="pill warn2">SB off</span>{% endif %}</td>
<td class="muted">{{ m.inventory_at|kyiv }}</td>
<td><a class="lnk" href="/machine/{{m.id}}">→</a></td></tr>
{% endfor %}
{% if not machines %}<tr><td colspan="12" class="muted">Немає даних інвентарю. Зʼявиться після enroll/аудиту з оновленим клієнтом.</td></tr>{% endif %}
</table></div>
"""


COVERAGE = """
<h1>Покриття шифруванням <span class="muted">({{enrolled}} / {{total}})</span></h1>
<div class="card">
<p>Ця сторінка показує, <b>скільки АРМ з вашого парку вже зашифровано й здали ключ, а скільки ще ні</b>.
Завантажте список усіх машин (CSV) — нижче побачите по кожній 🟢 <i>зашифрована</i> або 🔴 <i>ще ні</i>.
Це ваш трекер розкочування (доменного інвентаря у вас нема, тож список ведемо тут).</p>

{% if full %}
<form method="post" action="/coverage/import" enctype="multipart/form-data"
      style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:6px">
  <input type="file" name="file" accept=".csv,text/csv" required>
  <button class="btn" type="submit">Імпортувати список</button>
  <a class="lnk" href="/coverage/template">↓ завантажити шаблон CSV</a>
</form>
{% else %}<p class="muted">🔒 Імпорт списку — лише роль «admin».</p>{% endif %}
<p class="muted" style="margin-top:8px">
<b>Формат:</b> CSV, перший рядок — заголовки: <span class="mono">hostname,serial,note</span><br>
Приклад рядка: <span class="mono">ARM-001,PF0ZJ6M8,Accounting</span><br>
Можна заповнити лише <span class="mono">hostname</span> або лише <span class="mono">serial</span>. Імпорт ЗАМІНЮЄ попередній список.
{% if total > 0 %}<br>Поточний список: <b>{{total}}</b> машин ({{enrolled}} зашифровано, {{total-enrolled}} — ні).{% endif %}
</p>
</div>

{% if total > 0 %}
<div class="card">
<table><tr><th>Hostname</th><th>Серійник</th><th>Примітка</th><th>Статус</th><th>Last seen</th></tr>
{% for r in rows %}
<tr><td class="mono">{{r.hostname or '-'}}</td><td class="mono">{{r.serial or '-'}}</td><td>{{r.note or ''}}</td>
<td>{% if r.enrolled %}<span class="pill ok">зашифрована</span>{% else %}<span class="pill bad">НЕ зашифровано</span>{% endif %}</td>
<td class="muted">{{ r.last_seen|kyiv }}</td></tr>
{% endfor %}
</table></div>
{% else %}
<div class="card"><p class="muted">Список ще порожній — завантажте CSV вище, щоб побачити покриття.</p></div>
{% endif %}
"""


BACKUPS = """
{% if flash %}{% if flash.startswith('ok:') %}<div class="card" style="background:#0c3a22;border-color:#1e6b43;margin-bottom:14px"><b>✅ Бекап успішно створено</b>{% if flash[3:] %} <span class="mono muted">{{ flash[3:] }}</span>{% endif %}</div>{% else %}<div class="err">❌ Помилка бекапу: {{ flash[4:] }}</div>{% endif %}{% endif %}
<h1>Бекапи <span class="muted">({{items|length}} · ретеншн 4 тижні)</span></h1>
<div class="card">
{% if full %}
<form method="post" action="/backups/run" style="display:inline" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='⏳ Робиться бекап…';document.getElementById('bkbar').style.display='block'">
  <button class="btn warn" type="submit">🗄 Зробити бекап зараз</button>
</form>
<div id="bkbar" style="display:none;margin-top:10px;height:8px;background:#1a2438;border-radius:999px;overflow:hidden">
  <div style="height:100%;width:45%;background:var(--acc);border-radius:999px;animation:bkmove 1.1s linear infinite"></div>
</div>
<span class="muted">  Старіші за 28 днів чистяться автоматично щодня.</span>
{% else %}<span class="muted">🔒 Керування бекапами — лише роль «admin».</span>{% endif %}
</div>
<div class="card">
<table><tr><th>Файл</th><th>Дата</th><th>Розмір</th><th>Дії</th></tr>
{% for b in items %}
<tr><td class="mono">{{b.name}}</td><td class="muted">{{b.mtime}}</td><td class="muted">{{b.size}} KB</td>
<td>{% if full %}<a class="lnk" href="/backups/download/{{b.name}}">завантажити</a> &nbsp;·&nbsp;
<form method="post" action="/backups/delete/{{b.name}}" style="display:inline" onsubmit="return confirm('Видалити цей бекап?')">
<button type="submit" style="background:none;border:0;color:#ff9a9a;cursor:pointer;padding:0;font:inherit">видалити</button></form>
{% else %}<span class="muted">—</span>{% endif %}</td></tr>
{% endfor %}
{% if not items %}<tr><td colspan="4" class="muted">Бекапів немає.</td></tr>{% endif %}
</table></div>
<p class="muted">Файли зашифровані (age). Розшифрувати — лише ОФЛАЙН приватним ключем (escrow-restore).</p>
"""


SERVER = """
{% if flash %}{% if flash.startswith('ok:') %}<div class="card" style="background:#0c3a22;border-color:#1e6b43;margin-bottom:14px"><b>✅ {{ flash[3:] }}</b></div>{% else %}<div class="err">❌ {{ flash[4:] }}</div>{% endif %}{% endif %}
<h1>Керування сервером</h1>

{% if full %}
<div class="card">
<h3 style="margin:0 0 10px">Стан сервісу</h3>
<p>Сховище ключів:
{% if unlocked %}<span class="pill ok">розблоковано</span>{% else %}<span class="pill bad">заблоковано</span>{% endif %}
<span class="muted"> · розблокування master-ключем — лише локально на сервері (escrow-unlock).</span></p>
{% if unlocked %}
<form method="post" action="/server/lock"
      onsubmit="return confirm('Заблокувати сервіс? Ключі стануть недоступні, доки не виконаєш escrow-unlock на сервері.')">
  <button type="submit" style="background:none;border:1px solid var(--bad);color:#ff9a9a;border-radius:8px;padding:7px 14px;cursor:pointer">🔒 Заблокувати сервіс зараз</button>
  <span class="muted">  вивантажує master-ключ з памʼяті</span>
</form>
{% endif %}
</div>

<div class="card">
<h3 style="margin:0 0 10px">Налаштування</h3>
<form method="post" action="/server/settings" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
  <div><label class="muted">Автовихід при бездіяльності (хв)</label><br>
  <input type="text" name="idle_timeout_min" value="{{idle_timeout_min}}" inputmode="numeric" style="width:120px"></div>
  <button class="btn" type="submit">Зберегти</button>
  <span class="muted">  від 5 до 720 хв. Сесія завершується після стількох хвилин без активності.</span>
</form>
</div>

<div class="card">
<h3 style="margin:0 0 10px">Адміністратори <span class="muted">({{admins|length}})</span></h3>
<table><tr><th>Користувач</th><th>Роль</th><th>Останній вхід</th><th>Backup-коди</th><th>Дії</th></tr>
{% for a in admins %}
<tr>
<td class="mono">{{a.username}}{% if a.username==me %} <span class="pill ok">це ви</span>{% endif %}</td>
<td><form method="post" action="/server/admins/{{a.username}}/role" style="display:flex;gap:6px;align-items:center;margin:0">
  <select name="role">
    <option value="admin" {{ 'selected' if a.role=='admin' else '' }}>admin</option>
    <option value="helpdesk" {{ 'selected' if a.role=='helpdesk' else '' }}>helpdesk</option>
  </select>
  <button class="btn" type="submit" style="padding:5px 10px">OK</button>
</form></td>
<td class="muted mono">{{ a.last_login|kyiv if a.last_login else '—' }}</td>
<td class="muted">{{a.backup_left}}</td>
<td>
  <form method="post" action="/server/admins/{{a.username}}/reset2fa" style="display:inline"
        onsubmit="return confirm('Скинути 2FA цьому користувачу? Старий код перестане діяти, буде новий QR.')"><button type="submit" style="background:none;border:0;color:var(--acc);cursor:pointer;padding:0;font:inherit">скинути 2FA</button></form> ·
  <form method="post" action="/server/admins/{{a.username}}/backupcodes" style="display:inline"
        onsubmit="return confirm('Нові backup-коди цьому користувачу? Старі стануть недійсні.')"><button type="submit" style="background:none;border:0;color:var(--acc);cursor:pointer;padding:0;font:inherit">нові коди</button></form>
  {% if a.username!=me %} ·
  <form method="post" action="/server/admins/{{a.username}}/delete" style="display:inline"
        onsubmit="return confirm('Видалити цього адміна? Дію не відмінити.')"><button type="submit" style="background:none;border:0;color:#ff9a9a;cursor:pointer;padding:0;font:inherit">видалити</button></form>
  {% endif %}
</td>
</tr>
{% endfor %}
</table>
<h4 style="margin:16px 0 6px">Додати адміністратора</h4>
<form method="post" action="/server/admins/add" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
  <div><label class="muted">Користувач</label><br><input type="text" name="username" style="width:170px"></div>
  <div><label class="muted">Пароль (мін 10)</label><br><input type="password" name="password" style="width:170px"></div>
  <div><label class="muted">Роль</label><br><select name="role"><option value="admin">admin</option><option value="helpdesk">helpdesk</option></select></div>
  <button class="btn" type="submit">Створити</button>
</form>
</div>
{% endif %}

<div class="card">
<h3 style="margin:0 0 10px">Мій профіль <span class="muted">({{me}})</span></h3>
<form method="post" action="/server/me/password" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
  <div><label class="muted">Поточний пароль</label><br><input type="password" name="old" style="width:170px"></div>
  <div><label class="muted">Новий пароль (мін 10)</label><br><input type="password" name="new1" style="width:170px"></div>
  <div><label class="muted">Повтор</label><br><input type="password" name="new2" style="width:170px"></div>
  <button class="btn" type="submit">Змінити пароль</button>
</form>
<form method="post" action="/server/me/reset2fa" style="margin-top:12px"
      onsubmit="return confirm('Перегенерувати свій 2FA? Доведеться наново додати код у застосунок.')">
  <button class="btn warn" type="submit">Перегенерувати мій 2FA</button>
  <span class="muted">  покажемо новий QR і нові backup-коди</span>
</form>
</div>
"""


SERVER_CRED = """
<p><a class="lnk" href="/server">← Керування сервером</a></p>
<h1>{{title}}</h1>
<div class="card">
<p class="muted">Покажемо це лише один раз — збережи зараз.</p>
{% if uri %}
<p><span class="muted">Користувач:</span> <span class="mono">{{username}}</span></p>
<p>Відскануй QR у застосунку (Google Authenticator / Aegis):</p>
<div style="background:#fff;display:inline-block;padding:10px;border-radius:8px;width:230px">{{ qr|safe }}</div>
<p class="muted" style="margin-top:10px">Якщо не скануєш — додай вручну:<br>
секрет: <span class="mono">{{secret}}</span><br>
otpauth: <span class="mono" style="word-break:break-all">{{uri}}</span></p>
{% endif %}
{% if codes %}
<h3 style="margin:16px 0 6px">Backup-коди <span class="muted">(кожен працює ОДИН раз замість коду 2FA)</span></h3>
<div class="key" style="letter-spacing:1px">{% for c in codes %}{{c}}{% if not loop.last %}  ·  {% endif %}{% endfor %}</div>
{% endif %}
<p style="margin-top:16px"><a class="btn" href="/server" style="text-decoration:none">Готово</a></p>
</div>
"""


# ---------------- i18n (uk default / en) ----------------
# Post-render translation: templates stay Ukrainian; in EN mode we translate the
# whole HTML via EN (uk->en); in UK mode we localise the few English nav labels
# via UKFIX (en->uk). Applied longest-key-first to avoid partial overlaps.
def _lang(request):
    try:
        return "en" if request.session.get("lang") == "en" else "uk"
    except Exception:
        return "uk"


UKFIX = {
    ">Dashboard<": ">Панель<", ">Coverage<": ">Покриття<", ">Backups<": ">Бекапи<",
    ">Audit<": ">Аудит<", ">Logout<": ">Вихід<", "Last seen": "Востаннє", "Hostname": "Імʼя хоста",
}

EN = {
    # nav / chrome
    ">Інвентар<": ">Inventory<", ">Керування<": ">Management<",
    # login
    "🔐 Вхід": "🔐 Sign in", "Користувач": "User", "Пароль": "Password",
    "Код 2FA (TOTP)": "2FA code (TOTP)", "Увійти": "Sign in",
    "Невірний логін, пароль або код 2FA": "Invalid username, password or 2FA code",
    # dashboard
    "Робочі станції": "Workstations", "сервіс LOCKED — ключі недоступні": "service LOCKED — keys unavailable",
    "↓ експорт CSV": "↓ export CSV", "всього станцій": "total stations",
    "захист призупинено": "protection suspended", "зниклі (&gt;30 дн)": "missing (&gt;30 d)",
    "стан сервісу": "service state", "останній бекап": "last backup",
    "🗄 Останній бекап:": "🗄 Last backup:", "свіжий": "fresh", "застарів (": "stale (",
    " дн тому)": " d ago)", "· збережено ": "· kept ", "бекапів немає!": "no backups!",
    "пошук: hostname / серійник / Recovery Key ID...": "search: hostname / serial / Recovery Key ID...",
    "усі статуси": "all statuses", "зашифровані": "encrypted",
    "сорт: hostname": "sort: hostname", "сорт: last seen": "sort: last seen",
    "сорт: дата enroll": "sort: enroll date", "Застосувати": "Apply",
    "МВО (відповідальний)": "Owner (responsible)", "МВО": "Owner", "Серійник": "Serial",
    "Диски": "Disks", "Диск C:": "Disk C:", "Диск": "Drive",
    "зашифровано": "encrypted", "шифрується": "encrypting", "не зашифр.": "not encr.",
    "захист OFF": "protection OFF", "відкрити →": "open →", "зник ": "missing ",
    " дн</span>": " d</span>", "Поки немає записів.": "No records yet.",
    # machine page
    "← усі станції": "← all stations", "Серійник:": "Serial:", "Пристрій:": "Device:",
    "ОС:": "OS:", "Примітки": "Notes", "Зберегти": "Save", "Інвентар": "Inventory",
    "(оновлено ": "(updated ", "Мережа": "Network", "Аптайм": "Uptime", " дн (з ": " d (since ",
    "Безпека": "Security", "встановлено ": "installed ", "BIOS / плата": "BIOS / board",
    "диск: ": "disk: ", "сигнатури ": "signatures ", "RTP ВИМК!": "RTP OFF!",
    "очікує перезавантаження": "pending reboot",
    "ОС": "OS", "Увімк": "On", "Вимк": "Off", "ГБ": "GB", "вільно": "free",
    " дн ·": " d ·", " дн<": " d<", "Формат:": "Format:", "— ні)": "— no)", "Бекапи": "Backups",
    "Recovery key ID (protector)": "Recovery key ID (protector)", "Статус": "Status",
    "показано": "revealed", "приховано": "hidden", "Ключі відновлення": "Recovery keys",
    "Копіювати ключ": "Copy key", "Скопійовано ✓": "Copied ✓",
    "Клік по ключу виділяє його повністю. Перегляд записано в аудит.": "Click the key to select it fully. The view is logged in the audit.",
    "Введи код на екрані відновлення BitLocker залоченого ПК.": "Enter the code on the BitLocker recovery screen of the locked PC.",
    "📋 Копіювати всю інфо": "📋 Copy all info", "🔑 Показати ключ(і) відновлення": "🔑 Reveal recovery key(s)",
    "  (дія записується в журнал аудиту)": "  (action is logged in the audit)",
    "Сервіс LOCKED — спершу escrow-unlock на сервері": "Service LOCKED — run escrow-unlock on the server first",
    "🔒 Перегляд ключів доступний лише ролі «admin».": "🔒 Key reveal is available only to the «admin» role.",
    "📋 Копіювати інфо (без ключів)": "📋 Copy info (without keys)", "Історія": "History",
    "Час (Київ)": "Time (Kyiv)", "Дія": "Action", "Хто": "Who", "Деталі": "Details",
    "Подій ще немає.": "No events yet.", "🗑 Списати машину": "🗑 Decommission machine",
    "  видаляє запис + ключ із сервера (для виведених з експлуатації АРМ)": "  removes the record + key from the server (for decommissioned PCs)",
    "Списати цю машину? Запис і збережений ключ буде ВИДАЛЕНО назавжди.": "Decommission this machine? The record and stored key will be DELETED permanently.",
    # audit log
    "Журнал аудиту": "Audit log", "(останні ": "(last ",
    # inventory
    "пошук: hostname / МВО / серійник / CPU / користувач / IP / модель...": "search: hostname / Owner / serial / CPU / user / IP / model...",
    "Знайти": "Find", "Модель": "Model", "Користувач": "User", "ОС (білд)": "OS (build)", "Оновлено": "Updated",
    "Немає даних інвентарю. Зʼявиться після enroll/аудиту з оновленим клієнтом.": "No inventory data yet. It appears after enroll/audit from an updated client.",
    # coverage
    "Покриття шифруванням": "Encryption coverage",
    "Ця сторінка показує, ": "This page shows ", "скільки АРМ з вашого парку вже зашифровано й здали ключ, а скільки ще ні": "how many PCs in your fleet are already encrypted and escrowed their key, and how many are not yet",
    "Завантажте список усіх машин (CSV) — нижче побачите по кожній": "Upload a list of all machines (CSV) — below you will see, per machine,",
    "зашифрована": "encrypted", "ще ні": "not yet",
    "Це ваш трекер розкочування (доменного інвентаря у вас нема, тож список ведемо тут).": "This is your rollout tracker (you have no domain inventory, so we keep the list here).",
    "Імпортувати список": "Import list", "↓ завантажити шаблон CSV": "↓ download CSV template",
    "🔒 Імпорт списку — лише роль «admin».": "🔒 List import — only the «admin» role.",
    "перший рядок — заголовки:": "first row — headers:", "Приклад рядка:": "Example row:",
    "Можна заповнити лише": "You may fill in only", "Імпорт ЗАМІНЮЄ попередній список.": "Import REPLACES the previous list.",
    "Поточний список:": "Current list:", " машин (": " machines (", "Примітка": "Note",
    "НЕ зашифровано": "NOT encrypted", "або лише": "or only", "або": "or",
    "Список ще порожній — завантажте CSV вище, щоб побачити покриття.": "The list is empty — upload a CSV above to see coverage.",
    # backups
    "· ретеншн 4 тижні": "· retention 4 weeks", "🗄 Зробити бекап зараз": "🗄 Make a backup now",
    "Робиться бекап…": "Backing up…",
    "✅ Бекап успішно створено": "✅ Backup created successfully", "❌ Помилка бекапу:": "❌ Backup error:",
    "  Старіші за 28 днів чистяться автоматично щодня.": "  Older than 28 days are pruned automatically every day.",
    "🔒 Керування бекапами — лише роль «admin».": "🔒 Backup management — only the «admin» role.",
    "Файл": "File", "Дата": "Date", "Розмір": "Size", "Дії": "Actions",
    "завантажити": "download", "видалити": "delete", "Видалити цей бекап?": "Delete this backup?",
    "Бекапів немає.": "No backups.",
    "Файли зашифровані (age). Розшифрувати — лише ОФЛАЙН приватним ключем (escrow-restore).": "Files are encrypted (age). Decrypt only OFFLINE with the private key (escrow-restore).",
    # stale-key (protector mismatch) / login banner / reveal reason
    "ключ застарів": "key is stale",
    "⚠ Сервіс LOCKED — видача ключів не працює, доки не виконано escrow-unlock на сервері.":
        "⚠ Service LOCKED — key reveal does not work until escrow-unlock is run on the server.",
    "причина / тікет (напр. користувач залочився)": "reason / ticket (e.g. user got locked out)",
    "  (хто, коли й причина — пишуться в журнал аудиту)": "  (who, when and reason — logged in the audit)",
    # server management
    "Керування сервером": "Server management", "Стан сервісу": "Service state",
    "Сховище ключів:": "Key vault:", "розблоковано": "unlocked", "заблоковано": "locked",
    " · розблокування master-ключем — лише локально на сервері (escrow-unlock).":
        " · unlocking with the master key — only locally on the server (escrow-unlock).",
    "Заблокувати сервіс? Ключі стануть недоступні, доки не виконаєш escrow-unlock на сервері.":
        "Lock the service? Keys become unavailable until you run escrow-unlock on the server.",
    "🔒 Заблокувати сервіс зараз": "🔒 Lock the service now",
    "  вивантажує master-ключ з памʼяті": "  unloads the master key from memory",
    "Налаштування збережено": "Settings saved", "Налаштування": "Settings",
    "Автовихід при бездіяльності (хв)": "Auto-logout on idle (min)",
    "  від 5 до 720 хв. Сесія завершується після стількох хвилин без активності.":
        "  from 5 to 720 min. The session ends after that many minutes without activity.",
    "Невірне число (5–720)": "Invalid number (5–720)",
    "Адміністратори": "Administrators", "Останній вхід": "Last login", "Backup-коди": "Backup codes",
    "Роль": "Role", "це ви": "you", "скинути 2FA": "reset 2FA", "нові коди": "new codes",
    "Скинути 2FA цьому користувачу? Старий код перестане діяти, буде новий QR.":
        "Reset 2FA for this user? The old code stops working, a new QR is issued.",
    "Нові backup-коди цьому користувачу? Старі стануть недійсні.":
        "New backup codes for this user? The old ones become invalid.",
    "Видалити цього адміна? Дію не відмінити.": "Delete this admin? This cannot be undone.",
    "Додати адміністратора": "Add administrator", "Пароль (мін 10)": "Password (min 10)",
    "Створити": "Create", "Мій профіль": "My profile", "Поточний пароль": "Current password",
    "Новий пароль (мін 10)": "New password (min 10)", "Повтор": "Repeat",
    "Змінити пароль": "Change password",
    "Перегенерувати свій 2FA? Доведеться наново додати код у застосунок.":
        "Regenerate your 2FA? You will have to add the code to the app again.",
    "Перегенерувати мій 2FA": "Regenerate my 2FA",
    "  покажемо новий QR і нові backup-коди": "  we will show a new QR and new backup codes",
    # server flash / errors
    "Сервіс заблоковано": "Service locked", "Роль змінено": "Role changed",
    "Адміна видалено": "Admin deleted", "Пароль змінено": "Password changed",
    "Пароль закороткий (мін 10)": "Password too short (min 10)",
    "Паролі не збігаються": "Passwords do not match",
    "Невірний поточний пароль": "Wrong current password",
    "Такий користувач уже існує": "Such user already exists", "Порожній логін": "Empty username",
    "Не можна видалити останнього адміна": "Cannot delete the last admin",
    "Не можна видалити себе": "Cannot delete yourself",
    "Не можна змінити роль останнього адміна": "Cannot change the role of the last admin",
    # credentials one-time page
    "Новий адміністратор": "New administrator", "Скидання 2FA": "2FA reset",
    "Нові backup-коди": "New backup codes", "Мій новий 2FA": "My new 2FA",
    "Покажемо це лише один раз — збережи зараз.": "Shown only once — save it now.",
    "Відскануй QR у застосунку (Google Authenticator / Aegis):":
        "Scan the QR in your app (Google Authenticator / Aegis):",
    "Якщо не скануєш — додай вручну:": "If you cannot scan — add manually:",
    "секрет:": "secret:", "(кожен працює ОДИН раз замість коду 2FA)": "(each works ONCE instead of a 2FA code)",
    "Готово": "Done",
}


def _translate(html, lang):
    table = EN if lang == "en" else UKFIX
    for k in sorted(table, key=len, reverse=True):
        html = html.replace(k, table[k])
    return html


def _page(body_tpl, user, lang="uk", **ctx):
    body = _render(body_tpl, user=user, **ctx)
    html = _render(BASE, user=user, body=body, role=ctx.get("role_name"),
                   lang=lang, wide=ctx.get("wide", False))
    return HTMLResponse(_translate(html, lang))


# ---------------- routes ----------------
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return _page(LOGIN, user=None, lang=_lang(request), error="",
                 locked=not crypto.vault.is_unlocked())


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), code: str = Form(...)):
    a = db.get_admin(username)
    second = False
    if a and auth.verify_pw(password, a["pw_hash"]):
        if auth.verify_totp(a["totp_secret"], code):
            second = True
        elif db.use_backup_code(username, auth.hash_code(code)):
            second = True
            db.log("login_backup_code", actor=username)
    if a and second:
        request.session["admin"] = username
        request.session["role"] = a.get("role") or "admin"
        request.session["ts"] = time.time()
        db.set_last_login(username)
        db.log("login", actor=username, detail="role=" + (a.get("role") or "admin"))
        return RedirectResponse("/", status_code=303)
    db.log("login_fail", actor=username, detail=request.client.host if request.client else None)
    lang = _lang(request)
    html = _render(BASE, user=None, lang=lang, body=_render(LOGIN, user=None,
                   error="Невірний логін, пароль або код 2FA",
                   locked=not crypto.vault.is_unlocked()))
    return HTMLResponse(_translate(html, lang), status_code=401)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/lang/{code}")
def set_lang(request: Request, code: str):
    request.session["lang"] = "en" if code == "en" else "uk"
    ref = request.headers.get("referer") or "/"
    return RedirectResponse(ref, status_code=303)


STALE_DAYS = 30


def _days_since(iso):
    if not iso:
        return None
    try:
        t = datetime.datetime.fromisoformat(iso)
        if t.tzinfo:
            t = t.replace(tzinfo=None)
        return (datetime.datetime.utcnow() - t).days
    except Exception:
        return None


def _suspended(m):
    # encrypted volume whose protection is reported Off => BitLocker suspended (data effectively open)
    for v in m["volumes"]:
        prot = (v.get("protection") or "")
        st = (v.get("status") or "")
        if "FullyEncrypted" in st and prot and prot.lower() in ("off", "0"):
            return True
    return False


def _mstatus(m):
    sts = [(v["status"] or "") for v in m["volumes"]]
    if not sts:
        return "other"
    if all("FullyEncrypted" in s for s in sts):
        return "full"
    if any("Progress" in s for s in sts):
        return "progress"
    return "other"


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, q: str = "", status: str = "all", sort: str = "host"):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    all_machines = db.report()
    for m in all_machines:
        m["stale_days"] = _days_since(m["last_seen"])
        m["suspended"] = _suspended(m)
        m["mismatch"] = any(db.volume_key_mismatch(v) for v in m["volumes"])
    stats = {"total": len(all_machines),
             "full": sum(1 for m in all_machines if _mstatus(m) == "full"),
             "progress": sum(1 for m in all_machines if _mstatus(m) == "progress"),
             "stale": sum(1 for m in all_machines if m["stale_days"] is not None and m["stale_days"] >= STALE_DAYS),
             "suspended": sum(1 for m in all_machines if m["suspended"]),
             "mismatch": sum(1 for m in all_machines if m["mismatch"])}
    machines = all_machines
    if q:
        ql = q.lower()
        kid = db.machine_ids_by_keyid(q)
        machines = [m for m in machines if ql in (m["hostname"] or "").lower()
                    or ql in (m["serial"] or "").lower() or m["id"] in kid]
    if status in ("full", "progress", "other"):
        machines = [m for m in machines if _mstatus(m) == status]
    elif status == "stale":
        machines = [m for m in machines if m["stale_days"] is not None and m["stale_days"] >= STALE_DAYS]
    elif status == "suspended":
        machines = [m for m in machines if m["suspended"]]
    elif status == "mismatch":
        machines = [m for m in machines if m["mismatch"]]
    if sort == "seen":
        machines.sort(key=lambda m: m["last_seen"] or "", reverse=True)
    elif sort == "enrolled":
        machines.sort(key=lambda m: m["enrolled_at"] or "", reverse=True)
    else:
        machines.sort(key=lambda m: (m["hostname"] or "").lower())
    return _page(DASH, user=u, machines=machines, q=q, status=status, sort=sort,
                 unlocked=crypto.vault.is_unlocked(), bk=_last_backup(), stats=stats,
                 role_name=_role(request), lang=_lang(request))


@router.get("/machine/{mid}", response_class=HTMLResponse)
def machine(request: Request, mid: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    data = db.get_keys(machine_id=mid)
    if not data:
        raise HTTPException(404, "not found")
    vols = [{"mount": v["mount"], "protector_id": v["protector_id"]} for v in data["volumes"]]
    return _page(MACHINE, user=u, m=data["machine"], vols=vols, revealed=None,
                 unlocked=crypto.vault.is_unlocked(), history=db.audit_for_machine(mid),
                 full=_is_full(request), role_name=_role(request), lang=_lang(request))


@router.post("/machine/{mid}/update")
def machine_update(request: Request, mid: str, assignee: str = Form(""), note: str = Form("")):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    db.update_machine_meta(mid, assignee.strip(), note.strip())
    db.log("update_meta", machine_id=mid, actor=u)
    return RedirectResponse(f"/machine/{mid}", status_code=303)


@router.post("/machine/{mid}/delete")
def machine_delete(request: Request, mid: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    data = db.get_keys(machine_id=mid)
    db.delete_machine(mid)
    db.log("machine_delete", machine_id=mid, actor=u,
           detail=(data["machine"]["hostname"] if data else mid))
    return RedirectResponse("/", status_code=303)


@router.post("/machine/{mid}/reveal", response_class=HTMLResponse)
def reveal(request: Request, mid: str, reason: str = Form("")):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    data = db.get_keys(machine_id=mid)
    if not data:
        raise HTTPException(404, "not found")
    vols = [{"mount": v["mount"], "protector_id": v["protector_id"]} for v in data["volumes"]]
    if not crypto.vault.is_unlocked():
        return _page(MACHINE, user=u, m=data["machine"], vols=vols, revealed=None, unlocked=False,
                     history=db.audit_for_machine(mid), full=_is_full(request), role_name=_role(request), lang=_lang(request))
    revealed = [{"rp": crypto.vault.decrypt(v["rec_pw_enc"])} for v in data["volumes"]]
    host = data["machine"]["hostname"] or ""
    reason = (reason or "").strip()
    db.log("key_read", machine_id=mid, actor=u,
           detail="web:" + host + (" | " + reason if reason else ""))
    alert(f"🔑 BitLocker: {u} показав ключ '{host}'" + (f" — {reason}" if reason else ""))
    return _page(MACHINE, user=u, m=data["machine"], vols=vols, revealed=revealed, unlocked=True,
                 history=db.audit_for_machine(mid), full=True, role_name=_role(request), lang=_lang(request))


def _csv_response(rows, header, filename):
    buf = io.StringIO()
    buf.write("﻿")  # BOM so Excel reads UTF-8 (Cyrillic) correctly
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@router.get("/export/machines.csv")
def export_machines(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    rows = []
    for m in db.report():
        vols = "; ".join(f"{v['mount']} {v.get('status') or ''}".strip() for v in m["volumes"])
        rows.append([m["hostname"], m["serial"], m.get("manufacturer") or "",
                     m.get("product") or "", m["model"] or "", m.get("os_version") or "",
                     m.get("assignee") or "", m.get("note") or "", vols,
                     m["enrolled_at"] or "", m["last_seen"] or ""])
    db.log("export_machines", actor=u, detail=f"{len(rows)} rows")
    return _csv_response(rows,
        ["hostname", "serial", "manufacturer", "product", "model", "os_version",
         "mvo", "note", "volumes", "enrolled_at", "last_seen"],
        "machines.csv")


@router.get("/export/audit.csv")
def export_audit(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    rows = [[r["ts"], r["action"], r.get("actor") or "", r.get("detail") or ""]
            for r in db.audit_tail(5000)]
    db.log("export_audit", actor=u, detail=f"{len(rows)} rows")
    return _csv_response(rows, ["ts", "action", "actor", "detail"], "audit.csv")


@router.get("/inventory", response_class=HTMLResponse)
def inventory(request: Request, q: str = ""):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    machines = db.report()
    if q:
        ql = q.lower()

        def _hit(m):
            i = m.get("inventory") or {}
            blob = " ".join(str(x) for x in [
                m.get("hostname"), m.get("serial"), m.get("product"), m.get("model"),
                m.get("assignee"), i.get("cpu"), i.get("last_user"), i.get("ipv4"), i.get("os_caption"),
            ] if x)
            return ql in blob.lower()

        machines = [m for m in machines if _hit(m)]
    machines.sort(key=lambda m: (m["hostname"] or "").lower())
    return _page(INVENTORY, user=u, machines=machines, q=q, wide=True,
                 role_name=_role(request), lang=_lang(request))


@router.get("/export/inventory.csv")
def export_inventory(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    rows = []
    for m in db.report():
        i = m.get("inventory") or {}
        disks = "; ".join(f"{d.get('model', '?')} {d.get('size_gb', '?')}GB" for d in (i.get("disks") or []))
        rows.append([m["hostname"], m.get("assignee") or "", m["serial"] or "", m.get("product") or m.get("model") or "",
                     i.get("cpu") or "", i.get("cpu_cores") or "", i.get("cpu_threads") or "",
                     i.get("ram_gb") or "", i.get("c_free_gb") or "", i.get("c_size_gb") or "", disks,
                     i.get("ipv4") or "", i.get("mac") or "", i.get("last_user") or "", i.get("domain") or "",
                     i.get("os_caption") or m.get("os_version") or "", i.get("os_build") or "",
                     i.get("os_arch") or "", i.get("os_install") or "", i.get("uptime_days") or "",
                     i.get("tpm_version") or "", i.get("secure_boot") if i.get("secure_boot") is not None else "",
                     i.get("bios_version") or "", i.get("board") or "", m.get("inventory_at") or ""])
    db.log("export_inventory", actor=u, detail=f"{len(rows)} rows")
    return _csv_response(rows,
        ["hostname", "mvo", "serial", "model", "cpu", "cpu_cores", "cpu_threads", "ram_gb", "c_free_gb",
         "c_size_gb", "disks", "ipv4", "mac", "last_user", "domain", "os", "os_build", "os_arch",
         "os_install", "uptime_days", "tpm", "secure_boot", "bios", "board", "inventory_at"],
        "inventory.csv")


@router.get("/coverage", response_class=HTMLResponse)
def coverage(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    rows = db.coverage()
    enrolled = sum(1 for r in rows if r["enrolled"])
    return _page(COVERAGE, user=u, rows=rows, total=len(rows), enrolled=enrolled, full=_is_full(request), role_name=_role(request), lang=_lang(request))


@router.post("/coverage/import")
async def coverage_import(request: Request, file: UploadFile = File(...)):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    raw = await file.read()
    text = raw.decode("utf-8-sig", errors="replace")
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        rl = {(k or "").lower().strip(): (v or "").strip() for k, v in r.items()}
        host = rl.get("hostname") or rl.get("host") or rl.get("name") or rl.get("computer")
        ser = rl.get("serial") or rl.get("serialnumber") or rl.get("sn")
        note = rl.get("note") or rl.get("department") or rl.get("user") or ""
        if host or ser:
            rows.append({"hostname": host, "serial": ser, "note": note})
    db.set_expected(rows)
    db.log("import_assets", actor=u, detail=f"{len(rows)} rows (web)")
    return RedirectResponse("/coverage", status_code=303)


@router.get("/coverage/template")
def coverage_template(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    sample = "hostname,serial,note\nARM-001,PF0ZJ6M8,Buhgalteria\nARM-002,PF1ABCDE,Kasa\n"
    return Response(content=sample, media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=assets-template.csv"})


@router.get("/auditlog", response_class=HTMLResponse)
def auditlog(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    return _page(AUDIT, user=u, rows=db.audit_tail(200), role_name=_role(request), lang=_lang(request))


@router.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    return _page(BACKUPS, user=u, items=_list_backups(), full=_is_full(request), flash=request.session.pop("flash", None), role_name=_role(request), lang=_lang(request))


@router.post("/backups/run")
def backups_run(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    try:
        r = backup.run_backup()
        if r.get("ok"):
            db.log("backup_run", actor=u, detail=r.get("file"))
            request.session["flash"] = "ok:" + (r.get("file") or "")
        else:
            db.log("backup_run_fail", actor=u, detail=r.get("msg"))
            request.session["flash"] = "err:" + (r.get("msg") or "backup failed")
    except Exception as e:
        db.log("backup_run_fail", actor=u, detail=str(e))
        request.session["flash"] = "err:" + str(e)
    return RedirectResponse("/backups", status_code=303)


@router.get("/backups/download/{name}")
def backups_download(request: Request, name: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    if not _safe_backup_name(name):
        raise HTTPException(404, "not found")
    path = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    db.log("backup_download", actor=u, detail=name)
    return FileResponse(path, filename=name, media_type="application/octet-stream")


@router.post("/backups/delete/{name}")
def backups_delete(request: Request, name: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    if _safe_backup_name(name):
        path = os.path.join(BACKUP_DIR, name)
        if os.path.isfile(path):
            os.remove(path)
            db.log("backup_delete", actor=u, detail=name)
    return RedirectResponse("/backups", status_code=303)


# ---------------- server management ----------------
def _flash(request, msg, target="/server"):
    request.session["flash"] = msg
    return RedirectResponse(target, status_code=303)


def _cred_page(request, user, title, username, secret, codes):
    """One-time display of TOTP QR/secret and/or backup codes (never shown again)."""
    uri = auth.provisioning_uri(secret, username) if secret else None
    qr = auth.qr_svg(uri) if uri else None
    return _page(SERVER_CRED, user=user, title=title, username=username,
                 secret=secret, uri=uri, qr=qr, codes=codes,
                 role_name=_role(request), lang=_lang(request))


@router.get("/server", response_class=HTMLResponse)
def server_page(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    full = _is_full(request)
    return _page(SERVER, user=u, me=u, full=full,
                 unlocked=crypto.vault.is_unlocked(),
                 admins=db.list_admins() if full else [],
                 idle_timeout_min=db.get_setting("idle_timeout_min", "60"),
                 flash=request.session.pop("flash", None),
                 role_name=_role(request), lang=_lang(request))


@router.post("/server/settings")
def server_settings(request: Request, idle_timeout_min: str = Form("60")):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    try:
        v = int(idle_timeout_min)
        if v < 5 or v > 720:
            raise ValueError
    except ValueError:
        return _flash(request, "err:Невірне число (5–720)")
    db.set_setting("idle_timeout_min", v)
    db.log("settings_update", actor=u, detail=f"idle_timeout_min={v}")
    return _flash(request, "ok:Налаштування збережено")


@router.post("/server/lock")
def server_lock(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    crypto.vault.lock()
    db.log("service_lock", actor=u)
    return _flash(request, "ok:Сервіс заблоковано")


@router.post("/server/admins/add", response_class=HTMLResponse)
def server_admin_add(request: Request, username: str = Form(""), password: str = Form(""),
                     role: str = Form("admin")):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    username = username.strip()
    role = role if role in ("admin", "helpdesk") else "admin"
    if not username:
        return _flash(request, "err:Порожній логін")
    if db.get_admin(username):
        return _flash(request, "err:Такий користувач уже існує")
    if len(password) < 10:
        return _flash(request, "err:Пароль закороткий (мін 10)")
    secret = auth.new_totp_secret()
    db.create_admin(username, auth.hash_pw(password), secret, role)
    codes = auth.gen_backup_codes(8)
    db.set_backup_codes(username, [auth.hash_code(c) for c in codes])
    db.log("admin_create", actor=u, detail=f"{username} role={role}")
    return _cred_page(request, u, "Новий адміністратор", username, secret, codes)


@router.post("/server/admins/{username}/role")
def server_admin_role(request: Request, username: str, role: str = Form("admin")):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    a = db.get_admin(username)
    if not a:
        raise HTTPException(404, "not found")
    role = role if role in ("admin", "helpdesk") else "admin"
    if role != "admin" and a.get("role") == "admin" and db.count_full_admins() <= 1:
        return _flash(request, "err:Не можна змінити роль останнього адміна")
    db.set_role(username, role)
    db.log("admin_setrole", actor=u, detail=f"{username}->{role}")
    return _flash(request, "ok:Роль змінено")


@router.post("/server/admins/{username}/reset2fa", response_class=HTMLResponse)
def server_admin_reset2fa(request: Request, username: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    if not db.get_admin(username):
        raise HTTPException(404, "not found")
    secret = auth.new_totp_secret()
    db.set_totp_secret(username, secret)
    codes = auth.gen_backup_codes(8)
    db.set_backup_codes(username, [auth.hash_code(c) for c in codes])
    db.log("admin_reset2fa", actor=u, detail=username)
    return _cred_page(request, u, "Скидання 2FA", username, secret, codes)


@router.post("/server/admins/{username}/backupcodes", response_class=HTMLResponse)
def server_admin_backupcodes(request: Request, username: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    if not db.get_admin(username):
        raise HTTPException(404, "not found")
    codes = auth.gen_backup_codes(8)
    db.set_backup_codes(username, [auth.hash_code(c) for c in codes])
    db.log("admin_backupcodes", actor=u, detail=username)
    return _cred_page(request, u, "Нові backup-коди", username, None, codes)


@router.post("/server/admins/{username}/delete")
def server_admin_delete(request: Request, username: str):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if not _is_full(request):
        raise HTTPException(403, "forbidden (read-only role)")
    a = db.get_admin(username)
    if not a:
        raise HTTPException(404, "not found")
    if username == u:
        return _flash(request, "err:Не можна видалити себе")
    if a.get("role") == "admin" and db.count_full_admins() <= 1:
        return _flash(request, "err:Не можна видалити останнього адміна")
    db.delete_admin(username)
    db.log("admin_delete", actor=u, detail=username)
    return _flash(request, "ok:Адміна видалено")


@router.post("/server/me/password")
def server_me_password(request: Request, old: str = Form(""), new1: str = Form(""),
                       new2: str = Form("")):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    a = db.get_admin(u)
    if not a or not auth.verify_pw(old, a["pw_hash"]):
        return _flash(request, "err:Невірний поточний пароль")
    if len(new1) < 10:
        return _flash(request, "err:Пароль закороткий (мін 10)")
    if new1 != new2:
        return _flash(request, "err:Паролі не збігаються")
    db.set_password(u, auth.hash_pw(new1))
    db.log("admin_passwd", actor=u)
    return _flash(request, "ok:Пароль змінено")


@router.post("/server/me/reset2fa", response_class=HTMLResponse)
def server_me_reset2fa(request: Request):
    u = _user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    secret = auth.new_totp_secret()
    db.set_totp_secret(u, secret)
    codes = auth.gen_backup_codes(8)
    db.set_backup_codes(u, [auth.hash_code(c) for c in codes])
    db.log("admin_self_reset2fa", actor=u)
    return _cred_page(request, u, "Мій новий 2FA", u, secret, codes)

#!/usr/bin/env python3
"""Health monitor for the escrow service -> Telegram alert on state change.

Checks local /healthz; states: ok | locked | down. Alerts ONLY on change
(no spam). Config in /opt/escrow/alert.conf (TELEGRAM_TOKEN / TELEGRAM_CHAT).
If not configured, it just tracks state silently. Run by cron every 5 min.
Run with arg 'test' to send a test message.
"""
import os, sys, json, smtplib, platform, urllib.request, urllib.parse
from email.message import EmailMessage

ESC = "/opt/escrow"
STATE = os.path.join(ESC, "data", ".monitor_state")
CONF = os.path.join(ESC, "alert.conf")

conf = {}
if os.path.exists(CONF):
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
TOKEN = conf.get("TELEGRAM_TOKEN", "")
CHAT = conf.get("TELEGRAM_CHAT", "")
HOST = platform.node() or "escrow"


def tg(msg):
    if not TOKEN or not CHAT:
        return None  # not configured
    try:
        data = urllib.parse.urlencode({"chat_id": CHAT, "text": msg}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                               data=data, timeout=12)
        return True
    except Exception:
        return False


def mail(msg):
    host = conf.get("SMTP_HOST", "")
    to = conf.get("SMTP_TO", "")
    if not host or not to:
        return None  # not configured
    try:
        m = EmailMessage()
        m["Subject"] = f"BitLocker escrow [{HOST}] alert"
        m["From"] = conf.get("SMTP_FROM") or conf.get("SMTP_USER") or f"escrow@{HOST}"
        m["To"] = to
        m.set_content(msg)
        port = int(conf.get("SMTP_PORT", "587"))
        s = smtplib.SMTP(host, port, timeout=15)
        if conf.get("SMTP_TLS", "1") not in ("0", "no", "false"):
            s.starttls()
        if conf.get("SMTP_USER"):
            s.login(conf["SMTP_USER"], conf.get("SMTP_PASS", ""))
        s.send_message(m); s.quit()
        return True
    except Exception as e:
        sys.stderr.write(f"email error: {e}\n")
        return False


def notify(msg):
    """Send to ALL configured channels (telegram + email). Returns list of results."""
    res = []
    for fn in (tg, mail):
        r = fn(msg)
        if r is not None:
            res.append((fn.__name__, r))
    return res


def check_service():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=8) as r:
            d = json.loads(r.read().decode())
            return "ok" if d.get("unlocked") else "locked"
    except Exception:
        return "down"


def get_alerts():
    """Per-machine risk view (suspended / stale / in_progress). Works while locked."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/monitor/alerts", timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def load_state():
    try:
        return json.loads(open(STATE).read())
    except Exception:
        try:
            return {"service": open(STATE).read().strip()}  # back-compat: old bare-word state
        except Exception:
            return {}


def save_state(st):
    try:
        open(STATE, "w").write(json.dumps(st))
    except Exception:
        pass


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        res = notify(f"✅ BitLocker escrow [{HOST}]: тестове сповіщення (моніторинг працює)")
        if not res:
            print("NO channels configured (set TELEGRAM_* or SMTP_* in alert.conf)")
        else:
            for ch, ok in res:
                print(f"  {ch}: {'sent OK' if ok else 'FAILED'}")
        return

    prev = load_state()
    service = check_service()
    alerts = get_alerts() if service != "down" else {}
    have_alerts = bool(alerts)

    msgs = []
    if service != prev.get("service"):
        if service == "down":
            msgs.append(f"🔴 BitLocker escrow [{HOST}]: СЕРВІС НЕДОСТУПНИЙ")
        elif service == "locked":
            msgs.append(f"🟠 BitLocker escrow [{HOST}]: LOCKED — потрібен escrow-unlock (видача ключів НЕ працює)")
        elif service == "ok" and prev.get("service"):
            msgs.append(f"🟢 BitLocker escrow [{HOST}]: відновлено, працює (unlocked)")

    prev_susp = set(prev.get("suspended", []))
    cur_susp = set(alerts.get("suspended", [])) if have_alerts else prev_susp
    new_susp = cur_susp - prev_susp
    if new_susp:
        msgs.append(f"🔴 BitLocker [{HOST}]: захист ВИМКНЕНО на: " + ", ".join(sorted(new_susp)))

    prev_stale = set(prev.get("stale", []))
    cur_stale = set(alerts.get("stale", [])) if have_alerts else prev_stale
    new_stale = cur_stale - prev_stale
    if new_stale:
        msgs.append(f"🟠 BitLocker [{HOST}]: не виходять на звʼязок (>21 дн): " + ", ".join(sorted(new_stale)))

    prev_mm = set(prev.get("mismatch", []))
    cur_mm = set(alerts.get("mismatch", [])) if have_alerts else prev_mm
    new_mm = cur_mm - prev_mm
    if new_mm:
        msgs.append(f"🔴 BitLocker [{HOST}]: збережений ключ НЕ збігається з протектором на: "
                    + ", ".join(sorted(new_mm)) + " (потрібен re-escrow / Rotate)")

    for m in msgs:
        notify(m)

    save_state({"service": service, "suspended": sorted(cur_susp),
                "stale": sorted(cur_stale), "mismatch": sorted(cur_mm)})


if __name__ == "__main__":
    main()

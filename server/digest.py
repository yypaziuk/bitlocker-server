#!/usr/bin/env python3
"""Weekly coverage/health digest -> Telegram/email (reuses monitor.notify).

Sends a short fleet summary so you can track rollout WITHOUT logging into the
portal. Run by cron weekly; run manually to preview:  escrow-digest
Works while the service is locked (reads plaintext metadata only, no keys).
"""
import datetime, glob, os, platform
import db
import monitor

BK = "/opt/escrow/backups"


def _full(m):
    sts = [v.get("status") or "" for v in m["volumes"]]
    return bool(sts) and all("FullyEncrypted" in s for s in sts)


def _last_backup_line():
    files = glob.glob(os.path.join(BK, "escrow-*.tar.age"))
    if not files:
        return "НЕМАЄ!"
    newest = max(files, key=os.path.getmtime)
    ts = datetime.datetime.fromtimestamp(os.path.getmtime(newest))
    age_h = (datetime.datetime.now() - ts).total_seconds() / 3600
    tag = "свіжий" if age_h < 26 else f"{age_h / 24:.1f} дн тому"
    return f"{ts:%Y-%m-%d %H:%M} ({tag}), збережено {len(files)}"


def build():
    machines = db.report()
    total = len(machines)
    full = sum(1 for m in machines if _full(m))
    risk = db.at_risk()
    cov = db.coverage()
    host = platform.node() or "escrow"

    lines = [
        f"📊 BitLocker escrow [{host}] — щотижневий звіт",
        f"Станцій усього: {total} · зашифровано: {full}",
        (f"Шифрується: {len(risk.get('in_progress', []))} · захист OFF: {len(risk.get('suspended', []))} · "
         f"зниклі: {len(risk.get('stale', []))} · ключ застарів: {len(risk.get('mismatch', []))}"),
    ]
    if cov:
        enrolled = sum(1 for r in cov if r["enrolled"])
        lines.append(f"Покриття зі списку: {enrolled}/{len(cov)} зашифровано ({len(cov) - enrolled} ще ні)")
    lines.append(f"Останній бекап: {_last_backup_line()}")

    for label, key in (("Захист OFF", "suspended"), ("Зниклі", "stale"), ("Ключ застарів", "mismatch")):
        hosts = sorted(risk.get(key) or [])
        if hosts:
            shown = ", ".join(hosts[:20]) + (f" … (+{len(hosts) - 20})" if len(hosts) > 20 else "")
            lines.append(f"• {label}: {shown}")
    return "\n".join(lines)


if __name__ == "__main__":
    msg = build()
    res = monitor.notify(msg)
    if not res:
        print(msg)
        print("\n(no notify channel configured - set TELEGRAM_* or SMTP_* in alert.conf)")
    else:
        for ch, ok in res:
            print(f"  {ch}: {'sent OK' if ok else 'FAILED'}")

#!/usr/bin/env python3
"""One-shot update of the escrow server code, then re-unlock (variant A2).

Uploads server/*.py -> /opt/escrow/app, syntax-checks them, restarts the service
(which by design comes up LOCKED), then drops you into `escrow-unlock` so you type
the master passphrase ONCE. The passphrase is never stored or transmitted by this
tool - you type it into the interactive ssh session.

  python escrow-update.py             # push all server/*.py
  python escrow-update.py web.py      # push only the named file(s)
"""
import sys, os, pathlib, subprocess, paramiko

here = pathlib.Path(__file__).parent
env = {}
for line in (here / ".env").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1); env[k.strip()] = v.strip()

HOST = env["VPS_IP"]; PORT = int(env.get("VPS_PORT", 22))
USER = env["VPS_USER"]; PW = env["VPS_SUDO_PASS"]
KEY = env.get("SSH_KEY", "bl-escrow")
keypath = pathlib.Path(KEY) if os.path.isabs(KEY) else here / KEY

names = sys.argv[1:] or [p.name for p in sorted((here / "server").glob("*.py"))]
files = [here / "server" / n for n in names]
for f in files:
    if not f.exists():
        sys.exit(f"no such file: {f}")

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, port=PORT, username=USER, key_filename=str(keypath), timeout=20,
          allow_agent=False, look_for_keys=False)


def run(cmd):
    _, out, err = c.exec_command(cmd)
    return out.read().decode(errors="replace") + err.read().decode(errors="replace")


sftp = c.open_sftp()
for f in files:
    sftp.put(str(f), "/tmp/" + f.name)
    run(f"echo {PW!r} | sudo -S install -o escrow -g escrow -m 644 /tmp/{f.name} /opt/escrow/app/{f.name}")
print(">> uploaded:", ", ".join(f.name for f in files))

mods = " ".join(f"/opt/escrow/app/{f.name}" for f in files)
res = run(f"echo {PW!r} | sudo -S -u escrow /opt/escrow/venv/bin/python -m py_compile {mods}; echo rc=$?")
if "rc=0" not in res:
    print("COMPILE FAILED - NOT restarting:\n" + res); c.close(); sys.exit(1)
print(">> compile OK")

run(f"echo {PW!r} | sudo -S systemctl restart escrow")
print(">> restarted (service is now LOCKED by design)")
c.close()

print(">> opening escrow-unlock - enter the master passphrase:")
subprocess.run(["ssh", "-i", str(keypath), "-o", "IdentitiesOnly=yes", "-t",
                f"{USER}@{HOST}", "escrow-unlock"])
print(">> done. Verify: curl -sk https://%s/healthz  -> unlocked:true" % HOST)

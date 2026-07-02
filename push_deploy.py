#!/usr/bin/env python3
"""SFTP-upload deploy/* to /tmp/escrow_deploy/ on the VM."""
import sys, os, pathlib, paramiko
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
here = pathlib.Path(__file__).parent
env = {}
for line in (here / ".env").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1); env[k.strip()] = v.strip()
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
_kw = dict(hostname=env["VPS_IP"], port=int(env.get("VPS_PORT", 22)), username=env["VPS_USER"],
           timeout=25, allow_agent=False, look_for_keys=False)
_key = env.get("SSH_KEY")
if _key:
    _kp = _key if os.path.isabs(_key) else str(here / _key)
    if os.path.exists(_kp):
        _kw["key_filename"] = _kp
if "key_filename" not in _kw:
    _kw["password"] = env["VPS_SUDO_PASS"]
c.connect(**_kw)
sftp = c.open_sftp()
try: sftp.mkdir("/tmp/escrow_deploy")
except IOError: pass
for f in sorted((here / "deploy").glob("*")):
    if f.is_file():
        sftp.put(str(f), "/tmp/escrow_deploy/" + f.name); print("pushed:", f.name)
sftp.close(); c.close(); print("done")

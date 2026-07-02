#!/usr/bin/env python3
"""Run a command on the Bitlocker-Server Ubuntu VM over SSH (password auth via paramiko).
Usage:
    python ssh_run.py "uname -a"
    python ssh_run.py --sudo "apt update"
Reads creds from .env next to this file.
"""
import sys, os, pathlib, shlex, paramiko
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

env = {}
for line in (pathlib.Path(__file__).parent / ".env").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()

HOST = env["VPS_IP"]; PORT = int(env.get("VPS_PORT", 22))
USER = env["VPS_USER"]; PW = env["VPS_SUDO_PASS"]

argv = sys.argv[1:]
use_sudo = "--sudo" in argv
argv = [a for a in argv if a != "--sudo"]
cmd = " ".join(argv) if argv else sys.stdin.read()

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
_kw = dict(hostname=HOST, port=PORT, username=USER, timeout=25,
           allow_agent=False, look_for_keys=False)
_key = env.get("SSH_KEY")
if _key:
    _kp = _key if os.path.isabs(_key) else str(pathlib.Path(__file__).parent / _key)
    if os.path.exists(_kp):
        _kw["key_filename"] = _kp
if "key_filename" not in _kw:
    _kw["password"] = PW
c.connect(**_kw)

if use_sudo:
    full = "sudo -S -p '' bash -lc " + shlex.quote(cmd)
else:
    full = "bash -lc " + shlex.quote(cmd)

stdin, stdout, stderr = c.exec_command(full, get_pty=False)
if use_sudo:
    stdin.write(PW + "\n"); stdin.flush()

out = stdout.read().decode(errors="replace")
err = stderr.read().decode(errors="replace")
rc = stdout.channel.recv_exit_status()
sys.stdout.write(out)
if err.strip():
    sys.stdout.write("\n--- STDERR ---\n" + err)
sys.stdout.write(f"\n[exit {rc}]\n")
c.close()

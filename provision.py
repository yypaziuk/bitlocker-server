#!/usr/bin/env python3
"""One-command provisioning of a BitLocker escrow server (reproducible deploy).

New server:
  1. Bring up a clean Ubuntu VM.
  2. Edit .env: VPS_IP / VPS_USER / VPS_SUDO_PASS (and SSH_KEY name).
  3. python provision.py
  4. On the server: escrow-unlock   (set the master passphrase)

What it does: generate SSH key (if missing) -> connect (key or password) ->
upload server/ + deploy/ -> install pubkey -> run deploy/bootstrap.sh (full
setup incl. SSH key-only hardening) -> print secrets + cert fingerprint and
write SSH_KEY into .env.
"""
import sys, os, pathlib, subprocess, paramiko
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

here = pathlib.Path(__file__).parent
env = {}
envfile = here / ".env"
for line in envfile.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1); env[k.strip()] = v.strip()

HOST = env["VPS_IP"]; PORT = int(env.get("VPS_PORT", 22))
USER = env["VPS_USER"]; PW = env["VPS_SUDO_PASS"]
KEYNAME = env.get("SSH_KEY", "bl-escrow")
keypath = pathlib.Path(KEYNAME) if os.path.isabs(KEYNAME) else here / KEYNAME
pubpath = pathlib.Path(str(keypath) + ".pub")

# 1) ensure local key
if not keypath.exists():
    print(f">> generating SSH key {keypath}")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(keypath), "-N", "", "-C", f"{USER}@escrow"], check=True)

# 2) connect (key first, fallback password)
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
mode = None
try:
    c.connect(HOST, port=PORT, username=USER, key_filename=str(keypath), timeout=20,
              allow_agent=False, look_for_keys=False)
    mode = "key"
except Exception:
    c.connect(HOST, port=PORT, username=USER, password=PW, timeout=20,
              allow_agent=False, look_for_keys=False)
    mode = "password"
print(f">> connected via {mode}")

sftp = c.open_sftp()
def mkd(p):
    try: sftp.mkdir(p)
    except IOError: pass

# 3) upload sources
for d in ("/tmp/escrow_src", "/tmp/escrow_src/app", "/tmp/escrow_src/deploy"):
    mkd(d)
for f in sorted((here / "server").glob("*")):
    if f.is_file(): sftp.put(str(f), "/tmp/escrow_src/app/" + f.name)
for f in sorted((here / "deploy").glob("*")):
    if f.is_file(): sftp.put(str(f), "/tmp/escrow_src/deploy/" + f.name)
print(">> uploaded server/ + deploy/")

# 4) install pubkey (so bootstrap can safely enable key-only SSH)
pub = pubpath.read_text().strip()
cmd = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
       f"(grep -qxF {pub!r} ~/.ssh/authorized_keys 2>/dev/null || echo {pub!r} >> ~/.ssh/authorized_keys) && "
       "chmod 600 ~/.ssh/authorized_keys && echo pubkey-ok")
_, out, err = c.exec_command(cmd)
print(out.read().decode().strip() or err.read().decode().strip())

# 5) run bootstrap with sudo
print(">> running bootstrap.sh ...\n" + "-" * 60)
run = f"sudo -S -p '' bash /tmp/escrow_src/deploy/bootstrap.sh {HOST}"
stdin, stdout, stderr = c.exec_command(run, get_pty=False)
stdin.write(PW + "\n"); stdin.flush()
out = stdout.read().decode(errors="replace")
err = stderr.read().decode(errors="replace")
print(out)
if err.strip():
    print("--- stderr ---\n" + err)
print("-" * 60)

# 6) record SSH_KEY in .env
txt = envfile.read_text()
if "SSH_KEY=" not in txt:
    with open(envfile, "a", encoding="utf-8") as f:
        f.write(f"\nSSH_KEY={KEYNAME}\n")
    print(f">> wrote SSH_KEY={KEYNAME} to .env")

c.close()
print("\nNEXT: ssh to the server and run  escrow-unlock  to set the master passphrase.")
print("If NEW_* secrets/CERT_SHA256 were printed above, save them and update client\\Enroll-BitLocker.ps1.")

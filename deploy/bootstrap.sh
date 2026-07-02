#!/bin/bash
# Idempotent end-to-end provisioning of a BitLocker escrow server on a fresh
# Ubuntu VM. Run by provision.py via: sudo bash bootstrap.sh <SERVER_IP>
# Source files are expected under /tmp/escrow_src/{app,deploy}.
set -euo pipefail

SERVER_IP="${1:?usage: bootstrap.sh <SERVER_IP>}"
SRC=/tmp/escrow_src
ESC=/opt/escrow
ADMIN_USER="${SUDO_USER:-admin}"

echo ">> packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3-venv python3-pip sqlite3 nginx fail2ban unattended-upgrades ufw openssl age >/dev/null

timedatectl set-timezone Europe/Kyiv 2>/dev/null || true

echo ">> app user + files"
id escrow >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$ESC" escrow
mkdir -p "$ESC/app" "$ESC/data"
install -m 644 "$SRC"/app/*.py "$ESC/app/"
install -m 644 "$SRC"/app/requirements.txt "$ESC/app/"

echo ">> venv"
[ -d "$ESC/venv" ] || python3 -m venv "$ESC/venv"
"$ESC/venv/bin/pip" install -q --upgrade pip
"$ESC/venv/bin/pip" install -q -r "$ESC/app/requirements.txt"

echo ">> secrets (only if missing)"
if [ ! -f "$ESC/escrow.env" ]; then
    ENROLL=$(openssl rand -hex 24); ADMIN=$(openssl rand -hex 24)
    EHASH=$(printf %s "$ENROLL" | sha256sum | cut -d' ' -f1)
    AHASH=$(printf %s "$ADMIN"  | sha256sum | cut -d' ' -f1)
    printf 'ESCROW_DATA=%s/data\nESCROW_DB=%s/data/escrow.db\nESCROW_ENROLL_HASH=%s\nESCROW_ADMIN_HASH=%s\n' \
        "$ESC" "$ESC" "$EHASH" "$AHASH" > "$ESC/escrow.env"
    echo "NEW_ENROLL_SECRET=$ENROLL"
    echo "NEW_ADMIN_TOKEN=$ADMIN"
else
    echo "escrow.env exists - keeping current secrets"
fi
# web session secret (for SessionMiddleware) - add if missing
grep -q '^ESCROW_SESSION_SECRET=' "$ESC/escrow.env" || \
    echo "ESCROW_SESSION_SECRET=$(openssl rand -hex 32)" >> "$ESC/escrow.env"

# backup keypair (age): PUBLIC recipient stays on server; PRIVATE printed once -> store OFFLINE
mkdir -p "$ESC/backups"
if [ ! -f "$ESC/backup_recipient.txt" ]; then
    AGEKEY=$(age-keygen 2>/dev/null)
    echo "$AGEKEY" | grep 'public key:' | sed 's/.*public key: //' > "$ESC/backup_recipient.txt"
    echo "BACKUP_AGE_PRIVATE_KEY (STORE OFFLINE - required to decrypt backups):"
    echo "  $(echo "$AGEKEY" | grep '^AGE-SECRET-KEY-')"
fi

echo ">> admin helpers"
install -m 755 "$SRC"/deploy/escrow-unlock /usr/local/bin/escrow-unlock
install -m 755 "$SRC"/deploy/escrow-getkey /usr/local/bin/escrow-getkey
install -m 755 "$SRC"/deploy/escrow-report /usr/local/bin/escrow-report
install -m 755 "$SRC"/deploy/escrow-adduser /usr/local/bin/escrow-adduser
install -m 755 "$SRC"/deploy/escrow-backup /usr/local/bin/escrow-backup
install -m 755 "$SRC"/deploy/escrow-restore /usr/local/bin/escrow-restore
install -m 755 "$SRC"/deploy/escrow-import-assets /usr/local/bin/escrow-import-assets
install -m 755 "$SRC"/deploy/escrow-backupcodes /usr/local/bin/escrow-backupcodes
install -m 644 "$SRC"/deploy/escrow-backup.cron /etc/cron.d/escrow-backup
install -m 755 "$SRC"/deploy/escrow-setrole /usr/local/bin/escrow-setrole
install -m 755 "$SRC"/deploy/escrow-monitor /usr/local/bin/escrow-monitor
install -m 644 "$SRC"/deploy/escrow-monitor.cron /etc/cron.d/escrow-monitor
install -m 755 "$SRC"/deploy/escrow-digest /usr/local/bin/escrow-digest
install -m 644 "$SRC"/deploy/escrow-digest.cron /etc/cron.d/escrow-digest
install -m 755 "$SRC"/deploy/escrow-rekey /usr/local/bin/escrow-rekey
install -m 755 "$SRC"/deploy/escrow-relock /usr/local/bin/escrow-relock
[ -f "$ESC/alert.conf" ] || cp "$SRC"/deploy/alert.conf.template "$ESC/alert.conf"

chown -R escrow:escrow "$ESC"
chmod 600 "$ESC/escrow.env"
chmod 600 "$ESC/alert.conf" 2>/dev/null || true

echo ">> systemd"
install -m 644 "$SRC"/deploy/escrow.service /etc/systemd/system/escrow.service
systemctl daemon-reload
systemctl enable escrow >/dev/null 2>&1
systemctl restart escrow

echo ">> nginx + TLS"
mkdir -p /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/escrow.crt ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 1825 \
        -keyout /etc/nginx/ssl/escrow.key -out /etc/nginx/ssl/escrow.crt \
        -subj "/CN=$SERVER_IP" -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null
    chmod 600 /etc/nginx/ssl/escrow.key
fi
install -m 644 "$SRC"/deploy/escrow-ratelimit.conf /etc/nginx/conf.d/escrow-ratelimit.conf
sed "s/10\.25\.25\.10/$SERVER_IP/g" "$SRC"/deploy/nginx-escrow.conf > /etc/nginx/sites-available/escrow
ln -sf /etc/nginx/sites-available/escrow /etc/nginx/sites-enabled/escrow
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

echo ">> ufw"
ufw allow 22/tcp comment SSH >/dev/null
ufw allow 443/tcp comment "Escrow HTTPS" >/dev/null
ufw --force enable >/dev/null

echo ">> fail2ban"
[ -f /etc/fail2ban/jail.local ] || printf '[sshd]\nenabled = true\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n' > /etc/fail2ban/jail.local
install -m 644 "$SRC"/deploy/fail2ban-escrow-login.filter /etc/fail2ban/filter.d/escrow-login.conf
install -m 644 "$SRC"/deploy/fail2ban-escrow.jail /etc/fail2ban/jail.d/escrow-login.local
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

echo ">> auto security updates"
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades

echo ">> log rotation (~6 months)"
install -m 644 "$SRC"/deploy/logrotate-escrow /etc/logrotate.d/escrow
install -d /etc/systemd/journald.conf.d
install -m 644 "$SRC"/deploy/journald-escrow.conf /etc/systemd/journald.conf.d/escrow.conf
systemctl restart systemd-journald
# nginx access/error logs: keep ~6 months (default is 14)
sed -i 's/\brotate 14\b/rotate 180/' /etc/logrotate.d/nginx 2>/dev/null || true

echo ">> SSH hardening (only if a key is installed for $ADMIN_USER)"
if [ -s "/home/$ADMIN_USER/.ssh/authorized_keys" ]; then
    cat > /etc/ssh/sshd_config.d/00-escrow-hardening.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers $ADMIN_USER
EOF
    [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ] && \
        sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf || true
    sshd -t && systemctl reload ssh && echo "SSH hardened (key-only)"
else
    echo "SSH hardening SKIPPED: no /home/$ADMIN_USER/.ssh/authorized_keys (install key, then re-run)"
fi

echo "CERT_SHA256=$(openssl x509 -in /etc/nginx/ssl/escrow.crt -noout -fingerprint -sha256 | sed 's/.*=//')"
echo "BOOTSTRAP_DONE"

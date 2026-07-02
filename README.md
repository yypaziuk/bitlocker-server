# BitLocker Key Escrow Server

Self-hosted BitLocker recovery key management for Windows workstations **without Active Directory**.

---

[English](#english) · [Українська](#ukrainian)

---

## English

### Why

Microsoft's BitLocker key escrow requires Active Directory (MBAM) or Azure AD. If you have neither,
this project gives you a simple, self-hosted alternative with a web portal and 2FA.

### Architecture

```
[Windows workstation]  →  HTTPS enroll  →  [Ubuntu server]
                                              FastAPI + SQLite + age encryption
                                              nginx TLS + fail2ban + ufw
                                              Web portal (2FA)
```

- **Server:** Ubuntu VM — FastAPI escrow API, SQLite (WAL), keys encrypted at-rest via [age](https://github.com/FiloSottile/age)
- **Encryption:** App-level (A2): master-passphrase entered by admin on service start; stolen VM image = encrypted DB without the key
- **Client:** Portable PowerShell script + compiled EXE — runs on each workstation during setup
- **Transport:** HTTPS + shared enroll secret + cert fingerprint pinning (no CA required)

### Features

- `POST /enroll` — workstation sends recovery key; server stores it encrypted
- `GET /key/<id>` — admin retrieves key on lockout (admin-token auth, LAN only)
- `POST /audit` — workstations report BitLocker status opportunistically
- Web portal with TOTP 2FA for admins
- fail2ban + rate-limiting on all endpoints
- Encrypted backup + offline master-key copy workflow
- CLI helpers for key rotation, re-lock, user management

### Structure

```
server/         FastAPI app (app.py, web.py portal, crypto.py, db.py, auth.py, ...)
client/         Enroll-BitLocker.ps1/.exe, Rotate-BitLocker.ps1/.exe, audit.ps1
deploy/         bootstrap.sh, nginx config, systemd service, fail2ban rules, cron jobs
provision.py    First-time server provisioning from local machine
ssh_run.py      Run admin commands on server over SSH
```

### Quick Start

#### 1. Provision the server

```bash
# On your local machine — edit .env first: VPS_IP, VPS_USER, VPS_SUDO_PASS, SSH_KEY
pip install paramiko
python provision.py
# Output: ENROLL_SECRET, ADMIN_TOKEN, CERT_SHA256 — save all three
```

#### 2. Unlock the service (after every reboot)

The service starts in **LOCKED** state — keys are inaccessible until unlocked:

```bash
ssh <server_user>@YOUR_SERVER_IP
escrow-unlock      # enter master-passphrase
```

Verify: `curl -sk https://YOUR_SERVER_IP/healthz` → `"unlocked": true`

> **The master-passphrase is never stored anywhere. Losing it means losing all keys. Keep an offline copy in a safe.**

#### 3. Create the first admin account (once)

```bash
ssh <server_user>@YOUR_SERVER_IP
sudo escrow-adduser
# enter login + password (min 10 chars) → scan the QR in Google Authenticator / Aegis
```

#### 4. Configure the client

```powershell
# Fill in values from provision.py output
Copy-Item client\escrow.config.example.ps1 client\escrow.config.ps1
# Edit: $Server, $EnrollSecret, $CertSha256

# Propagate config into enroll/rotate scripts
.\client\Apply-Config.ps1

# Build EXEs (optional — requires PS2EXE)
.\client\enroll\Build-EnrollExe.ps1
.\client\rotate\Build-RotateExe.ps1
```

#### 5. Enroll a workstation

Requirements: Windows 10/11 **Pro/LTSC**, TPM enabled, admin rights, reachable server.

```
Copy client\enroll\Enroll-BitLocker.bat + Enroll-BitLocker.ps1 to the workstation
Double-click Enroll-BitLocker.bat → approve UAC
```

The script checks TPM → enables BitLocker (TPM + recovery password) → sends the key to the server and waits for confirmation → saves a local copy of the key to the Desktop as a failsafe.

The workstation appears in the dashboard after enroll.

### Web Portal

Open **https://YOUR_SERVER_IP** in a browser (self-signed cert — add an exception, this is expected).

- **Dashboard** — all workstations, encryption status, search by hostname/serial. Tiles at the top are clickable filters; "key mismatch" = stored key no longer matches the active protector.
- Click a workstation → **Show recovery key** — requires a reason/ticket (logged to audit).
- **Audit** — log of logins, key views, enrolls, status changes.
- **Inventory** — hardware/OS info per workstation (CPU, RAM, disks, IP/MAC, OS build, TPM, Secure Boot), search + CSV export.
- **Management** (admin role only) — session timeout, admin accounts (add/reset 2FA/backup codes/delete), panic-lock button, service status.

### Recover a Key (user locked out)

**Via web portal:** log in → find workstation → Show recovery key → read out the 48-digit code.

**Via CLI:**

```bash
ssh <server_user>@YOUR_SERVER_IP
escrow-getkey <hostname or serial>   # prompts for ADMIN_TOKEN
escrow-report                        # list all workstations and status
```

### Maintenance

| Task | Command |
|------|---------|
| Unlock after reboot | `escrow-unlock` |
| Create admin | `sudo escrow-adduser` |
| Regenerate 2FA backup codes | `sudo escrow-backupcodes <user>` |
| Get recovery key | `escrow-getkey <host\|serial\|key-id>` |
| List workstations | `escrow-report` |
| Import asset list (coverage report) | `sudo escrow-import-assets <csv>` — columns: hostname,serial,note |
| Manual backup | `escrow-backup` — auto-backup runs daily at 02:30 via cron |
| Restore backup | `escrow-restore <file.age> <privkey>` — needs the offline age private key |
| Weekly coverage digest | `escrow-digest` — auto-runs Mon 08:00; channels in alert.conf |
| Panic-lock | `escrow-relock` — flushes master-key from RAM; unlock: `escrow-unlock` locally only |
| Change master-passphrase | `sudo escrow-rekey` → restart service → `escrow-unlock` with new passphrase |
| Deploy another server | `python provision.py` on a new VM with its own `.env` — idempotent |
| Update server code | `python escrow-update.py` — uploads code, restarts service, prompts for unlock |
| Check service | `sudo systemctl status escrow` |
| Check health | `curl -sk https://YOUR_SERVER_IP/healthz` |

Backups are stored encrypted (age) in `/opt/escrow/backups/`, 14-day rotation.
Recommend copying `*.age` files offsite as well.

Alerts (key view, mismatch, digest, backup failure) go to channels in `/opt/escrow/alert.conf` (Telegram/email).
While the config is empty, alerts are silent. Test: `sudo escrow-monitor test`.

### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Dashboard shows LOCKED, keys unavailable | Service not unlocked → `escrow-unlock` |
| Enroll fails: "server is LOCKED" | Same → `escrow-unlock` on server |
| Enroll fails: "No TPM / not ready" | Enable/initialize TPM in BIOS/UEFI |
| Enroll fails: "cannot reach server / cert mismatch" | No network to server, or certificate changed (update `$CertSha256` in client script) |
| Cannot log in to portal | Check credentials; verify 2FA code is current (phone time in sync) |
| Master-passphrase forgotten | **Not recoverable** — all keys inaccessible. Mandatory offline copy in safe. |
| "Key mismatch" on dashboard | Workstation reported a protector different from the stored one → run `Rotate-BitLocker.bat` on that machine |

### Security Notes

- TLS cert fingerprint is pinned in the client — no CA trust required
- `ENROLL_SECRET` and admin token are generated randomly on first bootstrap
- Master-passphrase lives only in RAM — service starts locked after every reboot
- All key access is logged; fail2ban blocks brute-force on API and login
- `.env` and SSH keys are gitignored — never committed

### Requirements

**Server:** Ubuntu 22.04+, Python 3.10+, nginx, age, fail2ban, ufw

**Client:** Windows 10/11 Pro or LTSC, TPM 2.0, admin rights, PowerShell 5.1+

### Contributing

Issues and PRs welcome. This project was built for a specific environment but designed to be generic — if something is hardcoded that shouldn't be, please open an issue.

### License

MIT

---

## Українська

### Про проект

Власний сервіс централізованого зберігання й видачі ключів відновлення BitLocker для
робочих станцій без домену (~100 АРМ, Win10/11 Pro/LTSC).

Microsoft вимагає AD (MBAM) або Azure AD для escrow ключів BitLocker. Цей проект — проста
самохостована альтернатива з веб-порталом і 2FA.

### Швидкий старт

#### 1. Розгорнути сервер

```bash
# На своєму ПК — спочатку заповни .env: VPS_IP, VPS_USER, VPS_SUDO_PASS, SSH_KEY
pip install paramiko
python provision.py
# Виведе: ENROLL_SECRET, ADMIN_TOKEN, CERT_SHA256 — збережи всі три
```

#### 2. Розблокувати сервіс (після кожного ребуту)

Сервіс стартує у стані **LOCKED** — ключі недоступні до розблокування:

```bash
ssh <server_user>@YOUR_SERVER_IP
escrow-unlock      # ввести майстер-пароль
```

Перевірити: `curl -sk https://YOUR_SERVER_IP/healthz` → `"unlocked": true`

> ⚠️ **Майстер-пароль ніде не зберігається. Втрата = втрата ВСІХ ключів. Тримай офлайн-копію в сейфі.**

#### 3. Створити першого адміна (один раз)

```bash
ssh <server_user>@YOUR_SERVER_IP
sudo escrow-adduser
# логін + пароль (мін 10 символів) → покаже QR → сканувати в Google Authenticator / Aegis
```

#### 4. Налаштувати клієнт

```powershell
# Заповнити значеннями з виводу provision.py
Copy-Item client\escrow.config.example.ps1 client\escrow.config.ps1
# Редагувати: $Server, $EnrollSecret, $CertSha256

# Прокинути конфіг у скрипти enroll/rotate
.\client\Apply-Config.ps1

# Зібрати EXE (опціонально — потребує PS2EXE)
.\client\enroll\Build-EnrollExe.ps1
.\client\rotate\Build-RotateExe.ps1
```

#### 5. Підключити робочу станцію (enroll)

Вимоги: Windows 10/11 **Pro/LTSC**, TPM увімкнено, права адміна, мережа до сервера.

```
Скопіювати client\enroll\Enroll-BitLocker.bat + Enroll-BitLocker.ps1 на АРМ
Подвійний клік на Enroll-BitLocker.bat → «Так» в UAC
```

Скрипт перевірить TPM → увімкне BitLocker (TPM + ключ відновлення) → надішле ключ на сервер і дочекається підтвердження → залишить копію ключа на Робочому столі.

Після цього станція зʼявиться в дашборді.

### Веб-портал

Відкрити **https://YOUR_SERVER_IP** у браузері (сертифікат самопідписаний → додати виняток, це нормально).

- **Dashboard** — усі станції, статус шифрування, пошук за hostname/серійником. Плитки зверху — клікабельні фільтри; «ключ застарів» = збережений ключ не збігається з активним протектором.
- Клік на станцію → **«Показати ключ відновлення»** — вимагає вписати причину/тікет (все пишеться в аудит).
- **Audit** — журнал: входи, перегляди ключів, enroll, зміни статусу.
- **Інвентар** — залізо/ОС кожного АРМ (CPU, RAM, диски, IP/MAC, ОС-білд, TPM, Secure Boot), пошук + експорт CSV.
- **Керування** (роль `admin`) — час сесії, адміністратори (додати/скинути 2FA/backup-коди/видалити), кнопка panic-lock, стан сервісу.

### Відновити ключ (користувач залочився)

**Веб-портал:** увійти → знайти станцію → «Показати ключ» → продиктувати 48-значний код.

**CLI:**

```bash
ssh <server_user>@YOUR_SERVER_IP
escrow-getkey <hostname або серійник>   # запитає ADMIN_TOKEN
escrow-report                           # список усіх станцій і статусів
```

### Обслуговування

| Завдання | Команда |
|----------|---------|
| Розблокувати після ребуту | `escrow-unlock` |
| Створити адміна | `sudo escrow-adduser` |
| Перегенерувати 2FA backup-коди | `sudo escrow-backupcodes <user>` |
| Видати ключ відновлення | `escrow-getkey <host\|serial\|key-id>` |
| Список станцій | `escrow-report` |
| Імпорт списку АРМ (звіт покриття) | `sudo escrow-import-assets <csv>` — колонки: hostname,serial,note |
| Ручний бекап | `escrow-backup` — авто-бекап щодня 02:30 через cron |
| Відновити бекап | `escrow-restore <file.age> <privkey>` — потрібен офлайн age-приватний ключ |
| Щотижневий дайджест покриття | `escrow-digest` — авто пн 08:00; канали в alert.conf |
| Panic-lock | `escrow-relock` — вивантажує майстер з RAM; назад: `escrow-unlock` лише локально |
| Змінити майстер-пароль | `sudo escrow-rekey` → рестарт → `escrow-unlock` з новим паролем |
| Підняти ще один сервер | `python provision.py` на новій VM зі своїм `.env` — ідемпотентно |
| Оновити код сервісу | `python escrow-update.py` — заливає код, перезапускає, запитає unlock |
| Перевірити сервіс | `sudo systemctl status escrow` |
| Перевірити стан | `curl -sk https://YOUR_SERVER_IP/healthz` |

Бекапи зберігаються у `/opt/escrow/backups/` (age-шифрування), ротація 14 днів.
Рекомендується копіювати `*.age` ще й на інший хост/носій.

Сповіщення (показ ключа, mismatch, дайджест, збій бекапу) — в канали `/opt/escrow/alert.conf` (Telegram/email).
Поки конфіг порожній — алерти мовчазні. Тест: `sudo escrow-monitor test`.

### Усунення проблем

| Симптом | Причина / рішення |
|---------|-------------------|
| Дашборд пише LOCKED, ключі не показуються | Сервіс не розблоковано → `escrow-unlock` |
| enroll: «server is LOCKED» | Те саме → `escrow-unlock` на сервері |
| enroll: «No TPM / not ready» | Увімкнути/ініціалізувати TPM у BIOS/UEFI |
| enroll: «cannot reach server / cert mismatch» | Немає мережі до сервера, або змінився сертифікат (оновити `$CertSha256` у скрипті) |
| Не пускає у портал | Перевір логін/пароль; код 2FA має бути свіжим (час на телефоні синхронний) |
| Забув майстер-пароль | **Не відновлюється** — ключі недоступні. Тому офлайн-копія обовʼязкова. |
| «Ключ застарів» на дашборді | АРМ повідомив про інший протектор → запусти `Rotate-BitLocker.bat` на тій машині |

### Вимоги

**Сервер:** Ubuntu 22.04+, Python 3.10+, nginx, age, fail2ban, ufw

**Клієнт:** Windows 10/11 Pro або LTSC, TPM 2.0, права адміна, PowerShell 5.1+

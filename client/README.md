# BitLocker Escrow — клієнтські скрипти для АРМ

Скрипти, що запускаються на робочих станціях (Win10/11 **Pro/LTSC/Enterprise**, TPM увімкнено,
у мережі з escrow-сервером **https://YOUR_SERVER_IP**). Розкладено по теках, щоб enroll і rotate
не змішувались:

```
client\
├── enroll\   ← первинне ввімкнення BitLocker + escrow ключа (запускається ОДИН раз на АРМ)
│   ├── Enroll-BitLocker.ps1     ← основна логіка
│   ├── Enroll-BitLocker.bat     ← лаунчер (.bat, бо .ps1 напряму блокує політика)
│   ├── Enroll-BitLocker.exe     ← підписаний EXE (для машин з application control)
│   ├── Build-EnrollExe.ps1      ← перезбірка підписаного EXE з .ps1
│   └── audit.ps1                ← довідкова копія фонового phone-home скрипта (див. нижче)
└── rotate\   ← перевипуск (ротація) recovery-ключа ПІСЛЯ того, як ключ показували/використали
    ├── Rotate-BitLocker.ps1
    └── Rotate-BitLocker.bat
```

## Конфіг — єдине джерело (`escrow.config.ps1`)
Адреса сервера, enroll-секрет і відбиток серта живуть **в одному файлі** `client\escrow.config.ps1`.
При зміні будь-чого:
1. відредагуй `escrow.config.ps1`;
2. запусти `.\Apply-Config.ps1` — розставить значення в `enroll\Enroll-BitLocker.ps1`,
   `rotate\Rotate-BitLocker.ps1` і `enroll\audit.ps1` (між маркерами `>>>ESCROW-CONFIG<<<`,
   плюс пін у TLS-колбеку audit.ps1);
3. перезбери EXE: `enroll\Build-EnrollExe.ps1` + `rotate\Build-RotateExe.ps1` (з `-Thumbprint`).

> Не редагуй значення в самих `.ps1` вручну — їх перезапише `Apply-Config.ps1`.

## Тести
`server\test_smoke.py` — смоук-тести ядра (crypto round-trip, enroll→видача ключа, audit-лог лише на
зміну, інвентар). Запуск на сервері: `/opt/escrow/venv/bin/python /opt/escrow/app/test_smoke.py`
(тимчасова БД, прод не чіпає; exit 0 = усе ок).

---

## enroll\ — підключення нової станції

Запускати **один раз** на кожному АРМ при налаштуванні (поки бачить сервер).

### На машині БЕЗ application control
Скопіювати `Enroll-BitLocker.bat` + `Enroll-BitLocker.ps1` в одну теку → подвійний клік на
**`.bat`** → «Так» в UAC.

### На машині З application control (AppLocker/WDAC)
Політика часто блокує прямий запуск `powershell.exe -File ...`, тож використовуй **підписаний EXE**:
скопіювати `Enroll-BitLocker.exe` (+ за бажання `.bat`) → запустити `Enroll-BitLocker.exe`.

### Що робить enroll
1. Pre-flight: адмін-права, редакція з BitLocker, TPM present+ready, зв'язок із сервером + звірка
   відбитка серта.
2. Вмикає BitLocker: системний диск — TPM + recovery password; диски даних — recovery + auto-unlock.
   (Якщо диск уже зашифрований — повторно НЕ шифрує, лише переконується, що recovery-протектор є.)
3. Зчитує recovery key(и) і **відсилає на `POST /enroll`**, чекає підтвердження `stored`.
4. Лишає **failsafe-копію** ключа на Робочому столі.
5. Ставить заплановану задачу **`BLEscrow-Audit`** (фонове оновлення статусу) + кладе
   `C:\ProgramData\BLEscrow\audit.ps1`.

### Фоновий аудит (`BLEscrow-Audit` / `audit.ps1`)
- Генерується enroll-скриптом у `C:\ProgramData\BLEscrow\audit.ps1` (файл `enroll\audit.ps1` — його
  довідкова копія; також придатна для ручного «ремонту» вже зареєстрованих машин).
- **Cert-pin через scriptblock-колбек** (SHA-256 серта == пін): **без `Add-Type`** (під app-control
  компіляція `csc.exe` з-під SYSTEM падає!), без cert-стора, без сирого `SslStream`.
- Пише лог кожної спроби в **`C:\ProgramData\BLEscrow\audit.log`** (час, LanguageMode, статус/помилка).
- Тригери: at-startup + at-logon + щодня 12:00, з `StartWhenAvailable` + `RunOnlyIfNetworkAvailable`.
- **Збирає інвентар** (CPU, RAM, диски, IP/MAC, ОС-білд, останній користувач, домен, TPM, Secure Boot — через CIM/WMI) і шле разом зі статусом → видно в порталі на вкладці **Інвентар**. Збирається і при enroll, і на кожному аудиті.
- Ручна перевірка: `Start-ScheduledTask -TaskName BLEscrow-Audit`, далі
  `Get-Content C:\ProgramData\BLEscrow\audit.log -Tail 5` (очікувано `... status=ok`).

### Перезбірка EXE після зміни `.ps1`
На ПК-розробці (без app-control), у теці `enroll\`:
```powershell
.\Build-EnrollExe.ps1 -Pfx "C:\path	o\CodeSign.pfx" -Password "ПАРОЛЬ_PFX"
```
Має вивести `Signature: Valid`. Підпис code-signing сертом обов'язковий для машин з application control.

---

## rotate\ — ротація ключа

Запускати на АРМ **лише після того, як recovery key показували/використовували** (щоб старий
показаний ключ став недійсним).
- БЕЗ application control: подвійний клік `Rotate-BitLocker.bat` (разом з `.ps1`).
- З application control: підписаний **`Rotate-BitLocker.exe`**.

Логіка: для кожного зашифрованого тому — додає **новий** recovery-протектор → re-escrow нового ключа
(чекає підтвердження) → лише потім видаляє **старий** протектор. Escrow завжди збігається з живим ключем.

> `Rotate-BitLocker.ps1` пінить серт через `Add-Type` — для **інтерактивного** запуску (вручну/через EXE)
> це працює (як enroll). Add-Type падає лише у фоновій задачі під SYSTEM, а rotate так не запускається.
> Перезбірка EXE: `rotate\Build-RotateExe.ps1 -Thumbprint F2AAFBF70F7585FC6762C67D782F138B034FE500`.

---

## Відновлення ключа (коли користувач залочився)
Не на АРМ, а в адмін-порталі/CLI сервера — див. кореневу `..\ІНСТРУКЦІЯ.md`.

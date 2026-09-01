# IronTrace

<p align="center">
  <strong>🌐 Мови / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <b>Українська</b> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pl.md">Polski</a> ·
  <a href="README.pt.md">Português</a> ·
  <a href="README.zh-CN.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

**Сканер апаратної та forensic-цілісності Windows для адмінів ігрових серверів.**

IronTrace збирає докази про безпеку платформи, пристрої PCI/PCIe/USB, драйвери та опційні forensic-сигнали — і формує зрозумілу оцінку цілісності. Інструмент допомагає **перевірити** машину. Він не оголошує гравця читером через одну дивну знахідку. Автобанів немає.

| Канал | Версія |
|-------|--------|
| Додаток | **0.7.0** (Фаза 6 — Forensic Integrity Scan) |
| Схема звіту | `1.6` |
| API | `v1` |
| Протокол драйвера | `2` |
| Схема довідкової БД | `2` |

---

## Зміст

- [Швидкий старт](#швидкий-старт)
- [Режими сканування](#режими-сканування)
- [Десктопний додаток (WPF)](#десктопний-додаток-wpf)
- [CLI](#cli)
- [Опційне сканування памʼяті (hollows_hunter)](#опційне-сканування-памʼяті-hollows_hunter)
- [Завантаження на сервер](#завантаження-на-сервер)
- [Що робить IronTrace](#що-робить-irontrace)
- [Чим IronTrace не є](#чим-irontrace-не-є)
- [Архітектура](#архітектура)
- [Розробка](#розробка)
- [Сторонні компоненти](#сторонні-компоненти)
- [Документація](#документація)
- [Ліцензія та контакти](#ліцензія-та-контакти)

---

## Швидкий старт

**Кінцевий користувач:**

1. Запустіть IronTrace на Windows 10/11 x64.
2. Оберіть режим на головному екрані:
   - **Admin Scan** — апаратний скан + опційна forensic-глибина для адмінів.
   - **Self-Audit** — self-audit для гравця; HTML-звіт автоматично на Робочий стіл.
3. Перегляньте вердикт і знахідки на екрані Result.
4. Експортуйте JSON, завантажте на сервер IronTrace або почніть новий скан.

**Розробник:**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

Скани працюють **офлайн**, якщо є довідкові БД у `data/reference/`. Підвищення прав необовʼязкове; Administrator потрібен лише для глибшого Code Integrity / DeviceGuard.

---

## Режими сканування

| Режим | Кнопка WPF | CLI `--profile` | Forensic-шари | Типове використання |
|-------|------------|-----------------|---------------|---------------------|
| Лише hardware | Admin Scan (без чекбоксів) | `hardware-only` | Немає | Базова PCI/USB/драйвери |
| Повний forensic | Admin Scan + чекбокси | `full-forensic` | Усі (+ memory з `--memory`) | Глибока перевірка адміном |
| Self-audit | **Self-Audit** | `self-audit` | Execution, BYOVD, HWID, overlay | Прозорий звіт для гравця |
| Console rig | — | `console-rig` | Self-audit + capture/input | Другий ПК у stream-setup |

**Forensic-шари (Фаза 6):**

| Шар | Що перевіряє | Згода |
|-----|--------------|-------|
| 0 | Prefetch/BAM/ShimCache, BYOVD deep, HWID, overlays | У Self-Audit / Full Forensic |
| 1 | Процеси/служби, persistence | Чекбокс `IncludeProcessInventory` |
| 2 | Памʼять через **hollows_hunter** | Чекбокс або CLI `--memory` |

Без hollows_hunter шар 2 пропускається — решта працює. UI показує попередження, якщо інструмент відсутній.

---

## Десктопний додаток (WPF)

```powershell
dotnet run --project src/IronTrace.App -c Release
```

| Елемент | Призначення |
|---------|-------------|
| **Admin Scan** | Hardware; стає Full Forensic з чекбоксами process/memory |
| **Self-Audit** | Forensic self-audit; HTML на `%USERPROFILE%\Desktop\` |
| Include process/service inventory | Шар 1 — процеси та служби (opt-in) |
| Include memory scan via PE-sieve | Шар 2 — лише якщо встановлено [hollows_hunter](#опційне-сканування-памʼяті-hollows_hunter) |
| Include PnP device history | Opt-in; історія PCI vs watchlist |

**Result:** вердикт, forensic banner, експорт JSON, upload на сервер, перегляд пристроїв і findings.

---

## CLI

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| Прапорець | Опис |
|-----------|------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | Шлях до JSON-звіту |
| `--html` | Опційний HTML (Self-Audit генерує `.html` поруч) |
| `--memory` | Шар 2 memory scan (full-forensic) |

---

## Опційне сканування памʼяті (hollows_hunter)

IronTrace **не постачає** інструменти memory scan. За згодою запускає [hollows_hunter](https://github.com/hasherezade/hollows_hunter) як зовнішній subprocess. Без дампів памʼяті в звітах.

| Компонент | Ліцензія | У комплекті? |
|-----------|----------|--------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **Ні** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) | BSD-2-Clause | **Ні** |

**Встановлення:**

1. Завантажте 64-bit збірки з upstream.
2. Покладіть у:

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

3. Перезапустіть IronTrace — жовтий банер зникне, чекбокс memory scan увімкнеться.

Деталі: [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) · [pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md)

---

## Завантаження на сервер

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

PostgreSQL: `docker compose up -d` перед запуском сервера.

Потік: challenge → HMAC-підпис → збереження → triage в `/admin`. Деталі: [docs/api/README.md](../api/README.md).

---

## Що робить IronTrace

- Безпека платформи: Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection
- Інвентаризація материнської плати, PCI/PCIe, USB
- Офлайн `pci.ids` / `usb.ids`, LOLDrivers, Code Integrity logs
- Опційний kernel PCI evidence через `IronTrace.Driver`
- Консервативний risk engine → JSON (schema 1.6)
- Фаза 6 forensic: execution artifacts, BYOVD, HWID, overlay/AI-vision
- Опційний upload на ваш сервер для людського review

---

## Чим IronTrace не є

- **Не криптодоказ.** User-mode ID можна підробити — див. [threat model](../security/THREAT_MODEL.md).
- **Не шпигун.** Без історії браузера, паролів, скріншотів, дампів памʼяті.
- **Не DMA toolkit.** Драйвер — лише обмежені PCI IOCTL ([driver boundary](../architecture/DRIVER_BOUNDARY.md)).
- **Не постачальник читів.** PCILeech та exploit kits — лише research у `docs/research/`.

---

## Архітектура

```text
WPF / CLI → collectors → Forensic (Phase 6) → RiskEngine → JSON 1.6 → optional Upload → /admin
```

| Шлях | Роль |
|------|------|
| `src/IronTrace.App` | WPF-клієнт |
| `src/IronTrace.Cli` | Headless scanner |
| `src/IronTrace.Server` | API + admin UI |
| `src/IronTrace.Forensics` | Phase 6 collectors |
| `artifacts/tools/` | Опційний hollows_hunter (не в git) |

---

## Розробка

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

**Publish:**

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Повна політика: [PRIVACY.md](../security/PRIVACY.md).

---

## Сторонні компоненти

Офлайн-дані (pci.ids, usb.ids, LOLDrivers): [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

**hollows_hunter** / **pe-sieve** — BSD-2-Clause, **не входять у поставку**.

---

## Roadmap

| Фаза | Статус | Примітки |
|------|--------|----------|
| 1 Foundation | Done | WPF, PCI, risk engine |
| 2 Universal integrity | Done | USB, LOLDrivers, CI |
| 3 Server MVP | Done | Upload, `/admin` |
| 4 Kernel evidence | Done | KMDF driver |
| 5 Active verification | Done | DOE/PCR, DMA |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit, hollows_hunter |

---

## Документація

| Тема | Посилання |
|------|-----------|
| Архітектура | [ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
| API | [api/README.md](../api/README.md) |
| Threat model | [THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| Privacy | [PRIVACY.md](../security/PRIVACY.md) |
| hollows_hunter | [pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) |

---

## Ліцензія та контакти

**IronTrace** — proprietary. [LICENSE](../../LICENSE)

**Сторонні компоненти** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)

**Discord:** twinkipro

Безпека: [SECURITY.md](../../SECURITY.md)

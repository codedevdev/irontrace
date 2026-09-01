# IronTrace

<p align="center">
  <strong>🌐 Languages</strong><br/>
  <a href="README.md"><b>English</b></a> ·
  <a href="docs/i18n/README.uk.md">Українська</a> ·
  <a href="docs/i18n/README.de.md">Deutsch</a> ·
  <a href="docs/i18n/README.fr.md">Français</a> ·
  <a href="docs/i18n/README.es.md">Español</a> ·
  <a href="docs/i18n/README.pl.md">Polski</a> ·
  <a href="docs/i18n/README.pt.md">Português</a> ·
  <a href="docs/i18n/README.zh-CN.md">中文</a> ·
  <a href="docs/i18n/README.ja.md">日本語</a>
</p>

**Windows hardware & forensic integrity scanner for game-server admins.**

IronTrace collects evidence about platform security, PCI/PCIe/USB devices, drivers, and optional forensic signals — then produces an explainable integrity assessment. It helps you **review** a machine. It does not declare someone a cheater from one odd finding. There is no auto-ban path.

| Channel | Version |
|---------|---------|
| Application | **0.7.0** (Phase 6 — Forensic Integrity Scan) |
| Report schema | `1.6` |
| API | `v1` |
| Driver protocol | `2` |
| Reference DB schema | `2` |

---

## Table of contents

- [Quick start](#quick-start)
- [Scan modes](#scan-modes)
- [Desktop app (WPF)](#desktop-app-wpf)
- [CLI](#cli)
- [Optional memory scan (hollows_hunter)](#optional-memory-scan-hollows_hunter)
- [Server upload & admin review](#server-upload--admin-review)
- [What it does](#what-it-does)
- [What it is not](#what-it-is-not)
- [Architecture](#architecture)
- [Development](#development)
- [Third-party notices](#third-party-notices)
- [Documentation](#documentation)
- [License & contact](#license--contact)

---

## Quick start

**End user (published build or `dotnet run`):**

1. Launch IronTrace on Windows 10/11 x64.
2. Choose a scan mode on the home screen:
   - **Admin Scan** — hardware + optional forensic depth for server admins.
   - **Self-Audit** — player-facing scan; auto-saves HTML report to Desktop.
3. Review the verdict and findings on the Result screen.
4. Export JSON, upload to your IronTrace server, or start a new scan.

**Developer:**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

Scans work **offline** when bundled reference DBs under `data/reference/` are present. Elevation is optional (`asInvoker`); run as Administrator only if you want deeper Code Integrity / DeviceGuard detail.

---

## Scan modes

IronTrace separates **hardware-only** scans from **forensic** profiles. Forensic layers are privacy-gated; memory scan requires explicit opt-in and external tools (see below).

| Mode | WPF button | CLI `--profile` | Forensic layers | Typical use |
|------|------------|-----------------|-----------------|-------------|
| Hardware only | Admin Scan (no forensic checkboxes) | `hardware-only` | None | Baseline PCI/USB/driver integrity |
| Full forensic | Admin Scan + process / memory checkboxes | `full-forensic` | All (memory if tool installed + `--memory`) | Deep admin investigation |
| Self-audit | **Self-Audit** | `self-audit` | Execution, BYOVD, HWID, overlay, process inventory | Player transparency report |
| Console rig | — | `console-rig` | Self-audit + capture-card / input focus | Secondary PC on a stream setup |

**Forensic layers (Phase 6):**

| Layer | What it checks | Consent |
|-------|----------------|---------|
| 0 | Prefetch/BAM/ShimCache, BYOVD deep, HWID cross-source, overlays | On for Self-Audit / Full Forensic |
| 1 | Process/service inventory, persistence (tasks, Run keys) | `IncludeProcessInventory` checkbox or profile default |
| 2 | Memory integrity via **hollows_hunter** subprocess | `IncludeMemoryScan` checkbox or CLI `--memory` |

Without hollows_hunter installed, Layer 2 is skipped — everything else still runs. The UI shows a notice when the tool is missing.

---

## Desktop app (WPF)

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### Home screen

| Control | Purpose |
|---------|---------|
| **Admin Scan** | Hardware scan; becomes Full Forensic if process or memory checkboxes are checked |
| **Self-Audit** | Forensic self-audit profile; saves HTML to `%USERPROFILE%\Desktop\` |
| Include process/service inventory | Layer 1 — lists running processes and services (privacy opt-in) |
| Include memory scan via PE-sieve | Layer 2 — only enabled when [hollows_hunter](#optional-memory-scan-hollows_hunter) is installed |
| Include PnP device history | Privacy opt-in; correlates historical PCI entries with watchlist |

### Result screen

- **Verdict** — conservative risk engine output (`Normal` … `HighRisk`, never auto-ban).
- **Forensic banner** — high-level forensic summary when applicable.
- **Export report** — JSON with privacy toggles (serial hash by default, not raw serial).
- **Upload to server** — challenge/nonce + HMAC to your IronTrace instance.
- **Browse devices / Findings** — drill-down into PCI/USB and individual findings.

---

## CLI

Headless scans for automation, CI, or admin scripts:

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| Flag | Description |
|------|-------------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | JSON report path (default: timestamped file in cwd) |
| `--html` | Optional HTML path (Self-Audit auto-generates `.html` next to JSON) |
| `--memory` | Enable Layer 2 memory scan (full-forensic only) |

Published binary name: `irontrace.exe` (from `IronTrace.Cli` publish).

---

## Optional memory scan (hollows_hunter)

IronTrace **does not bundle** memory-scan tools. When opted in, it spawns [hollows_hunter](https://github.com/hasherezade/hollows_hunter) as an external subprocess and parses JSON stdout. No in-process memory APIs; no memory dumps in reports.

| Component | License | Shipped with IronTrace? |
|-----------|---------|-------------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **No** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) (`pe-sieve64.dll`) | BSD-2-Clause | **No** |

### Install (one-time, admin/lab)

1. Download 64-bit Windows builds from upstream releases.
2. Place files in the repo dev path:

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   For a published app, use a `tools/` folder next to the executable.

3. Restart IronTrace — the yellow **"Memory scan tool not found"** banner on Home should disappear and the memory checkbox becomes enabled.

If you redistribute hollows_hunter/pe-sieve in your admin bundle, retain upstream BSD-2-Clause notices. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/research/pe-sieve-hollows-hunter.md](docs/research/pe-sieve-hollows-hunter.md).

---

## Server upload & admin review

Run the server locally:

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

With PostgreSQL:

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

Upload flow: client requests challenge → signs report with HMAC → server stores scan → admin triages in `/admin` (Pending / Accepted / Rejected / NeedsInfo). Dev bootstrap API keys and plain HTTP are for local work only — rotate keys and use HTTPS before production. Details: [docs/api/README.md](docs/api/README.md).

---

## What it does

- Reads OS build and platform security: Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection, hypervisor flags
- Inventories motherboard/BIOS identity, PCI/PCIe devices, and USB devices
- Resolves vendor/device names from offline `pci.ids` / `usb.ids` databases
- Lists drivers and matches against offline LOLDrivers snapshot (BYOVD-style evidence, not a verdict by itself)
- Snapshots Code Integrity Operational log (more detail when elevated)
- Optional kernel PCI evidence via `IronTrace.Driver` (lab test-signed; degrades cleanly without it)
- Safe challenge policy (default deny; no device reset) and PCIe DOE detection where caps are available
- Best-effort Measured Boot PCR snapshot via TBS (evidence only, not attestation)
- Conservative risk engine → versioned JSON report (schema 1.6) with export privacy toggles
- DMA watchlist, multi-signal `DMA_SIGNAL_CLUSTER`, optional PnP history
- Phase 6 forensic: execution artifacts, process inventory, BYOVD deep, HWID cross-source, overlay/AI-vision signals
- Optional upload to your IronTrace server for human admin review

---

## What it is not

- **Not cryptographic proof.** User-mode PCI/USB IDs can be spoofed; kernel evidence raises confidence but does not prove honesty. See [threat model](docs/security/THREAT_MODEL.md).
- **Not spyware.** No browser history, documents, passwords, keystrokes, screenshots, or arbitrary process memory dumps.
- **Not a DMA toolkit.** The optional KMDF driver performs bounded PCI evidence IOCTLs only ([driver boundary](docs/architecture/DRIVER_BOUNDARY.md)).
- **Not a vendor of cheat tools.** PCILeech, BYOVD exploit kits, and HWID spoofers are research-only under `docs/research/`.

---

## Architecture

```text
WPF / CLI
  → Windows + Hardware collectors
  → optional KernelEvidence / MeasuredBoot
  → optional Forensic pipeline (Phase 6)
  → SafeChallengePolicy + DoeSpdmDetector
  → local reference DBs (pci.ids, usb.ids, LOLDrivers)
  → RiskEngine → JSON report (schema 1.6)
  → optional Upload (challenge + HMAC) → Server /admin
```

`IronTrace.Driver` is built with Visual Studio + WDK (not `dotnet`). CI runs usermode tests only.

**Solution layout:**

| Path | Role |
|------|------|
| `src/IronTrace.App` | WPF desktop client |
| `src/IronTrace.Cli` | Headless scanner |
| `src/IronTrace.Server` | Upload API + admin UI |
| `src/IronTrace.Core` | Scan orchestration |
| `src/IronTrace.Forensics` | Phase 6 collectors |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | Platform & device collectors |
| `src/IronTrace.RiskEngine` | Findings & verdict |
| `data/reference/` | Offline pci/usb/loldrivers DBs |
| `artifacts/tools/` | Optional hollows_hunter (not in git) |

---

## Development

### Requirements

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download) (`global.json` pins the band)
- Docker (optional) — PostgreSQL for local server stack
- Visual Studio + WDK (optional) — only for `IronTrace.Driver`

### Build & test

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### Publish (self-contained win-x64)

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

End-user machines do not need the .NET runtime when using a self-contained publish.

### Reference database

Bundled DBs under `data/reference/` keep scans usable without network. Rebuild with the importer:

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

Also supports `gen-keys` / `sign-manifest` for signed reference update packages. See [docs/database/REFERENCE_DB.md](docs/database/REFERENCE_DB.md).

### Design rules

- Evidence over accusations · unsupported is not suspicious
- No fake "success" for unimplemented features
- JSON export defaults to serial **hash**, not raw serial
- Server upload never sends raw serial; user confirms consent first
- Upload API keys prefer DPAPI storage over plaintext config
- Admin review is human triage only

Full policy: [docs/security/PRIVACY.md](docs/security/PRIVACY.md).

---

## Third-party notices

IronTrace ships **offline reference data** (pci.ids, usb.ids, LOLDrivers) — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Memory-scan tools (**hollows_hunter**, **pe-sieve**) are **third-party, BSD-2-Clause, not bundled** — you install them separately if you want Layer 2 memory scan.

---

## Roadmap

| Phase | Status | Notes |
|-------|--------|-------|
| 1 Foundation | Done (0.1.0) | WPF app, PCI inventory, risk engine, export |
| 2 Universal integrity | Done (0.2.0) | USB, drivers, LOLDrivers, CI logs, signed ref updates |
| 3 Server challenge MVP | Done (0.3.0) | Challenge upload, `/admin`, Docker Postgres |
| 4 Kernel evidence | Done (0.4.0) | KMDF lab driver, protocol v2, report schema 1.3 |
| 5 Active verification | Done (0.5.x) | Challenge policy, DOE/PCR, DMA triage/BAR/DSN |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit, Full Forensic, optional hollows_hunter |

Version channels stay separate: app, report schema, API, reference DB, driver protocol. See [docs/architecture/PHASED_ROADMAP.md](docs/architecture/PHASED_ROADMAP.md).

---

## Documentation

| Topic | Link |
|-------|------|
| Architecture | [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) |
| Phased roadmap | [docs/architecture/PHASED_ROADMAP.md](docs/architecture/PHASED_ROADMAP.md) |
| Driver boundary | [docs/architecture/DRIVER_BOUNDARY.md](docs/architecture/DRIVER_BOUNDARY.md) |
| Driver lab | [src/IronTrace.Driver/README.md](src/IronTrace.Driver/README.md) |
| API & upload | [docs/api/README.md](docs/api/README.md) |
| Threat model | [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md) |
| Privacy | [docs/security/PRIVACY.md](docs/security/PRIVACY.md) |
| Reference DB | [docs/database/REFERENCE_DB.md](docs/database/REFERENCE_DB.md) |
| pe-sieve / hollows_hunter | [docs/research/pe-sieve-hollows-hunter.md](docs/research/pe-sieve-hollows-hunter.md) |
| Research index | [docs/research/README.md](docs/research/README.md) |
| **Translations** | [docs/i18n/README.md](docs/i18n/README.md) (UK, DE, FR, ES, PL, PT, ZH, JA) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security policy | [SECURITY.md](SECURITY.md) |

---

## License & contact

**IronTrace** — proprietary. See [LICENSE](LICENSE).

**Third-party data & tools** — [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

**Discord:** twinkipro

For security issues, report privately (see [SECURITY.md](SECURITY.md)). Do not open public issues for exploitable bugs until a fix is ready.

<p align="center">
  <img src="../../docs/assets/irontrace-banner.png" alt="IronTrace — Windows Hardware &amp; Forensic Integrity Scanner" width="100%">
</p>

# IronTrace

<p align="center">
  <a href="https://github.com/codedevdev/irontrace/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/codedevdev/irontrace/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/codedevdev/irontrace/actions/workflows/release.yml"><img alt="Release" src="https://github.com/codedevdev/irontrace/actions/workflows/release.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/codedevdev/irontrace/releases/latest"><img alt="Latest Release" src="https://img.shields.io/github/v/release/codedevdev/irontrace?label=release"></a>
  <a href="https://github.com/codedevdev/irontrace/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/codedevdev/irontrace/total?label=downloads"></a>
  <a href="https://dotnet.microsoft.com/"><img alt=".NET 10" src="https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet"></a>
  <a href="https://github.com/codedevdev/irontrace"><img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20x64-0078D4?logo=windows"></a>
  <a href="../../LICENSE"><img alt="License" src="https://img.shields.io/github/license/codedevdev/irontrace"></a>
</p>

<p align="center">
  <strong>🌐 Sprachen / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <a href="README.uk.md">Українська</a> ·
  <b>Deutsch</b> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pl.md">Polski</a> ·
  <a href="README.pt.md">Português</a> ·
  <a href="README.zh-CN.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

**Windows-Hardware- und Forensic-Integritäts-Scanner für Game-Server-Admins.**

IronTrace sammelt Belege zur Plattformsicherheit, PCI/PCIe-/USB-Geräten, Treibern und optionalen Forensic-Signalen — und erstellt daraus eine nachvollziehbare Integritätsbewertung. Das Tool hilft Ihnen, einen Rechner **zu prüfen**. Es erklärt niemanden allein wegen eines auffälligen Befunds zum Cheater. Es gibt keinen Auto-Ban-Pfad.

| Kanal | Version |
|-------|---------|
| Anwendung | **0.7.0** (Phase 6 — Forensic Integrity Scan) |
| Report-Schema | `1.6` |
| API | `v1` |
| Driver-Protokoll | `2` |
| Referenz-DB-Schema | `2` |

---

## Inhaltsverzeichnis

- [Schnellstart](#schnellstart)
- [Scan-Modi](#scan-modi)
- [Desktop-App (WPF)](#desktop-app-wpf)
- [CLI](#cli)
- [Optionale Speichersuche (hollows_hunter)](#optionale-speichersuche-hollows_hunter)
- [Server-Upload & Admin-Review](#server-upload--admin-review)
- [Was IronTrace leistet](#was-irontrace-leistet)
- [Was IronTrace nicht ist](#was-irontrace-nicht-ist)
- [Architektur](#architektur)
- [Entwicklung](#entwicklung)
- [Drittanbieter-Hinweise](#drittanbieter-hinweise)
- [Roadmap](#roadmap)
- [Dokumentation](#dokumentation)
- [Lizenz & Kontakt](#lizenz--kontakt)

---

## Schnellstart

**Endnutzer (veröffentlichter Build oder `dotnet run`):**

1. IronTrace unter Windows 10/11 x64 starten.
2. Auf dem Startbildschirm einen Scan-Modus wählen:
   - **Admin Scan** — Hardware-Scan plus optionale Forensic-Tiefe für Server-Admins.
   - **Self-Audit** — spielerorientierter Scan; HTML-Report wird automatisch auf dem Desktop gespeichert.
3. Verdict und Findings auf dem Result-Bildschirm prüfen.
4. JSON exportieren, auf Ihren IronTrace-Server hochladen oder einen neuen Scan starten.

**Entwickler:**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

Scans funktionieren **offline**, wenn gebündelte Referenz-DBs unter `data/reference/` vorhanden sind. Erhöhte Rechte sind optional (`asInvoker`); als Administrator ausführen, nur wenn Sie detailliertere Code Integrity / DeviceGuard-Informationen benötigen.

---

## Scan-Modi

IronTrace trennt **reine Hardware-Scans** von **Forensic-Profilen**. Forensic-Ebenen sind datenschutzgeschützt; die Speichersuche erfordert explizite Zustimmung und externe Tools (siehe unten).

| Modus | WPF-Schaltfläche | CLI `--profile` | Forensic-Ebenen | Typischer Einsatz |
|------|------------------|-----------------|-----------------|-------------------|
| Nur Hardware | Admin Scan (ohne Forensic-Checkboxen) | `hardware-only` | Keine | PCI/USB/Treiber-Baseline |
| Vollständig Forensic | Admin Scan + Process-/Memory-Checkboxen | `full-forensic` | Alle (Memory bei installiertem Tool + `--memory`) | Tiefe Admin-Untersuchung |
| Self-Audit | **Self-Audit** | `self-audit` | Execution, BYOVD, HWID, Overlay, Process Inventory | Transparenz-Report für Spieler |
| Console rig | — | `console-rig` | Self-Audit + Capture-Card / Input-Fokus | Zweiter PC in einem Stream-Setup |

**Forensic-Ebenen (Phase 6):**

| Ebene | Was geprüft wird | Zustimmung |
|-------|------------------|------------|
| 0 | Prefetch/BAM/ShimCache, BYOVD deep, HWID cross-source, Overlays | Aktiv bei Self-Audit / Full Forensic |
| 1 | Process-/Service-Inventory, Persistence (Tasks, Run keys) | Checkbox `IncludeProcessInventory` oder Profil-Standard |
| 2 | Memory Integrity via **hollows_hunter**-Subprozess | Checkbox `IncludeMemoryScan` oder CLI `--memory` |

Ohne installiertes hollows_hunter wird Ebene 2 übersprungen — alles andere läuft weiter. Die UI zeigt einen Hinweis, wenn das Tool fehlt.

---

## Desktop-App (WPF)

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### Startbildschirm

| Steuerelement | Zweck |
|---------------|-------|
| **Admin Scan** | Hardware-Scan; wird zu Full Forensic, wenn Process- oder Memory-Checkboxen aktiviert sind |
| **Self-Audit** | Forensic-Self-Audit-Profil; speichert HTML nach `%USERPROFILE%\Desktop\` |
| Include process/service inventory | Ebene 1 — listet laufende Prozesse und Dienste (Privacy Opt-in) |
| Include memory scan via PE-sieve | Ebene 2 — nur aktiv, wenn [hollows_hunter](#optionale-speichersuche-hollows_hunter) installiert ist |
| Include PnP device history | Privacy Opt-in; korreliert historische PCI-Einträge mit der Watchlist |

### Result-Bildschirm

- **Verdict** — konservative Ausgabe der Risk Engine (`Normal` … `HighRisk`, niemals Auto-Ban).
- **Forensic banner** — Forensic-Zusammenfassung auf hoher Ebene, falls zutreffend.
- **Export report** — JSON mit Privacy-Toggles (Seriennummer-Hash standardmäßig, nicht die Roh-Seriennummer).
- **Upload to server** — Challenge/Nonce + HMAC zu Ihrer IronTrace-Instanz.
- **Browse devices / Findings** — Detailansicht für PCI/USB und einzelne Findings.

---

## CLI

Headless-Scans für Automatisierung, CI oder Admin-Skripte:

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| Flag | Beschreibung |
|------|--------------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | Pfad zum JSON-Report (Standard: zeitgestempelte Datei im cwd) |
| `--html` | Optionaler HTML-Pfad (Self-Audit erzeugt `.html` neben JSON) |
| `--memory` | Ebene-2-Memory-Scan aktivieren (nur full-forensic) |

Veröffentlichter Binary-Name: `irontrace.exe` (aus `IronTrace.Cli` publish).

---

## Optionale Speichersuche (hollows_hunter)

IronTrace **liefert keine** Memory-Scan-Tools mit. Bei Opt-in startet es [hollows_hunter](https://github.com/hasherezade/hollows_hunter) als externen Subprozess und parst JSON-Stdout. Keine In-Process-Memory-APIs; keine Memory-Dumps in Reports.

| Komponente | Lizenz | Mit IronTrace ausgeliefert? |
|-----------|--------|----------------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **Nein** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) (`pe-sieve64.dll`) | BSD-2-Clause | **Nein** |

### Installation (einmalig, Admin/Lab)

1. 64-Bit-Windows-Builds aus den Upstream-Releases herunterladen.
2. Dateien im Repo-Dev-Pfad ablegen:

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   Für eine veröffentlichte App einen Ordner `tools/` neben der ausführbaren Datei verwenden.

3. IronTrace neu starten — das gelbe Banner **"Memory scan tool not found"** auf dem Startbildschirm sollte verschwinden und die Memory-Checkbox wird aktiviert.

Wenn Sie hollows_hunter/pe-sieve in Ihrem Admin-Bundle weitergeben, behalten Sie die upstream BSD-2-Clause-Hinweise bei. Siehe [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) und [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md).

---

## Server-Upload & Admin-Review

Server lokal starten:

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

Mit PostgreSQL:

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

Upload-Ablauf: Client fordert Challenge an → signiert Report mit HMAC → Server speichert Scan → Admin triagiert in `/admin` (Pending / Accepted / Rejected / NeedsInfo). Dev-Bootstrap-API-Keys und plain HTTP sind nur für lokale Arbeit gedacht — Keys rotieren und HTTPS vor Produktion verwenden. Details: [docs/api/README.md](../api/README.md).

---

## Was IronTrace leistet

- Liest OS-Build und Plattformsicherheit: Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection, Hypervisor-Flags
- Inventarisiert Mainboard-/BIOS-Identität, PCI/PCIe-Geräte und USB-Geräte
- Löst Vendor-/Device-Namen über offline `pci.ids` / `usb.ids`-Datenbanken auf
- Listet Treiber und gleicht sie mit offline LOLDrivers-Snapshot ab (BYOVD-artige Belege, kein Verdict für sich allein)
- Snapshot des Code Integrity Operational Log (mehr Details bei erhöhten Rechten)
- Optionale Kernel-PCI-Evidence via `IronTrace.Driver` (Lab test-signed; sauberer Fallback ohne Treiber)
- Safe challenge policy (Standard: deny; kein Device reset) und PCIe DOE-Erkennung, wo Caps verfügbar sind
- Best-effort Measured Boot PCR-Snapshot via TBS (nur Evidence, keine Attestation)
- Konservative Risk Engine → versionierter JSON-Report (Schema 1.6) mit Export-Privacy-Toggles
- DMA-Watchlist, Multi-Signal `DMA_SIGNAL_CLUSTER`, optionale PnP-Historie
- Phase-6-Forensic: Execution Artifacts, Process Inventory, BYOVD deep, HWID cross-source, Overlay-/AI-Vision-Signale
- Optionaler Upload auf Ihren IronTrace-Server für menschliches Admin-Review

---

## Was IronTrace nicht ist

- **Kein kryptografischer Beweis.** User-Mode-PCI/USB-IDs können gefälscht werden; Kernel-Evidence erhöht die Konfidenz, beweist aber keine Ehrlichkeit. Siehe [threat model](../security/THREAT_MODEL.md).
- **Keine Spyware.** Kein Browser-Verlauf, keine Dokumente, Passwörter, Tastatureingaben, Screenshots oder beliebige Process-Memory-Dumps.
- **Kein DMA-Toolkit.** Der optionale KMDF-Treiber führt nur begrenzte PCI-Evidence-IOCTLs aus ([driver boundary](../architecture/DRIVER_BOUNDARY.md)).
- **Kein Anbieter von Cheat-Tools.** PCILeech, BYOVD-Exploit-Kits und HWID-Spoofer sind nur zu Forschungszwecken unter `docs/research/` dokumentiert.

---

## Architektur

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

`IronTrace.Driver` wird mit Visual Studio + WDK gebaut (nicht mit `dotnet`). CI führt nur User-Mode-Tests aus.

**Solution-Layout:**

| Pfad | Rolle |
|------|-------|
| `src/IronTrace.App` | WPF-Desktop-Client |
| `src/IronTrace.Cli` | Headless Scanner |
| `src/IronTrace.Server` | Upload-API + Admin-UI |
| `src/IronTrace.Core` | Scan-Orchestrierung |
| `src/IronTrace.Forensics` | Phase-6-Collectors |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | Plattform- und Device-Collectors |
| `src/IronTrace.RiskEngine` | Findings & Verdict |
| `data/reference/` | Offline pci/usb/loldrivers DBs |
| `artifacts/tools/` | Optionales hollows_hunter (nicht in git) |

---

## Entwicklung

### Voraussetzungen

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download) (`global.json` pinnt die Band)
- Docker (optional) — PostgreSQL für lokalen Server-Stack
- Visual Studio + WDK (optional) — nur für `IronTrace.Driver`

### Build & Test

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### Publish (self-contained win-x64)

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Endnutzer-Rechner benötigen bei self-contained Publish keine .NET-Runtime.

### Referenz-Datenbank

Gebündelte DBs unter `data/reference/` halten Scans ohne Netzwerk nutzbar. Neuaufbau mit dem Importer:

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

Unterstützt außerdem `gen-keys` / `sign-manifest` für signierte Referenz-Update-Pakete. Siehe [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md).

### Design-Regeln

- Evidence statt Anschuldigungen · unsupported ist nicht verdächtig
- Kein falsches „success“ für nicht implementierte Features
- JSON-Export standardmäßig Seriennummer-**Hash**, nicht Roh-Seriennummer
- Server-Upload sendet niemals Roh-Seriennummer; Nutzer bestätigt Zustimmung zuerst
- Upload-API-Keys bevorzugt DPAPI-Speicherung statt Klartext-Config
- Admin-Review ist ausschließlich menschliche Triage

Vollständige Richtlinie: [docs/security/PRIVACY.md](../security/PRIVACY.md).

---

## Drittanbieter-Hinweise

IronTrace liefert **Offline-Referenzdaten** (pci.ids, usb.ids, LOLDrivers) — siehe [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

Memory-Scan-Tools (**hollows_hunter**, **pe-sieve**) sind **Drittanbieter, BSD-2-Clause, nicht gebündelt** — Sie installieren sie separat, wenn Sie Ebene-2-Memory-Scan wünschen.

---

## Roadmap

| Phase | Status | Hinweise |
|-------|--------|----------|
| 1 Foundation | Done (0.1.0) | WPF-App, PCI-Inventory, Risk Engine, Export |
| 2 Universal integrity | Done (0.2.0) | USB, Treiber, LOLDrivers, CI-Logs, signierte Ref-Updates |
| 3 Server challenge MVP | Done (0.3.0) | Challenge-Upload, `/admin`, Docker Postgres |
| 4 Kernel evidence | Done (0.4.0) | KMDF-Lab-Treiber, Protokoll v2, Report-Schema 1.3 |
| 5 Active verification | Done (0.5.x) | Challenge Policy, DOE/PCR, DMA-Triage/BAR/DSN |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit, Full Forensic, optionales hollows_hunter |

Versionskanäle bleiben getrennt: App, Report-Schema, API, Referenz-DB, Driver-Protokoll. Siehe [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md).

---

## Dokumentation

| Thema | Link |
|-------|------|
| Architektur | [docs/architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
| Phased roadmap | [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md) |
| Driver boundary | [docs/architecture/DRIVER_BOUNDARY.md](../architecture/DRIVER_BOUNDARY.md) |
| Driver lab | [src/IronTrace.Driver/README.md](../../src/IronTrace.Driver/README.md) |
| API & upload | [docs/api/README.md](../api/README.md) |
| Threat model | [docs/security/THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| Privacy | [docs/security/PRIVACY.md](../security/PRIVACY.md) |
| Reference DB | [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md) |
| pe-sieve / hollows_hunter | [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) |
| Research index | [docs/research/README.md](../research/README.md) |
| Contributing | [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| Security policy | [SECURITY.md](../../SECURITY.md) |

---

## Lizenz & Kontakt

**IronTrace** — proprietär. Siehe [LICENSE](../../LICENSE).

**Drittanbieter-Daten & Tools** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

**Discord:** twinkipro

Bei Sicherheitsproblemen bitte privat melden (siehe [SECURITY.md](../../SECURITY.md)). Keine öffentlichen Issues für ausnutzbare Bugs, bis ein Fix bereitsteht.

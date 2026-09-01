# IronTrace Architecture

Product: IronTrace, a Windows hardware integrity and PCIe verification platform.  
Version focus: Phase 5 / 0.6.0 (active verification + DMA masquerade P0-P2 evidence).  
Last updated: 2026-08-25.

## Purpose

IronTrace helps game-server administrators collect evidence about platform security configuration and PCI/PCIe device authenticity. A single anomaly is not cheating. Outputs are confidence-oriented verdicts with explainable findings.

## High-level layers

```text
IronTrace.App (WPF / MVVM) ──opt-in upload──► IronTrace.Server (API + Razor admin)
        │                                              │
IronTrace.Core (ScanOrchestrator)                 PostgreSQL (EF)
        │
   ┌────┴────┐
   ▼         ▼
Windows   Hardware
collectors collectors (+ DeviceKindClassifier)
(+ DriverClient / KernelEvidence / MeasuredBoot)
(+ SafeChallengePolicy / DoeSpdmDetector)
   │         │
   └────┬────┘
        ▼
LocalPciIds / LocalUsbIds / LolDrivers providers
IReferenceUpdateService (signed manifests)
        │
        ▼
IronTrace.RiskEngine → Findings + Assessment
        │
        ▼
IronTrace.Reporting (schema 1.5 + ExportPrivacyOptions
+ pnpHistory / DMA watchlist signals)
  + kernelEvidence / challengeEvidence / spdmEvidence / measuredBootEvidence)

Lab-only: IronTrace.Driver (KMDF) ← DeviceIoControl protocol v2
```

## Projects

| Project | Responsibility |
|---------|----------------|
| `IronTrace.App` | WPF shell, DI host, MVVM UI, export privacy, reference updates, server upload |
| `IronTrace.Core` | Scan orchestration, safe challenge policy, DOE/SPDM detection |
| `IronTrace.Contracts` | DTOs, versions, capabilities, API + driver protocol contracts |
| `IronTrace.Windows` | OS / platform security / Code Integrity / kernel driver client / Measured Boot PCR |
| `IronTrace.Hardware` | Board, PCI/USB, drivers, identity, classifier |
| `IronTrace.Fingerprints` | pci.ids / usb.ids / LOLDrivers + signed reference updates |
| `IronTrace.RiskEngine` | Conservative assessment |
| `IronTrace.Reporting` | Versioned JSON export |
| `IronTrace.Server` | `/v1` challenge/upload/review API + `/admin` Razor console |
| `IronTrace.Driver` | KMDF lab driver (WDK; not in `dotnet` CI) |
| `HardwareDbImporter` | Import DBs + `gen-keys` / `sign-manifest` |

## Design principles

1. Evidence over accusations
2. Unsupported is not suspicious
3. Collector isolation
4. No player-chosen trust providers (signed manifests only; public key embedded in the app)
5. No fake implementations
6. Privacy by design (export toggles; raw serial local-only by default; upload requires consent)

## Scan pipeline

1. OS + platform security (elevated detail when admin + `WhenElevated`)
2. Motherboard / BIOS
3. PCI + `pci.ids`
4. Optional kernel PCI evidence (`IronTrace.Driver` when present)
5. Safe challenge policy + DOE/SPDM detection (no reset execution)
6. Best-effort Measured Boot / PCR snapshot (TBS)
7. USB + `usb.ids`
8. Driver inventory + LOLDrivers
9. Code Integrity logs
10. Identity consistency
11. Risk evaluation
12. Optional JSON export (privacy options)
13. Optional server upload (challenge → HMAC → PendingReview)

Advanced inventory (Result → Advanced) includes PCI, USB, Drivers, Kernel, CI Log, and Findings tabs.

## Server layer (Phase 3)

- Auth: hashed API keys (`Upload` / `Admin`); bootstrap keys via config/env
- `POST /v1/challenges` → `POST /v1/scans` with single-use nonce + HMAC binding
- Admin review via API or `/admin` (human triage only; never auto-ban)
- Accepts report schemas `1.4` … `1.0`
- See [../api/README.md](../api/README.md)

## Capability matrix

| Capability | Status |
|------------|--------|
| User-mode PCI/USB inventory | Supported |
| Local pci.ids / usb.ids / LOLDrivers | Supported |
| Signed reference DB updates | Supported |
| Code Integrity log snapshot | Supported |
| Elevated security detail | Supported (`WhenElevated`) |
| Export privacy options | Supported |
| Device kind classifier | Supported |
| Server upload (challenge/HMAC) | Supported |
| Kernel driver evidence | Supported (runtime Partial/Unsupported if driver missing) |
| Device reset challenge | Partial (policy only; CapSafeDeviceReset unset) |
| SPDM / DOE | Partial (detection only) |
| Measured Boot / PCR evidence | Partial (best-effort TBS) |

## Future boundaries

- Driver: [DRIVER_BOUNDARY.md](DRIVER_BOUNDARY.md) · [DRIVER_SIGNING.md](DRIVER_SIGNING.md)
- Report signing design: [REPORT_SIGNING.md](REPORT_SIGNING.md) (not implemented)
- Trust policy: signed manifests; never an end-user custom trust API
- Lab: [PHASE5_LAB.md](PHASE5_LAB.md) · [PHASED_ROADMAP.md](PHASED_ROADMAP.md)

## Security notes

See [../security/THREAT_MODEL.md](../security/THREAT_MODEL.md) and [../security/PRIVACY.md](../security/PRIVACY.md).

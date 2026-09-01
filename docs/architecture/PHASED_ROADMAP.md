# IronTrace Phased Roadmap

## Phase 1: Foundation + Safe User-Mode Scanner

**Version:** 0.1.0 (complete)

- Solution structure, WPF MVVM, DI, logging
- OS / platform security / motherboard / PCI inventory
- `pci.ids` importer + local reference provider
- Conservative risk engine + JSON export
- Unit tests + architecture / threat / privacy docs

## Phase 2: Universal Integrity Scan + reference updates

**Version:** 0.2.0 (complete)

- USB inventory + `usb.ids` reference DB
- Driver inventory + offline LOLDrivers match (BYOVD evidence)
- Code Integrity Operational log snapshot (best-effort / elevation-aware)
- Identity consistency checks (placeholder UUID/serial)
- Report schema `1.2` + richer Advanced UI tabs
- Signed reference DB update manifests (ECDSA P-256) + offline/pending package apply
- Virtual/software device classifier refinement (`DeviceKindClassifier`)
- Export privacy toggles + local serial view
- Elevated-mode security detail (`WhenElevated`)

### Acceptance

- Manual **Check reference updates** verifies signature + hashes before replacing LocalAppData DBs
- Export defaults omit raw serial; toggles control paths / CI / IDs
- Classifier unit tests distinguish Hyper-V / WireGuard vs physical GPU
- Non-elevated scans complete; elevated adds DeviceGuard/CI depth notes

## Phase 3: Server challenge MVP

**Version:** 0.3.0 (complete MVP)

- ASP.NET Core API + PostgreSQL (Docker Compose for local) + EF migrations
- Challenge session + single-use nonce → HMAC-SHA256 signed scan upload
- Hashed API keys (`Upload` / `Admin`); bootstrap via env/config (no fake auth)
- Admin Razor console `/admin` (login, list, detail, review status)
- WPF opt-in upload with consent + DPAPI key store
- OpenAPI in Development; integration tests with WebApplicationFactory + InMemory

### Acceptance

- Upload with valid HMAC succeeds; bad signature / reused nonce rejected
- Admin can set Pending / Accepted / Rejected / NeedsInfo (no auto-ban)
- Client never uploads raw serial; user must confirm consent dialog

## Phase 4: Kernel evidence (optional, high bar)

**Version:** 0.4.0 (complete MVP)

- `IronTrace.Driver` (KMDF) with a narrow versioned IOCTL surface (protocol 1)
- PCI config-space / capability / BAR / Express flag evidence
- Usermode bridge in `IronTrace.Windows` with graceful degrade when driver absent
- Report schema 1.3 (`kernelEvidence`); server accepts `1.3`…`1.0`
- Advanced inventory Kernel tab surfaces structured evidence without opening JSON
- Production signing story documented in [DRIVER_SIGNING.md](DRIVER_SIGNING.md) (EV + attestation; lab test-signing only for maintainers)
- Still no arbitrary memory access; `SafeDeviceReset` denied

### Acceptance

- Without driver: scan completes; `KERNEL_EVIDENCE_UNAVAILABLE` informational only; Advanced Kernel tab shows Unavailable summary
- With test-signed lab driver: `kernelEvidence.availability` is Available/Partial; bounded BDF reads appear in export and Advanced Kernel list
- Protocol packing / version negotiation unit tests pass without WDK
- Driver build is lab-only (WDK); not required for `dotnet test` CI

## Phase 5: Active verification + attestation research

**Version:** 0.5.0 (complete MVP); 0.5.1 DMA masquerade P0; 0.6.0 DMA masquerade P1/P2

- Safe challenge policy (usermode engine + kernel deny-list audit); CapSafeDeviceReset unset; no FLR execution
- SPDM/DOE detection only (extended cap `0x2E`) + research note; no libspdm
- Best-effort Measured Boot PCR 0-7 via TBS + [REPORT_SIGNING.md](REPORT_SIGNING.md) design (no "Attested" UI)
- Report schema 1.4 Phase 5 sections; 1.5 adds `pnpHistory`
- Driver protocol 2: gated BAR size write-probe (`CapQueryBarSizeProbe`); SafeDeviceReset still unset
- Bundled `dma-watchlist.json`, `DMA_SIGNAL_CLUSTER`, privacy-gated PnP Enum history (opt-in)
- Lab checklist: [PHASE5_LAB.md](PHASE5_LAB.md)

### Acceptance

- Policy: DenyCritical for storage/GPU/bridge/NIC/USB host; AllowListedEligible for multimedia/input with `ExecutionNotEnabled`; default deny elsewhere
- Missing DOE/TPM/PCR maps to Unsupported/Unknown. Never Suspicious or High from those alone.
- Without driver: full user-mode scan + challenge policy from PnP class codes
- Watchlist / cluster / PnP history findings ≤ Medium; CapSafeDeviceReset never advertised
- Unit tests cover policy, DOE detection, schema 1.5 export, protocol 2 negotiation, risk conservatism (no WDK/TPM required)

## Versioning channels (keep separate)

| Channel | Example |
|---------|---------|
| Application | 0.6.0 |
| Report schema | 1.5 |
| API | v1 |
| Reference DB | schema 1 |
| Driver protocol | 2 |

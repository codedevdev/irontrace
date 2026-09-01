# Phase 5 lab checklist

Manual checks that need a lab machine (driver / TPM). CI `dotnet test` does not require these.

## Without driver / TPM

- [ ] Full scan completes (user-mode path)
- [ ] Advanced / result shows kernel evidence Unavailable (informational)
- [ ] `challengeEvidence` present with DenyCritical / DenyDefault / AllowListedEligible decisions
- [ ] `spdmEvidence.availability` Unknown or Unsupported (not treated as suspicious)
- [ ] `measuredBootEvidence` Unknown/Unsupported when TBS/TPM unavailable (not suspicious)
- [ ] Export schemaVersion `1.5`; no "Attested" label in UI
- [ ] PnP history off by default; with Home checkbox / config opt-in, `pnpHistory.optInEnabled` true
- [ ] Kernel tab shows BAR type/base (and size when probe succeeded)

## With test-signed IronTrace.Driver

- [ ] Kernel evidence Available/Partial for some BDFs; protocol 2 advertises `CapQueryBarSizeProbe`
- [ ] Network-class BAR sizes may be non-zero; storage/GPU/bridge/USB host sizes stay 0 (probe denied)
- [ ] DOE (0x2E) devices (if any) appear under `spdmEvidence` with `doePresent: true` and `NotIntegrated`
- [ ] IOCTL `SafeDeviceReset` still fails: Cap unset; critical classes audit `SafeDeviceResetDeniedCritical`; others `SafeDeviceResetDenied`
- [ ] No FLR / device reset occurs
- [ ] If a stock `10EE:0666` device is present: `STOCK_PCILEECH_IDENTITY` (+ triage hint); default caps → `PCILEECH_DEFAULT_CAP_LAYOUT`; multi-signal → `DMA_SIGNAL_CLUSTER`
- [ ] Result screen shows DMA / CFW review summary when any DMA codes fire; Findings tab DMA / CFW only filter works
- [ ] DSN ext-cap devices (if any): `deviceSerialNumberHex` in `kernelEvidence`; zero/dup → `PCI_DSN_WEAK_SIGNAL` (≤ Medium)

## With TPM 2.0 + TBS

- [ ] `measuredBootEvidence` Supported or Partial with `pcrBank: sha256` and PCR indexes 0-7 (or subset)
- [ ] Export privacy `IncludePcrDigests=false` omits digest hex
- [ ] UI shows Measured Boot / PCR as evidence availability, never "Attested"

## Server

- [ ] Upload with schema `1.5` (and `1.4`…`1.0`) accepted
- [ ] Admin review remains human-only (no auto-ban)

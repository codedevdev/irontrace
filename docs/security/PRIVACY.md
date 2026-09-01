# IronTrace Privacy Policy (Engineering)

IronTrace is a hardware / platform security scanner, not spyware.

## Never collect

- Browser history
- Documents or unrelated files
- Passwords, messages, game account credentials
- Keystrokes or screenshots
- Arbitrary process memory (including dumps)
- Raw bulk PCI config-space dumps in reports (structured fields only)
- Full unrestricted ETW process telemetry (deferred behind a privacy gate)

## May collect (local scan)

- Windows version / build / architecture
- Platform security feature states (Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection, virtualization)
- Motherboard / BIOS identity fields (serial hashed for export by default; raw available behind a local UI toggle)
- PCI device inventory and driver metadata
- USB device inventory (VID/PID + driver metadata)
- Loaded/installed kernel driver image paths, SHA-256 hashes, and Authenticode metadata
- Offline matches against a local LOLDrivers snapshot (filename / hash)
- Code Integrity Operational event summaries (event IDs, truncated file paths; not full process memory)
- System product UUID / identity consistency signals (placeholder detection)
- Resolved vendor/device names from local reference DBs (`pci.ids`, `usb.ids`)
- Optional kernel PCI evidence (structured): BDF, config-derived VID/DID/class, capability IDs, BAR type/base, Express feature flags, optional PCIe DSN hex. Not bulk config-space dumps.
- Optional challenge policy decisions (class-based deny / allow-list eligibility; no reset execution)
- Optional SPDM/DOE detection flags (capability presence only)
- Optional Measured Boot PCR digests (best-effort; export toggle `IncludePcrDigests`)
- Optional PnP device history (opt-in via `IronTrace:Privacy:IncludePnpDeviceHistory` or Home checkbox). Scans Enum\PCI for watchlisted identities not on the current bus only; off by default.
- Findings and risk assessment derived from the above (including DMA/CFW review codes with admin triage hints)

## Phase 6 forensic scan (opt-in by profile)

Layer 0 (execution filenames, BYOVD deep, HWID cross-source, overlay context): included in `SelfAudit` / `FullForensic` profiles.

Layer 1 (process/service inventory, persistence): requires `IncludeProcessInventory` consent (default on for Self-Audit/FullForensic).

Layer 2 (memory scan via optional external PE-sieve/hollows_hunter subprocess): requires explicit `IncludeMemoryScan`; tools are not bundled; no memory dumps in reports.

Upload never includes raw command lines or module paths — hashes only when forensic sections are consented for upload.

## Export privacy

JSON export defaults:

- Include serial hash (not raw)
- Include driver paths, CI events, and instance IDs
- Include PCR digests when collected (platform fingerprint; toggleable)
- Include PCIe DSN hex inside `kernelEvidence` when collected (device fingerprint, not SMBIOS board serial)
- Omit raw serial

Users may toggle these on the Result screen before export. Raw serial in export is discouraged. PCR digests and PCIe DSN can identify a platform or device configuration; treat uploaded values as sensitive posture data.

## Hardware serial numbers

| Mode | Use |
|------|-----|
| Not collected | Default for network upload. Raw serial is never uploaded. |
| Hashed | HMAC-SHA256 with an install-local DPAPI-protected key. Preferred for correlation. |
| Raw | Local advanced view only, behind an explicit UI toggle. Never the default in exported JSON. |

## Export / upload consent

Before any network submission the client:

1. Shows a user-readable summary of fields that will be sent
2. Requires explicit Yes/No confirmation
3. Forces `IncludeRawSerial=false` (server also strips `serialRaw` if present)

Uploaded payload may include platform posture, PCI/USB inventory (counts/IDs without raw board serial), findings, and risk verdict for administrator review only.

Phase 3 ships opt-in upload to a configured `IronTrace:Server:BaseUrl` with an Upload API key (prefer DPAPI store under `%LocalAppData%\IronTrace\keys\`).

## Logs

Logs may include technical errors (API failures, parse errors). Logs must not include secrets, raw serials (prefer redaction), or unrelated user content. Stored under `%LocalAppData%\IronTrace\logs`.

## Retention

Local scans and exports stay on the user's machine unless the user copies or uploads them. Server-side retention is operator-controlled (Postgres); configurable retention policies are deferred. Operators should document their own retention when deploying `IronTrace.Server`.

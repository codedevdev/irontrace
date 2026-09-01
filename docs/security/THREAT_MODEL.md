# IronTrace Threat Model (Client)

STRIDE plus product-specific abuse cases. Covers the local Windows client through Phases 1-5: user-mode scanners, optional KMDF evidence driver, challenge policy, and attestation research. Last updated 2026-08-25.

## Assets

- Integrity of scan evidence and exported reports
- Local reference database authenticity (`pci.ids`, `usb.ids`, LOLDrivers snapshot)
- User privacy (hardware serials, machine identifiers, truncated CI paths)
- Trust that verdicts are explainable and not trivially poisoned by the end user
- Integrity of the optional kernel evidence channel (narrow IOCTL surface)

## Trust boundaries

1. IronTrace process ↔ Windows PnP / WMI / registry / Event Log
2. IronTrace process ↔ bundled/cached reference DBs on disk
3. IronTrace process ↔ future network update endpoint (stub in 0.1.0)
4. IronTrace process ↔ IronTrace.Driver (DeviceIoControl, Administrators-only)
5. End user ↔ UI (can lie about environment; we collect evidence, not proof of honesty)

## STRIDE summary

| Category | Threat | Mitigation |
|----------|--------|------------|
| Spoofing | Fake reference DB claiming known-good devices | ECDSA-signed manifests + SHA-256 per artifact; public key bundled; last-known-good `.bak` |
| Tampering | Modified exe / DLL search-order hijack | Prefer self-contained publish; avoid insecure probe paths; Authenticode later |
| Tampering | Malformed `pci.ids` / `usb.ids` / LOLDrivers JSON / oversized input | Parser size limits + unit tests |
| Tampering | Spoofed CI Operational events / cleared logs | Best-effort evidence; inaccessible log maps to Unknown, not Suspicious |
| Tampering | Unsigned / wrong-key reference update package | Signature verify fails: abort, no replace |
| Repudiation | User denies a scan happened | Local report includes scanId + timestamps; server challenge + nonce + stored submission |
| Info disclosure | Serial numbers / identifiers in exports and logs | Hash or omit serials in export; truncate CI paths; no secrets in logs |
| DoS | Hang/crash on bad device property | Collector isolation; timeouts; Unknown mapping |
| EoP | Malicious usermode abuse of driver IOCTLs | Administrators-only SDDL; METHOD_BUFFERED size checks; SafeDeviceReset never executes (class deny audit); unknown IOCTL fail-closed; see DRIVER_BOUNDARY |
| EoP | Future broader driver features | Keep surface minimal; deny list for reset; no raw memory APIs |
| Spoofing | Fake "attested" scan claims | No Attested UI; PCR evidence is not a report signature; see REPORT_SIGNING.md |

## Product abuse cases

| Abuse | Response |
|-------|----------|
| Player points trust at `https://evil.example` | Not allowed. No player trust-provider config. |
| Replayed clean JSON report | Mitigated by single-use challenge nonce + HMAC binding to body hash |
| Stolen Upload API key | Attacker can submit scans until key revoked; use TLS in production; rotate keys |
| Stolen Admin API key | Full review access. Protect bootstrap secrets; revoke via `revoked_at`. |
| "DMA detected" / "cheater" false positive UX | Conservative verdicts; Unsupported is not suspicious; LOLDrivers and DMA CFW signals max Medium; see [pcileech.md](../research/pcileech.md) |
| Filename-only LOLDrivers false positive | Prefer SHA-256 match confidence; explain filename matches as Medium |
| Poisoning community fingerprints | Not shipped; future trust tiers reject untrusted telemetry |
| BYOVD exploit code in product | Never. Intel catalog only. |
| Auto-ban from scan verdict | Explicitly out of scope. Human admin review only. |
| Challenge / SPDM / PCR failure as cheat | Unsupported is not suspicious; missing DOE/TPM never High/Suspicious |

## Residual risks

- User-mode PCI/USB IDs and SMBIOS fields can be spoofed. Treat them as inventory, not proof.
- Kernel config-space reads raise confidence but an admin-capable attacker can still tamper with the local machine.
- Some security features and CI logs require elevation; without it results may be `Unknown` / inaccessible.
- Unsigned local reports can be edited by the machine owner; server accepts HMAC from whoever holds the Upload key.
- LOLDrivers filename matches have higher false-positive risk than hash matches.
- Without TLS, API keys and payloads are exposed on the wire. Require HTTPS in production.
- Lab test-signed drivers are not for end-user distribution.
- Custom DMA firmware can clone a donor PCIe identity (NIC/storage/etc.). Stock and shallow CFW leave detectable fingerprints; deep FULL EMU is multi-signal and never proof alone. See [docs/research/pcileech.md](../research/pcileech.md).
- Local reports remain unsigned. Measured Boot PCR snapshots are evidence fingerprints, not TPM quotes over the JSON (see REPORT_SIGNING.md).

## Out of scope for current hardening

Invasive anti-tamper, kernel ACLs, remote attestation, ban automation, process-memory anti-cheat, FLR/device reset execution, full SPDM stack.

# IronTrace Driver Boundary

Status: protocol 2 (gated BAR size write-probe; CapSafeDeviceReset still unset).  
Component: `IronTrace.Driver` (C++20 / KMDF / WDK), lab build under [`src/IronTrace.Driver`](../../src/IronTrace.Driver).

## Goals

Expose the minimum hardware evidence operations IronTrace needs. Prefer security over convenience.

## Non-goals

- Arbitrary physical/virtual memory read/write
- Generic DMA tooling
- User-configurable raw IOCTL playground
- Bypassing Secure Boot / HVCI for convenience

## User-mode interface principles

1. Versioned protocol. `DriverProtocolVersion` is negotiated at open (`IronTrace.Contracts.Driver`, protocol 2; clients accept 1-2).
2. Capability query first. Call `GetProtocolInfo` before other ops.
3. Per-operation authorization. Device SDDL is Administrators+SYSTEM; future client-path hardening is deferred.
4. No bulk dump APIs. Scoped reads only (one BDF, bounded length). Reports store structured fields, not raw config blobs.
5. Audit logging. The driver logs operation class + device BDF, not secrets or payloads.

## Operations (protocol v2)

| Op | MVP | Purpose |
|----|-----|---------|
| `GetProtocolInfo` | Yes | Version + capability bitmask + max config read length |
| `ReadPciConfig` | Yes | Bounded config-space read for a BDF (≤ 4096) |
| `EnumerateCapabilities` | Yes | Standard + extended cap list (capped) |
| `QueryBarLayout` | Yes | BAR type/base; size via gated write-probe when `CapQueryBarSizeProbe` is set |
| `QueryExpressCaps` | Yes | PCIe / AER / ACS / ATS / SR-IOV / FLR flags where present |
| `SafeDeviceReset` | Denied | Cap bit unset; class-aware deny audit; never executes FLR |

### BAR size write-probe (protocol 2)

- Advertised as `CapQueryBarSizeProbe` (SafeDeviceReset remains unset).
- Denied for storage (`0x01`), GPU (`0x03`), bridges (`0x06`), USB host (`0x0C`/`0x03`).
- Allowed for network (`0x02`). Stock DMA CFW often presents as Ethernet.
- Probe writes `0xFFFFFFFF` to BAR registers then restores originals; size may remain 0 if probe is denied or fails.

## Critical device deny list (reset)

Never auto-reset. Usermode [`SafeChallengePolicyEngine`](../../src/IronTrace.Core/Challenge/SafeChallengePolicyEngine.cs) is authoritative for report `challengeEvidence`. Kernel mirrors the critical set on `SafeDeviceReset` IOCTL:

- Boot storage (PCI class `0x01`, conservative)
- GPU / display (`0x03`)
- Critical system bridges (`0x06`)
- Network adapters (`0x02`)
- USB host controllers (`0x0C` / subclass `0x03`)

Allow-list (future challenge only, not executed): multimedia (`0x04`), input (`0x09`). Everything else: default deny.

Kernel audit: `SafeDeviceResetDeniedCritical` vs `SafeDeviceResetDenied` → `STATUS_ACCESS_DENIED` / `STATUS_NOT_SUPPORTED`.

## Communication

User-mode talks through DeviceIoControl with structs in `IronTrace.Contracts` / `IronTraceDriverProtocol.h`. Fail closed on unknown IOCTL. Protocol 1 drivers remain compatible (Available without size-probe). Protocol 2 without `CapQueryBarSizeProbe` is Partial.

## Privilege / install

- Open requires Administrators (SDDL).
- Install requires administrator rights.
- Lab: test-signing. See [`src/IronTrace.Driver/README.md`](../../src/IronTrace.Driver/README.md).
- Production: EV Authenticode + Microsoft attestation. See [DRIVER_SIGNING.md](DRIVER_SIGNING.md).
- Driver project is not built by `dotnet` CI; use the WDK solution in `src/IronTrace.Driver`.

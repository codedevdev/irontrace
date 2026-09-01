# IronTrace.Driver (KMDF) lab build

Narrow kernel evidence driver for Phase 4-5. Not part of `dotnet build` / CI. Requires Visual Studio 2022+ with Windows Driver Kit (WDK) matching your SDK.

## What it does

- ROOT-enumerated software device (`Root\IronTrace`)
- Versioned IOCTL protocol v2 (`include/IronTraceDriverProtocol.h`, mirrored in `IronTrace.Contracts`)
- Scoped PCI config-space reads, capability walk, BAR decode with gated size write-probe (network allowed; storage/GPU/bridge/USB host denied), Express/AER/ACS/ATS/SR-IOV/FLR flags
- No arbitrary memory R/W or DMA tooling
- `SafeDeviceReset`: Cap unset; class-aware deny audit (`SafeDeviceResetDeniedCritical` / `SafeDeviceResetDenied`); never executes FLR

See [PHASE5_LAB.md](../../docs/architecture/PHASE5_LAB.md) for manual checks.

## Prerequisites

1. Visual Studio 2022 (C++ workload)
2. Windows 11 / Windows 10 SDK
3. Matching WDK (same major version as the SDK)
4. Administrator rights on a lab machine

## Build

```text
1. Open src\IronTrace.Driver\IronTrace.Driver.sln in Visual Studio
2. Select Release | x64 (or Debug | x64)
3. Build → IronTrace.Driver.sys (+ package folder with INF)
```

MSBuild (Developer Command Prompt for VS, WDK installed):

```bat
msbuild IronTrace.Driver.sln /p:Configuration=Release /p:Platform=x64
```

## Test signing (lab only, not for end users)

```bat
bcdedit /set testsigning on
:: reboot
```

Sign the driver for test (example with a self-signed cert created via `MakeCert` / `New-SelfSignedCertificate` + `signtool`):

```bat
signtool sign /v /s PrivateCertStore /n "IronTraceTest" /t http://timestamp.digicert.com IronTrace.Driver.sys
```

Production signing (EV Authenticode + Microsoft attestation for Secure Boot / HVCI clients): see [docs/architecture/DRIVER_SIGNING.md](../../docs/architecture/DRIVER_SIGNING.md). Lab test-signing is never for end users.

## Install

From an elevated prompt, in the folder containing `IronTrace.Driver.sys` and `IronTrace.Driver.inf`:

```bat
pnputil /add-driver IronTrace.Driver.inf /install
```

Or:

```bat
devcon install IronTrace.Driver.inf Root\IronTrace
```

Confirm the device appears under System devices as IronTrace Kernel Evidence Driver.

## Uninstall

```bat
pnputil /delete-driver IronTrace.Driver.inf /uninstall /force
```

Or remove the device in Device Manager, then delete the driver package.

## Manual lab checklist

1. Enable test signing and reboot
2. Build + test-sign `IronTrace.Driver.sys`
3. Install via `pnputil` / `devcon`
4. Run IronTrace (0.4.0+) as Administrator
5. Run a scan. Report schema `1.3` should include `kernelEvidence` with `availability: available` (or `partial`); Advanced → Kernel tab should list BDFs
6. Pick a known BDF from the PCI tab; confirm `configVendorId` / `configDeviceId` match user-mode inventory
7. Confirm absence of driver still yields a clean scan with informational `KERNEL_EVIDENCE_UNAVAILABLE` and Kernel tab Unavailable summary (uninstall and rescan)

## Security notes

- Device SDDL: Administrators + SYSTEM only
- IOCTLs are METHOD_BUFFERED with explicit size checks
- Audit logs: operation name + BDF only (no config dumps)
- Unknown IOCTL → fail closed
- `IOCTL_IRONTRACE_SAFE_DEVICE_RESET` → `STATUS_NOT_SUPPORTED`

See [docs/architecture/DRIVER_BOUNDARY.md](../../docs/architecture/DRIVER_BOUNDARY.md) and [docs/architecture/DRIVER_SIGNING.md](../../docs/architecture/DRIVER_SIGNING.md).

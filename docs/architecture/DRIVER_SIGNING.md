# IronTrace.Driver production signing

Audience: operators preparing an end-user / production build of `IronTrace.Driver`.  
Lab path: stay on [test signing](../../src/IronTrace.Driver/README.md). Never for customers.  
Related: [DRIVER_BOUNDARY.md](DRIVER_BOUNDARY.md), [THREAT_MODEL.md](../security/THREAT_MODEL.md).

This document describes the intended production signing and attestation path. IronTrace does not automate certificate purchase, Partner Center submission, or HLK in CI.

## Lab vs production

| Environment | Signing | Secure Boot | `bcdedit testsigning` | Audience |
|-------------|---------|-------------|----------------------|----------|
| Lab / developer | Self-signed or test cert | Often off or with test mode | ON | Maintainers only |
| Production / end user | EV Authenticode + Microsoft attestation | ON | OFF | Customers / server admins |

Lab test-signed packages must never be redistributed as "the" IronTrace driver.

## Prerequisites

1. EV Code Signing certificate from a public CA that Microsoft trusts for kernel drivers (hardware-backed EV as required by current Windows policy).
2. Microsoft Partner Center account with access to the Hardware / Windows Hardware Compatibility Program (Hardware Dev Center) dashboards.
3. Tooling on a secure build machine:
   - Visual Studio + matching WDK
   - `Inf2Cat.exe` (WDK)
   - `signtool.exe` (Windows SDK)
   - Current Hardware Dev Center submission tooling / portal workflow (verify against Microsoft docs at release time)

## Build artifacts

From `src/IronTrace.Driver` (Release | x64):

1. `IronTrace.Driver.sys`
2. `IronTrace.Driver.inf` (ROOT software device `Root\IronTrace`)
3. Generate a catalog with Inf2Cat (paths vary by WDK install):

```bat
Inf2Cat.exe /driver:<PackageFolder> /os:10_X64
```

Expected package folder contents before attestation: `.sys`, `.inf`, `.cat` (IronTrace MVP has no co-installers).

## Authenticode sign (EV)

Sign both the driver binary and the catalog with the EV certificate and an RFC 3161 timestamp server (example host; use your CA's recommended URL):

```bat
signtool sign /v /fd sha256 /tr http://timestamp.digicert.com /td sha256 /sha1 <EV_CERT_THUMBPRINT> IronTrace.Driver.sys
signtool sign /v /fd sha256 /tr http://timestamp.digicert.com /td sha256 /sha1 <EV_CERT_THUMBPRINT> IronTrace.Driver.cat
```

Verify:

```bat
signtool verify /v /pa IronTrace.Driver.sys
signtool verify /v /pa IronTrace.Driver.cat
```

## Microsoft attestation / Hardware Dev Center

On modern Windows with Secure Boot and Memory Integrity (HVCI), a private EV signature alone is usually not enough for a kernel driver to load for end users. Microsoft expects an attestation (or WHQL) signature obtained through Hardware Dev Center.

High-level flow:

1. Create a hardware submission / driver package submission in Partner Center (Hardware).
2. Upload the signed package (INF + SYS + CAT).
3. Complete any required questionnaires / declarations for the driver type.
4. For ROOT / software (non-PnP hardware) devices, confirm the current Partner Center and HLK policy before release. Microsoft's accepted paths for Root-enumerated control devices change; do not assume desktop WHQL suites apply unchanged.
5. Download the attested/signed package Microsoft returns and use that package for customer distribution.

HLK: run only the suites Partner Center requires for your submission class. IronTrace does not vendor HLK projects in-repo; treat HLK as an operator release gate.

## Production install (client machines)

Target posture: Secure Boot enabled, test-signing disabled, prefer Memory Integrity enabled.

```bat
pnputil /add-driver IronTrace.Driver.inf /install
```

Confirm Device Manager → System devices → IronTrace Kernel Evidence Driver.

If the driver fails to load under HVCI / CI policy, IronTrace's usermode client already degrades: scan continues; `kernelEvidence` is Unavailable/Unsupported and treated as unknown, not suspicious.

## HVCI / code integrity

- Do not document or ship any bypass of Secure Boot, HVCI, or CI policy "for convenience" ([DRIVER_BOUNDARY.md](DRIVER_BOUNDARY.md)).
- Production drivers must be loadable under default enterprise-hardening expectations; otherwise omit the driver from that SKU and rely on user-mode inventory.

## What IronTrace will not do

- Disable Secure Boot or turn on test-signing for end users
- Ship unsigned or test-signed `.sys` in customer installers
- Provide a raw IOCTL playground or memory R/W tooling behind a signed driver
- Treat missing/failed driver load as a cheat signal

## Cross-links

- Lab build / checklist: [`src/IronTrace.Driver/README.md`](../../src/IronTrace.Driver/README.md)
- IOCTL surface: [DRIVER_BOUNDARY.md](DRIVER_BOUNDARY.md)
- Threat residuals (lab signing): [THREAT_MODEL.md](../security/THREAT_MODEL.md)

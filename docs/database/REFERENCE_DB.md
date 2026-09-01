# Reference Database

## Purpose

Offline identity / intel resolution without per-device network calls or API keys.

## Sources

| DB | Source | License path | Provider |
|----|--------|--------------|----------|
| `pci-reference.db` | [pci.ids](https://pci-ids.ucw.cz/) | BSD-3-Clause | `LocalPciIdsProvider` |
| `usb-reference.db` | [usb.ids](http://www.linux-usb.org/usb.ids) | Upstream notice | `LocalUsbIdsProvider` |
| `loldrivers-reference.db` | [LOLDrivers](https://www.loldrivers.io/) snapshot JSON | Apache-2.0 | `LocalLolDriversProvider` |

Attribution: see `THIRD_PARTY_NOTICES.md` and `data/reference/provenance*.json`.

## Pipeline

```text
source file (pci.ids | usb.ids | LOLDrivers JSON)
   → HardwareDbImporter --mode <pci|usb|loldrivers>
   → SQLite reference DB
   → HardwareDbImporter --mode sign-manifest (ECDSA P-256)
   → bundle / offline package
   → IReferenceUpdateService verify → %LocalAppData%\IronTrace\reference\
```

## Signed updates

- Algorithm: ECDSA P-256 + SHA-256 (IEEE P1363 signature), field `algorithm: ECDSA-P256-SHA256`
- Public key: `data/reference/trust/irontrace-ref.pub` (bundled). Private key is not shipped (`*.priv.pem` gitignored).
- Generate keys: `HardwareDbImporter --mode gen-keys --private-key ... --public-key ...`
- Sign package: put DBs in a folder, then
  `HardwareDbImporter --mode sign-manifest --package <dir> --private-key <priv.pem> --output <dir>/manifest.json`
- Client apply:
  - Drop package under `%LocalAppData%\IronTrace\reference\pending\` (manifest + DBs), or set `OfflinePackageDirectory`
  - Optional HTTPS: set `IronTrace:ReferenceUpdates:Enabled=true` + `ManifestUrl`
  - UI: Check reference updates (manual)
- Verify: signature → per-file SHA-256 → atomic replace with `.bak` rollback on failure

## Schema versions

- PCI / USB / LOLDrivers logical schema version = `1`

## Trust

Local DBs + signed manifests provide names and known-vulnerable-driver intel only. They are not authenticity proof or cheat verdicts.

# Third-Party Notices

IronTrace uses offline reference data and optional external tools from the projects below. Research notes under `docs/research/` are not vendored into this repo.

## pci.ids

[PCI ID Repository](https://pci-ids.ucw.cz/) ([GitHub mirror](https://github.com/pciutils/pciids)). Dual-licensed GPL-2.0-or-later or BSD-3-Clause; IronTrace redistributes under BSD-3-Clause. Aggregation and formatting copyright: Martin Mares, Albert Pool, and contributors.

Used for offline PCI vendor/device/subsystem/class names. Provenance: `data/reference/provenance.json`.

Redistribution in source or binary form is allowed if you keep the copyright notice, conditions, and disclaimer. Full text is in the upstream pci.ids header.

## usb.ids

[Linux USB ID Repository](http://www.linux-usb.org/usb.ids). Used for offline USB vendor/product name lookup (`usb-reference.db`). See `data/reference/provenance-usb.json` and the upstream file header.

## LOLDrivers

[LOLDrivers](https://www.loldrivers.io/) ([GitHub](https://github.com/magicsword-io/LOLDrivers)), Apache-2.0. Used as an offline known-vulnerable-driver catalog (hash and filename match only). No exploit code ships with IronTrace. Provenance: `data/reference/provenance-loldrivers.json`.

## pe-sieve / hollows_hunter (optional — not shipped)

IronTrace **does not bundle or redistribute** these tools. When the user explicitly opts in to memory scan (`IncludeMemoryScan`), IronTrace may invoke **hollows_hunter** as an external subprocess and parse its JSON stdout. No in-process memory APIs, no memory dumps in reports.

| Component | Upstream | License | Role |
|-----------|----------|---------|------|
| hollows_hunter | [hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | CLI wrapper; IronTrace runs `hollows_hunter64.exe` |
| pe-sieve | [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve) | BSD-2-Clause | DLL dependency (`pe-sieve64.dll`) shipped alongside hollows_hunter by upstream |

**You must download and install these binaries yourself** if you want memory scan. Typical layout:

```text
artifacts/tools/hollows_hunter64.exe
artifacts/tools/pe-sieve64.dll
```

(or `tools/` next to a published IronTrace executable). If the tool is missing, all other scan layers still run; the UI shows an availability notice.

Research note: [docs/research/pe-sieve-hollows-hunter.md](docs/research/pe-sieve-hollows-hunter.md).

BSD-2-Clause (summary): redistribution and use in source and binary forms are permitted with copyright notice, conditions, and disclaimer retained. Full license text is in each upstream repository (`LICENSE`).

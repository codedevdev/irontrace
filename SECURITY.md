# Security Policy

## Reporting

Found a security issue? Tell the maintainers privately. Do not file a public issue for an exploitable bug until a fix is out.

## In scope

- Client integrity and privacy bugs
- Tampering with reference databases
- API or auth flaws in the server

## Out of scope

"User-mode PCI IDs can be spoofed" is not a product bug by itself. Phase 1 treats that inventory as evidence, not proof. See the threat model for the full picture.

## Threat model

Details live in `docs/security/THREAT_MODEL.md`.

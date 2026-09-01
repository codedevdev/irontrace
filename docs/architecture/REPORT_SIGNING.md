# Report signing and attestation design (not implemented)

Status: design only. IronTrace 0.5.1 does not ship TPM-backed report signatures or an "Attested" UI.

## Today (implemented)

| Mechanism | What it proves |
|-----------|----------------|
| Local JSON export | Nothing cryptographic. The machine owner can edit the file. |
| Server upload | API key possession + single-use challenge nonce + HMAC-SHA256 over body hash |
| Measured Boot evidence | Best-effort PCR 0-7 snapshot (schema `measuredBootEvidence`) when TBS works |

PCR digests are platform fingerprints, not a signature of the scan JSON.

## Future options (research)

1. HMAC (current server path). Continues to bind upload to a challenge; admin trust is key hygiene + human review.
2. TPM quote over report hash. Client hashes canonical report bytes, obtains a TPM2_Quote over a PCR selection + nonce from the server; server verifies quote against a known AK. Requires enrollment, AK certs, and careful privacy review.
3. Secure Boot / Measured Boot log export. Attach TCG event log for offline comparison. Still not "report attested" unless bound to a quote.

## What "attested" would require

- Explicit UX that distinguishes evidence collected vs cryptographically verified by IronTrace.Server
- Key/AK provisioning and revocation
- Nonce freshness (already partially present for uploads)
- No fake stubs: do not label UI "Attested" until verification succeeds server-side

## Non-goals

- Requiring TPM for user-mode scans
- Auto-ban on missing PCR / quote failure
- Shipping incomplete attestation as production trust

## Related

- [tss-msr.md](../research/tss-msr.md), [attestation-client-samples.md](../research/attestation-client-samples.md)
- [THREAT_MODEL.md](../security/THREAT_MODEL.md), [PRIVACY.md](../security/PRIVACY.md)

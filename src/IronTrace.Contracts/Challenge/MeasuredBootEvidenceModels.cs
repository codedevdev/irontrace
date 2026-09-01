using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Challenge;

public sealed record PcrDigestEntry(
    int Index,
    string DigestHex);

/// <summary>
/// Best-effort Measured Boot / TPM PCR snapshot. Absence is unknown, not suspicious.
/// Does not imply the report is cryptographically attested.
/// </summary>
public sealed record MeasuredBootEvidenceSnapshot(
    CapabilityStatus Availability,
    bool? TpmPresent,
    string? TpmSpecVersion,
    string? PcrBank,
    IReadOnlyList<PcrDigestEntry> Pcrs,
    string? Detail);

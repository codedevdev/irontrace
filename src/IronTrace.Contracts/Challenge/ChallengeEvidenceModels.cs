using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Challenge;

/// <summary>
/// Policy outcome for a potential safe device challenge. Execution is never automatic.
/// </summary>
public enum ChallengePolicyDecision
{
    /// <summary>Critical class (storage/GPU/bridge/NIC/USB host) — never challenge.</summary>
    DenyCritical = 0,

    /// <summary>Not on allow-list — default deny.</summary>
    DenyDefault = 1,

    /// <summary>On narrow allow-list; eligible for a future challenge — not executed in Phase 5 MVP.</summary>
    AllowListedEligible = 2,

    /// <summary>Insufficient identity to classify (e.g. missing class code).</summary>
    Unsupported = 3
}

public sealed record ChallengeDeviceDecision(
    int? Bus,
    int? Device,
    int? Function,
    byte? ClassCode,
    byte? Subclass,
    ChallengePolicyDecision Decision,
    string Reason,
    bool? SupportsFlr);

public sealed record ChallengeEvidenceSnapshot(
    CapabilityStatus Availability,
    string? Detail,
    IReadOnlyList<ChallengeDeviceDecision> Decisions);

using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Challenge;

/// <summary>
/// SPDM stack integration status. Phase 5 MVP never runs libspdm.
/// </summary>
public enum SpdmStackStatus
{
    NotIntegrated = 0,
    Unsupported = 1,
    Unknown = 2
}

public sealed record SpdmDeviceEvidence(
    int? Bus,
    int? Device,
    int? Function,
    bool DoePresent,
    SpdmStackStatus SpdmStackStatus,
    string? Detail);

/// <summary>
/// Detection-only SPDM/DOE evidence. Unsupported when no DOE capability was observed.
/// </summary>
public sealed record SpdmEvidenceSnapshot(
    CapabilityStatus Availability,
    string? Detail,
    IReadOnlyList<SpdmDeviceEvidence> Devices);

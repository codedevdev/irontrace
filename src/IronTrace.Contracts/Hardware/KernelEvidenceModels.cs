using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Hardware;

public enum KernelDriverAvailability
{
    Unavailable = 0,
    Unsupported = 1,
    Partial = 2,
    Available = 3
}

public sealed record KernelPciCapability(
    ushort CapabilityId,
    ushort Offset,
    bool IsExtended);

public sealed record KernelPciBar(
    byte Index,
    string BarType,
    ulong? BaseAddress,
    ulong? Size);

public sealed record KernelPciExpressCaps(
    bool HasPcie,
    bool HasAer,
    bool HasAcs,
    bool HasAts,
    bool HasSriov,
    bool SupportsFlr,
    ushort? DeviceControl,
    ushort? LinkStatus,
    byte? MaxPayloadSupported,
    byte? MaxReadRequest);

/// <summary>
/// Structured kernel PCI evidence for one BDF. Config bytes are omitted from reports
/// in favor of identity fields derived from a bounded header read.
/// </summary>
public sealed record KernelPciDeviceEvidence(
    string? InstanceId,
    int Bus,
    int Device,
    int Function,
    ushort? ConfigVendorId,
    ushort? ConfigDeviceId,
    byte? ConfigRevision,
    byte? ConfigClassCode,
    byte? ConfigSubclass,
    byte? ConfigProgIf,
    IReadOnlyList<KernelPciCapability> Capabilities,
    IReadOnlyList<KernelPciBar> Bars,
    KernelPciExpressCaps? Express,
    IReadOnlyList<string> Notes,
    string? DeviceSerialNumberHex = null);

public sealed record KernelEvidenceSnapshot(
    KernelDriverAvailability Availability,
    CapabilityStatus RuntimeCapabilityStatus,
    uint? ProtocolVersion,
    uint? CapabilityFlags,
    uint? MaxConfigReadLength,
    string? Detail,
    IReadOnlyList<KernelPciDeviceEvidence> Devices);

using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Contracts.Reference;

public interface IHardwareReferenceProvider
{
    string Name { get; }

    Task<ResolvedIdentity?> ResolveAsync(PciDeviceIdentity identity, CancellationToken cancellationToken);

    Task<string?> FindVendorNameAsync(ushort vendorId, CancellationToken cancellationToken);

    Task<string?> FindDeviceNameAsync(ushort vendorId, ushort deviceId, CancellationToken cancellationToken);

    Task<string?> FindSubsystemNameAsync(
        ushort vendorId,
        ushort deviceId,
        ushort subsystemVendorId,
        ushort subsystemDeviceId,
        CancellationToken cancellationToken);

    Task<string?> FindClassNameAsync(
        byte classCode,
        byte? subclass,
        byte? programmingInterface,
        CancellationToken cancellationToken);

    Task<ReferenceDbInfo?> GetInfoAsync(CancellationToken cancellationToken);
}

public sealed record ReferenceDbInfo(
    int SchemaVersion,
    string SourceName,
    string? SourceUrl,
    string? License,
    DateTimeOffset? RetrievedAt,
    string? ContentHash,
    string DatabasePath);

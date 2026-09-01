using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Hardware;

public sealed record PciDeviceIdentity(
    ushort VendorId,
    ushort DeviceId,
    ushort? SubsystemVendorId,
    ushort? SubsystemDeviceId,
    byte? Revision,
    byte? ClassCode,
    byte? Subclass,
    byte? ProgrammingInterface);

public sealed record DriverSignatureInfo(
    DriverSignatureStatus Status,
    string? SignerSubject,
    string? SignerIssuer,
    string? Thumbprint,
    string? SigningAlgorithm,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    string? CatalogOrFilePath,
    string AnalysisSummary,
    string? TechnicalDetail);

public sealed record DriverInfo(
    string? Service,
    string? DriverName,
    string? Version,
    string? Provider,
    string? Date,
    string? SigningState,
    string? InfPath = null,
    string? ImagePath = null,
    DriverSignatureInfo? Signature = null);

public sealed record ResolvedIdentity(
    string? VendorName,
    string? DeviceName,
    string? SubsystemName,
    string? ClassName,
    string Source,
    DateTimeOffset? RetrievedAt,
    FindingConfidence Confidence);

public sealed record PciDevice(
    string InstanceId,
    PciDeviceIdentity Identity,
    string? FriendlyName,
    string? Description,
    string? Manufacturer,
    string? LocationInformation,
    int? Bus,
    int? DeviceNumber,
    int? Function,
    string? ParentInstanceId,
    DriverInfo? Driver,
    ResolvedIdentity? Resolved,
    DeviceKind Kind,
    IReadOnlyList<string> HardwareIds,
    IReadOnlyList<string> CompatibleIds);

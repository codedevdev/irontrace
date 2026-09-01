using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Hardware;

public sealed record UsbDeviceIdentity(
    ushort VendorId,
    ushort ProductId,
    ushort? DeviceRelease);

public sealed record UsbResolvedIdentity(
    string? VendorName,
    string? ProductName,
    string Source,
    DateTimeOffset? RetrievedAt,
    FindingConfidence Confidence);

public sealed record UsbDevice(
    string InstanceId,
    UsbDeviceIdentity Identity,
    string? FriendlyName,
    string? Description,
    string? Manufacturer,
    string? Service,
    DriverInfo? Driver,
    UsbResolvedIdentity? Resolved,
    IReadOnlyList<string> HardwareIds,
    DeviceKind Kind = DeviceKind.Physical,
    string? KindReason = null);

public sealed record InventoriedDriver(
    string? ServiceName,
    string? DisplayName,
    string? ImagePath,
    string? Sha256,
    string? FileName,
    DriverSignatureInfo? Signature,
    string Source);

public sealed record VulnerableDriverMatch(
    string MatchKind,
    FindingConfidence Confidence,
    string? DriverFileName,
    string? DriverSha256,
    string? LolDriversId,
    string? Title,
    string? Category,
    string? Evidence,
    string? RelatedPath);

public sealed record IdentityCheckResult(
    string Code,
    bool IsAnomaly,
    FindingConfidence Confidence,
    string Title,
    string Explanation,
    string Evidence);

public sealed record IdentityConsistencyReport(
    string? SystemUuidNormalized,
    bool SystemUuidLooksPlaceholder,
    bool BoardSerialLooksPlaceholder,
    IReadOnlyList<IdentityCheckResult> Checks);

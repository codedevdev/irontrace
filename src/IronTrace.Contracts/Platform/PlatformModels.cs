using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Platform;

public sealed record OperatingSystemInfo(
    string ProductName,
    string Version,
    string BuildNumber,
    string DisplayVersion,
    string Architecture,
    string? InstallationType,
    string? EditionId);

public sealed record SecurityFeatureStatus(
    string Name,
    SecurityFeatureState State,
    string? Detail);

public sealed record PlatformSecurityState(
    SecurityFeatureStatus SecureBoot,
    SecurityFeatureStatus Tpm,
    SecurityFeatureStatus VirtualizationBasedSecurity,
    SecurityFeatureStatus MemoryIntegrity,
    SecurityFeatureStatus KernelDmaProtection,
    SecurityFeatureStatus Virtualization,
    bool? RanElevated,
    IReadOnlyList<string> Notes);

public sealed record MotherboardInfo(
    string? Manufacturer,
    string? Product,
    string? Version,
    string? SerialRaw,
    string? SerialHash,
    SerialHandling SerialHandling,
    string? BiosVendor,
    string? BiosVersion,
    string? BiosReleaseDate,
    string? FirmwareType);

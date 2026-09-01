namespace IronTrace.Contracts.Reporting;

public sealed record ExportPrivacyOptions(
    bool IncludeSerialHash = true,
    bool IncludeDriverImagePaths = true,
    bool IncludeCodeIntegrityEvents = true,
    bool IncludeInstanceIds = true,
    bool IncludeRawSerial = false,
    bool IncludePcrDigests = true)
{
    public static ExportPrivacyOptions Default { get; } = new();
}

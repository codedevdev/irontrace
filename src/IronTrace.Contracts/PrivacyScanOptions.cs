namespace IronTrace.Contracts;

/// <summary>Privacy-sensitive scan options. Defaults are off.</summary>
public sealed class PrivacyScanOptions
{
    public const string SectionName = "IronTrace:Privacy";

    /// <summary>
    /// When true, scan Enum\PCI for historical watchlist identities not on the current bus.
    /// Off by default — privacy-gated.
    /// </summary>
    public bool IncludePnpDeviceHistory { get; set; }
}

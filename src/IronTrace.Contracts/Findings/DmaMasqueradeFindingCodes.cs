namespace IronTrace.Contracts.Findings;

/// <summary>
/// Finding codes used for DMA CFW masquerade review (evidence only — never auto-ban).
/// </summary>
public static class DmaMasqueradeFindingCodes
{
    public const string StockPcileechIdentity = "STOCK_PCILEECH_IDENTITY";
    public const string DmaWatchlistHit = "DMA_WATCHLIST_HIT";
    public const string PcileechDefaultCapLayout = "PCILEECH_DEFAULT_CAP_LAYOUT";
    public const string DonorIdentityDriverMismatch = "DONOR_IDENTITY_DRIVER_MISMATCH";
    public const string DuplicatePciIdentity = "DUPLICATE_PCI_IDENTITY";
    public const string KernelPciIdentityMismatch = "KERNEL_PCI_IDENTITY_MISMATCH";
    public const string KernelPciClassMismatch = "KERNEL_PCI_CLASS_MISMATCH";
    public const string PciBarShapeAnomaly = "PCI_BAR_SHAPE_ANOMALY";
    public const string PciDsnWeakSignal = "PCI_DSN_WEAK_SIGNAL";
    public const string DmaSignalCluster = "DMA_SIGNAL_CLUSTER";
    public const string PnpHistoryWatchlistHit = "PNP_HISTORY_WATCHLIST_HIT";

    public static readonly HashSet<string> All = new(StringComparer.OrdinalIgnoreCase)
    {
        StockPcileechIdentity,
        DmaWatchlistHit,
        PcileechDefaultCapLayout,
        DonorIdentityDriverMismatch,
        DuplicatePciIdentity,
        KernelPciIdentityMismatch,
        KernelPciClassMismatch,
        PciBarShapeAnomaly,
        PciDsnWeakSignal,
        DmaSignalCluster,
        PnpHistoryWatchlistHit
    };

    /// <summary>Codes that count toward multi-signal clustering on a device (excludes cluster itself).</summary>
    public static readonly HashSet<string> ClusterSources = new(StringComparer.OrdinalIgnoreCase)
    {
        StockPcileechIdentity,
        DmaWatchlistHit,
        PcileechDefaultCapLayout,
        DonorIdentityDriverMismatch,
        DuplicatePciIdentity,
        KernelPciIdentityMismatch,
        KernelPciClassMismatch,
        PciBarShapeAnomaly,
        PciDsnWeakSignal,
        PnpHistoryWatchlistHit
    };

    public static bool IsDmaRelated(string? code)
        => !string.IsNullOrEmpty(code) && All.Contains(code);

    public static string? TriageHintFor(string code) => code switch
    {
        StockPcileechIdentity =>
            "Admin: compare with a known-clean machine; lab Xilinx/Squirrel boards can match. Do not auto-ban.",
        DmaWatchlistHit =>
            "Admin: device matched the local DMA identity watchlist. Correlate with caps/BARs; do not auto-ban.",
        PcileechDefaultCapLayout =>
            "Admin: correlate with stock VID/DID and BAR shape; custom CFW often relocates caps. Review only.",
        DonorIdentityDriverMismatch =>
            "Admin: check Device Manager errors; broken installs and partial dump-emu look similar. Do not auto-ban.",
        DuplicatePciIdentity =>
            "Admin: confirm multi-function/multi-slot vs cloned donor identity. Do not auto-ban.",
        KernelPciIdentityMismatch =>
            "Admin: re-scan elevated with driver; UM↔config mismatch is review evidence, not proof of cheating.",
        KernelPciClassMismatch =>
            "Admin: class/subclass disagree between PnP and config space — check shadow/spoof. Review only.",
        PciBarShapeAnomaly =>
            "Admin: BAR layout vs claimed class is a weak signal; many legitimate devices vary. Do not auto-ban.",
        PciDsnWeakSignal =>
            "Admin: DSN zero/collision/stock pairing is weak alone. Correlate with other DMA signals; do not auto-ban.",
        DmaSignalCluster =>
            "Admin: multiple DMA/CFW signals on one device — prioritize human review; still not an auto-ban.",
        PnpHistoryWatchlistHit =>
            "Admin: historical PnP entry for a watchlisted identity is absent from the current bus. Privacy-sensitive; do not auto-ban.",
        _ => null
    };
}

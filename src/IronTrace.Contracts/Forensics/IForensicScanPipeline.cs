using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Scanning;

namespace IronTrace.Contracts.Forensics;

public interface IForensicScanPipeline
{
    Task<ForensicEvidenceSnapshot?> CollectAsync(
        ScanOptions options,
        IReadOnlyList<InventoriedDriver> drivers,
        MotherboardInfo? board,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken);
}

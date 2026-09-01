using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Hardware;

public sealed record PnPHistoryHit(
    string InstanceId,
    ushort VendorId,
    ushort DeviceId,
    string? FriendlyName,
    bool PresentOnBus);

public sealed record PnPHistorySnapshot(
    CapabilityStatus Availability,
    bool OptInEnabled,
    string? Detail,
    IReadOnlyList<PnPHistoryHit> WatchlistHitsNotOnBus);

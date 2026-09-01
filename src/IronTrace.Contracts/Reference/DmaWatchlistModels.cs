using IronTrace.Contracts.Hardware;

namespace IronTrace.Contracts.Reference;

public sealed record DmaWatchlistEntry(
    ushort VendorId,
    ushort DeviceId,
    ushort? SubsystemVendorId,
    ushort? SubsystemDeviceId,
    string Label,
    string Severity,
    string? Notes);

public sealed record DmaWatchlistDocument(
    int SchemaVersion,
    string? Description,
    IReadOnlyList<DmaWatchlistEntry> Entries);

public interface IDmaWatchlistProvider
{
    IReadOnlyList<DmaWatchlistEntry> Entries { get; }

    bool TryMatch(PciDeviceIdentity identity, out DmaWatchlistEntry match);
}

public static class DmaWatchlistMatching
{
    public static bool Matches(
        DmaWatchlistEntry entry,
        ushort vendorId,
        ushort deviceId,
        ushort? subVen,
        ushort? subDev)
    {
        if (entry.VendorId != vendorId || entry.DeviceId != deviceId)
            return false;

        if (entry.SubsystemVendorId is null && entry.SubsystemDeviceId is null)
            return true;

        return entry.SubsystemVendorId == subVen && entry.SubsystemDeviceId == subDev;
    }
}

using System.Globalization;
using System.Text.RegularExpressions;
using IronTrace.Contracts;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Reference;
using IronTrace.Core.Scanning;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Windows.Collectors;

/// <summary>
/// Privacy-gated historical PnP PCI enum scan for watchlisted identities not on the current bus.
/// </summary>
public sealed class PnPHistoryCollector : IPnPHistoryCollector
{
    private static readonly Regex VenDevRegex = new(
        @"VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly PrivacyScanOptions _privacy;
    private readonly IDmaWatchlistProvider _watchlist;
    private readonly ILogger<PnPHistoryCollector> _logger;

    public PnPHistoryCollector(
        PrivacyScanOptions privacy,
        IDmaWatchlistProvider watchlist,
        ILogger<PnPHistoryCollector> logger)
    {
        _privacy = privacy;
        _watchlist = watchlist;
        _logger = logger;
    }

    public Task<PnPHistorySnapshot> CollectAsync(
        IReadOnlyList<PciDevice> currentPci,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_privacy.IncludePnpDeviceHistory)
        {
            return Task.FromResult(new PnPHistorySnapshot(
                CapabilityStatus.Unsupported,
                OptInEnabled: false,
                "PnP device history collection is off (privacy default). Enable IronTrace:Privacy:IncludePnpDeviceHistory to opt in.",
                Array.Empty<PnPHistoryHit>()));
        }

        try
        {
            var presentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in currentPci)
            {
                presentKeys.Add($"{d.Identity.VendorId:X4}:{d.Identity.DeviceId:X4}");
                presentKeys.Add(d.InstanceId);
            }

            var hits = new List<PnPHistoryHit>();
            using var pciRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
            if (pciRoot is null)
            {
                return Task.FromResult(new PnPHistorySnapshot(
                    CapabilityStatus.Unknown,
                    OptInEnabled: true,
                    "PCI Enum registry key unavailable.",
                    Array.Empty<PnPHistoryHit>()));
            }

            foreach (var deviceKeyName in pciRoot.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var m = VenDevRegex.Match(deviceKeyName);
                if (!m.Success)
                    continue;

                if (!ushort.TryParse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var ven) ||
                    !ushort.TryParse(m.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var dev))
                {
                    continue;
                }

                var identity = new PciDeviceIdentity(ven, dev, null, null, null, null, null, null);
                if (!_watchlist.TryMatch(identity, out var entry))
                    continue;

                using var deviceKey = pciRoot.OpenSubKey(deviceKeyName);
                if (deviceKey is null)
                    continue;

                foreach (var instanceName in deviceKey.GetSubKeyNames())
                {
                    var instanceId = $@"PCI\{deviceKeyName}\{instanceName}";
                    if (presentKeys.Contains(instanceId) ||
                        presentKeys.Contains($"{ven:X4}:{dev:X4}"))
                    {
                        // Still on bus (by instance or VID:DID) — skip historical-only signal.
                        // If VID:DID is present on bus, any historical instance of same ID is weaker;
                        // only report when that VID:DID is NOT on the current physical inventory.
                        continue;
                    }

                    string? friendly = null;
                    using (var inst = deviceKey.OpenSubKey(instanceName))
                    {
                        friendly = inst?.GetValue("FriendlyName") as string
                                   ?? inst?.GetValue("DeviceDesc") as string;
                    }

                    hits.Add(new PnPHistoryHit(
                        instanceId,
                        ven,
                        dev,
                        friendly,
                        PresentOnBus: false));

                    _logger.LogDebug(
                        "PnP history watchlist hit (not on bus): {Instance} ({Label})",
                        instanceId,
                        entry.Label);
                }
            }

            // Re-filter: only keep hits whose VID:DID truly absent from current bus.
            var busIds = currentPci
                .Where(d => d.Kind != DeviceKind.VirtualOrSoftware)
                .Select(d => $"{d.Identity.VendorId:X4}:{d.Identity.DeviceId:X4}")
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            hits = hits
                .Where(h => !busIds.Contains($"{h.VendorId:X4}:{h.DeviceId:X4}"))
                .GroupBy(h => $"{h.VendorId:X4}:{h.DeviceId:X4}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();

            return Task.FromResult(new PnPHistorySnapshot(
                hits.Count > 0 ? CapabilityStatus.Partial : CapabilityStatus.Supported,
                OptInEnabled: true,
                hits.Count > 0
                    ? $"Found {hits.Count} watchlisted historical PCI identity(ies) not on the current bus."
                    : "PnP history scanned; no watchlisted historical identities missing from the bus.",
                hits));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PnP history collection failed");
            return Task.FromResult(new PnPHistorySnapshot(
                CapabilityStatus.Unknown,
                OptInEnabled: true,
                "PnP history collection failed. Unknown, not suspicious.",
                Array.Empty<PnPHistoryHit>()));
        }
    }
}

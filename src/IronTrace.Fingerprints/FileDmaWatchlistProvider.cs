using System.Globalization;
using System.Text.Json;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Reference;
using Microsoft.Extensions.Logging;

namespace IronTrace.Fingerprints;

public sealed class FileDmaWatchlistProvider : IDmaWatchlistProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private readonly IReadOnlyList<DmaWatchlistEntry> _entries;
    private readonly ILogger<FileDmaWatchlistProvider> _logger;

    public FileDmaWatchlistProvider(string path, ILogger<FileDmaWatchlistProvider> logger)
    {
        _logger = logger;
        _entries = Load(path);
    }

    /// <summary>Fallback when no file is available — stock PCILeech identity only.</summary>
    public FileDmaWatchlistProvider(ILogger<FileDmaWatchlistProvider> logger)
    {
        _logger = logger;
        _entries = BuiltInStock();
        _logger.LogDebug("Using built-in DMA watchlist (stock 10EE:0666 only).");
    }

    public IReadOnlyList<DmaWatchlistEntry> Entries => _entries;

    public bool TryMatch(PciDeviceIdentity identity, out DmaWatchlistEntry match)
    {
        foreach (var entry in _entries)
        {
            if (DmaWatchlistMatching.Matches(
                    entry,
                    identity.VendorId,
                    identity.DeviceId,
                    identity.SubsystemVendorId,
                    identity.SubsystemDeviceId))
            {
                match = entry;
                return true;
            }
        }

        match = null!;
        return false;
    }

    private IReadOnlyList<DmaWatchlistEntry> Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                _logger.LogWarning("DMA watchlist not found at {Path}; using built-in stock entry.", path);
                return BuiltInStock();
            }

            var json = File.ReadAllText(path);
            var dto = JsonSerializer.Deserialize<WatchlistFileDto>(json, JsonOptions);
            if (dto?.Entries is null || dto.Entries.Count == 0)
            {
                _logger.LogWarning("DMA watchlist empty at {Path}; using built-in stock entry.", path);
                return BuiltInStock();
            }

            var list = new List<DmaWatchlistEntry>();
            foreach (var e in dto.Entries)
            {
                if (!TryParseHexUshort(e.VendorId, out var ven) ||
                    !TryParseHexUshort(e.DeviceId, out var dev))
                {
                    continue;
                }

                ushort? subVen = null, subDev = null;
                if (!string.IsNullOrWhiteSpace(e.SubsystemVendorId) &&
                    TryParseHexUshort(e.SubsystemVendorId, out var sv))
                {
                    subVen = sv;
                }

                if (!string.IsNullOrWhiteSpace(e.SubsystemDeviceId) &&
                    TryParseHexUshort(e.SubsystemDeviceId, out var sd))
                {
                    subDev = sd;
                }

                list.Add(new DmaWatchlistEntry(
                    ven,
                    dev,
                    subVen,
                    subDev,
                    e.Label ?? $"VEN_{ven:X4}&DEV_{dev:X4}",
                    e.Severity ?? "stock",
                    e.Notes));
            }

            if (list.Count == 0)
            {
                _logger.LogWarning("DMA watchlist had no valid entries; using built-in stock entry.");
                return BuiltInStock();
            }

            _logger.LogInformation("Loaded DMA watchlist with {Count} entries from {Path}", list.Count, path);
            return list;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load DMA watchlist from {Path}", path);
            return BuiltInStock();
        }
    }

    private static IReadOnlyList<DmaWatchlistEntry> BuiltInStock()
        =>
        [
            new DmaWatchlistEntry(
                0x10EE,
                0x0666,
                null,
                null,
                "Stock PCILeech / Squirrel-class FPGA",
                "stock",
                "Built-in fallback when dma-watchlist.json is missing.")
        ];

    private static bool TryParseHexUshort(string? text, out ushort value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ushort.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private sealed class WatchlistFileDto
    {
        public int SchemaVersion { get; set; }
        public string? Description { get; set; }
        public List<WatchlistEntryDto>? Entries { get; set; }
    }

    private sealed class WatchlistEntryDto
    {
        public string? VendorId { get; set; }
        public string? DeviceId { get; set; }
        public string? SubsystemVendorId { get; set; }
        public string? SubsystemDeviceId { get; set; }
        public string? Label { get; set; }
        public string? Severity { get; set; }
        public string? Notes { get; set; }
    }
}

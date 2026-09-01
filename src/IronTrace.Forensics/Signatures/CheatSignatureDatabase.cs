using System.Text.Json;
using IronTrace.Contracts.Enums;
using Microsoft.Extensions.Logging;

namespace IronTrace.Forensics.Signatures;

public sealed record CheatSignatureCategory(
    string Name,
    FindingSeverity DefaultSeverity,
    FindingSeverity? BrandSeverity,
    IReadOnlyList<string> Keywords);

public sealed record CheatSignatureDatabase(
    int SchemaVersion,
    int RecencyDecayDays,
    IReadOnlyList<CheatSignatureCategory> Categories,
    IReadOnlyList<string> VendorAllowlist,
    IReadOnlyList<string> KnownGameProcesses);

public interface ICheatSignatureProvider
{
    CheatSignatureDatabase Database { get; }
}

public sealed class FileCheatSignatureProvider : ICheatSignatureProvider
{
    private readonly ILogger<FileCheatSignatureProvider> _logger;

    public CheatSignatureDatabase Database { get; }

    public FileCheatSignatureProvider(string path, ILogger<FileCheatSignatureProvider> logger)
    {
        _logger = logger;
        Database = Load(path);
    }

    public FileCheatSignatureProvider(ILogger<FileCheatSignatureProvider> logger)
        : this(FindDefaultPath(), logger)
    {
    }

    private CheatSignatureDatabase Load(string path)
    {
        if (!File.Exists(path))
        {
            _logger.LogWarning("Cheat signatures file not found at {Path}; using empty database", path);
            return Empty();
        }

        try
        {
            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var recency = root.TryGetProperty("recencyDecayDays", out var rd) ? rd.GetInt32() : 180;
            var schema = root.TryGetProperty("schemaVersion", out var sv) ? sv.GetInt32() : 1;
            var categories = new List<CheatSignatureCategory>();

            if (root.TryGetProperty("categories", out var cats))
            {
                foreach (var prop in cats.EnumerateObject())
                {
                    var defSev = ParseSeverity(prop.Value, "defaultSeverity", FindingSeverity.Medium);
                    FindingSeverity? brandSev = prop.Value.TryGetProperty("brandSeverity", out var bs)
                        ? ParseSeverity(bs)
                        : null;
                    var keywords = prop.Value.TryGetProperty("keywords", out var kw)
                        ? kw.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToList()
                        : [];
                    categories.Add(new CheatSignatureCategory(prop.Name, defSev, brandSev, keywords));
                }
            }

            var allowlist = ReadStringArray(root, "vendorAllowlist");
            var games = ReadStringArray(root, "knownGameProcesses");
            return new CheatSignatureDatabase(schema, recency, categories, allowlist, games);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load cheat signatures from {Path}", path);
            return Empty();
        }
    }

    private static CheatSignatureDatabase Empty()
        => new(1, 180, [], [], []);

    private static IReadOnlyList<string> ReadStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var arr))
            return [];
        return arr.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToList();
    }

    private static FindingSeverity ParseSeverity(JsonElement parent, string name, FindingSeverity fallback)
        => parent.TryGetProperty(name, out var el) ? ParseSeverity(el) : fallback;

    private static FindingSeverity ParseSeverity(JsonElement el) => el.GetString()?.ToLowerInvariant() switch
    {
        "information" or "info" => FindingSeverity.Information,
        "low" => FindingSeverity.Low,
        "medium" => FindingSeverity.Medium,
        "high" => FindingSeverity.High,
        "critical" => FindingSeverity.Critical,
        _ => FindingSeverity.Medium
    };

    private static string FindDefaultPath()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "IronTrace", "reference", "cheat-signatures.json"),
            Path.Combine(AppContext.BaseDirectory, "reference", "cheat-signatures.json"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "data", "reference", "cheat-signatures.json"))
        };
        return candidates.FirstOrDefault(File.Exists) ?? candidates[^1];
    }
}

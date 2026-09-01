using System.Collections.Frozen;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Forensics;

namespace IronTrace.Forensics.Signatures;

public interface ISignatureMatcher
{
    IReadOnlyList<SignatureMatchHit> Match(string text, string source, DateTimeOffset? lastSeenUtc = null);

    IReadOnlyList<SignatureMatchHit> MatchFileName(string fileName, string source, DateTimeOffset? lastSeenUtc = null);

    bool IsDualUseCategory(string category);

    bool IsOnVendorAllowlist(string text);

    int RecencyDecayDays { get; }
}

public sealed class SignatureMatcher : ISignatureMatcher
{
    private readonly CheatSignatureDatabase _db;
    private readonly FrozenDictionary<string, (string Category, string Keyword, FindingSeverity Sev)> _index;

    public SignatureMatcher(ICheatSignatureProvider provider)
    {
        _db = provider.Database;
        var map = new Dictionary<string, (string, string, FindingSeverity)>(StringComparer.OrdinalIgnoreCase);
        foreach (var cat in _db.Categories)
        {
            foreach (var kw in cat.Keywords)
            {
                var normalized = Normalize(kw);
                if (normalized.Length == 0)
                    continue;
                var sev = cat.Name.Equals("cheat_brands", StringComparison.OrdinalIgnoreCase) && cat.BrandSeverity.HasValue
                    ? cat.BrandSeverity.Value
                    : cat.DefaultSeverity;
                map.TryAdd(normalized, (cat.Name, kw, sev));
            }
        }

        _index = map.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    public int RecencyDecayDays => _db.RecencyDecayDays;

    public bool IsDualUseCategory(string category)
        => category.Equals("dual_use_tools", StringComparison.OrdinalIgnoreCase);

    public bool IsOnVendorAllowlist(string text)
    {
        var lower = text.ToLowerInvariant();
        return _db.VendorAllowlist.Any(v => lower.Contains(v, StringComparison.OrdinalIgnoreCase));
    }

    public IReadOnlyList<SignatureMatchHit> MatchFileName(string fileName, string source, DateTimeOffset? lastSeenUtc = null)
        => Match(fileName, source, lastSeenUtc);

    public IReadOnlyList<SignatureMatchHit> Match(string text, string source, DateTimeOffset? lastSeenUtc = null)
    {
        if (string.IsNullOrWhiteSpace(text))
            return [];

        var lower = text.ToLowerInvariant();
        var hits = new List<SignatureMatchHit>();
        foreach (var (key, (category, keyword, sev)) in _index)
        {
            if (!lower.Contains(key, StringComparison.OrdinalIgnoreCase))
                continue;

            var (effective, demoted) = ApplyRecency(sev, lastSeenUtc);
            hits.Add(new SignatureMatchHit(
                category,
                keyword,
                text,
                source,
                sev,
                effective,
                lastSeenUtc,
                lastSeenUtc.HasValue ? (int?)(DateTimeOffset.UtcNow - lastSeenUtc.Value).TotalDays : null,
                demoted));
        }

        return hits;
    }

    private (FindingSeverity Effective, bool Demoted) ApplyRecency(FindingSeverity original, DateTimeOffset? lastSeenUtc)
    {
        if (!lastSeenUtc.HasValue)
            return (original, false);

        var ageDays = (DateTimeOffset.UtcNow - lastSeenUtc.Value).TotalDays;
        if (ageDays <= _db.RecencyDecayDays)
            return (original, false);

        var demoted = original switch
        {
            FindingSeverity.High => FindingSeverity.Medium,
            FindingSeverity.Medium => FindingSeverity.Information,
            FindingSeverity.Critical => FindingSeverity.High,
            _ => original
        };
        return (demoted, demoted != original);
    }

    private static string Normalize(string s) => s.Trim().ToLowerInvariant();
}

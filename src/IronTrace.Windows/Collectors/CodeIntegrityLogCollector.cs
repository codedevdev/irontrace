using System.Diagnostics.Eventing.Reader;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Reference;
using IronTrace.Core.Scanning;
using Microsoft.Extensions.Logging;

namespace IronTrace.Windows.Collectors;

public sealed class CodeIntegrityLogCollector : ICodeIntegrityLogCollector
{
    private static readonly int[] WatchedIds = [3004, 3033, 3076, 3077];
    private readonly ILogger<CodeIntegrityLogCollector> _logger;
    private readonly ElevatedSecurityOptions _elevatedOptions;

    public CodeIntegrityLogCollector(
        ILogger<CodeIntegrityLogCollector> logger,
        ElevatedSecurityOptions? elevatedOptions = null)
    {
        _logger = logger;
        _elevatedOptions = elevatedOptions ?? new ElevatedSecurityOptions();
    }

    public Task<CodeIntegrityLogSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var elevated = IsElevated();
        var deep = elevated &&
                   string.Equals(_elevatedOptions.Mode, "WhenElevated", StringComparison.OrdinalIgnoreCase);
        var lookbackDays = deep
            ? Math.Clamp(_elevatedOptions.ElevatedCiLookbackDays, 1, 90)
            : Math.Clamp(_elevatedOptions.StandardCiLookbackDays, 1, 90);
        var maxEvents = deep
            ? Math.Clamp(_elevatedOptions.ElevatedCiMaxEvents, 10, 500)
            : Math.Clamp(_elevatedOptions.StandardCiMaxEvents, 10, 500);

        var end = DateTimeOffset.UtcNow;
        var start = end.AddDays(-lookbackDays);
        var events = new List<CodeIntegrityEvent>();

        try
        {
            var ids = string.Join(" or ", WatchedIds.Select(id => $"EventID={id}"));
            var query = new EventLogQuery(
                "Microsoft-Windows-CodeIntegrity/Operational",
                PathType.LogName,
                $"*[System[({ids})]]")
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            for (var i = 0; i < maxEvents; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                EventRecord? record = reader.ReadEvent();
                if (record is null)
                {
                    break;
                }

                using (record)
                {
                    var created = record.TimeCreated is DateTime dt
                        ? new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc))
                        : (DateTimeOffset?)null;
                    if (created is not null && created < start)
                    {
                        break;
                    }

                    events.Add(new CodeIntegrityEvent(
                        record.Id,
                        created,
                        TruncatePath(TryGetPath(record)),
                        null,
                        record.FormatDescription(),
                        record.ActivityId?.ToString()));
                }
            }

            return Task.FromResult(new CodeIntegrityLogSnapshot(
                Accessible: true,
                AccessDetail: deep ? "Elevated lookback/event cap applied." : null,
                WindowStartUtc: start,
                WindowEndUtc: end,
                LookbackDays: lookbackDays,
                EventCount: events.Count,
                Events: events));
        }
        catch (EventLogException ex)
        {
            _logger.LogWarning(ex, "Code Integrity Operational log inaccessible");
            return Task.FromResult(Inaccessible(start, end, lookbackDays,
                "Code Integrity Operational log requires elevation or is unavailable."));
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Code Integrity log access denied");
            return Task.FromResult(Inaccessible(start, end, lookbackDays,
                "Access denied reading Code Integrity Operational log (try elevated)."));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Code Integrity log collection failed");
            return Task.FromResult(Inaccessible(start, end, lookbackDays,
                "Unexpected failure reading Code Integrity Operational log."));
        }
    }

    private static CodeIntegrityLogSnapshot Inaccessible(
        DateTimeOffset start, DateTimeOffset end, int lookback, string detail)
        => new(false, detail, start, end, lookback, 0, Array.Empty<CodeIntegrityEvent>());

    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static string? TryGetPath(EventRecord record)
    {
        try
        {
            if (record.Properties.Count > 0)
            {
                foreach (var prop in record.Properties)
                {
                    var text = prop.Value?.ToString();
                    if (!string.IsNullOrWhiteSpace(text) &&
                        (text.Contains('\\') || text.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
                         text.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                         text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                    {
                        return text;
                    }
                }
            }
        }
        catch
        {
            // ignored
        }

        return null;
    }

    private static string? TruncatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        const int max = 180;
        return path.Length <= max ? path : path[..max] + "…";
    }
}

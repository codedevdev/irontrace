using IronTrace.Contracts.Forensics;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Forensics.Collectors;

public interface IPersistenceCollector
{
    Task<PersistenceSnapshot> CollectAsync(bool consentGranted, CancellationToken cancellationToken);
}

public sealed class PersistenceCollector : IPersistenceCollector
{
    private readonly ISignatureMatcher _matcher;
    private readonly ILogger<PersistenceCollector> _logger;

    public PersistenceCollector(ISignatureMatcher matcher, ILogger<PersistenceCollector> logger)
    {
        _matcher = matcher;
        _logger = logger;
    }

    public Task<PersistenceSnapshot> CollectAsync(bool consentGranted, CancellationToken cancellationToken)
    {
        if (!consentGranted)
        {
            return Task.FromResult(new PersistenceSnapshot(
                ForensicAvailability.Skipped,
                "Persistence scan skipped — consent not granted.",
                false,
                []));
        }

        var entries = new List<PersistenceEntry>();
        try
        {
            CollectRunKeys(entries, cancellationToken);
            CollectScheduledTasks(entries, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Persistence collection failed");
            return Task.FromResult(new PersistenceSnapshot(
                ForensicAvailability.Partial,
                ex.Message,
                true,
                entries));
        }

        return Task.FromResult(new PersistenceSnapshot(
            ForensicAvailability.Available,
            $"Entries={entries.Count}",
            true,
            entries));
    }

    private void CollectRunKeys(List<PersistenceEntry> entries, CancellationToken ct)
    {
        var paths = new[]
        {
            (@"Software\Microsoft\Windows\CurrentVersion\Run", RegistryHive.CurrentUser, "RunKey(CU)"),
            (@"Software\Microsoft\Windows\CurrentVersion\RunOnce", RegistryHive.CurrentUser, "RunOnce(CU)"),
            (@"Software\Microsoft\Windows\CurrentVersion\Run", RegistryHive.LocalMachine, "RunKey(LM)"),
            (@"Software\Microsoft\Windows\CurrentVersion\RunOnce", RegistryHive.LocalMachine, "RunOnce(LM)")
        };

        foreach (var (path, hive, kind) in paths)
        {
            ct.ThrowIfCancellationRequested();
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            if (key is null)
                continue;

            foreach (var name in key.GetValueNames())
            {
                var val = key.GetValue(name)?.ToString() ?? "";
                var hits = _matcher.Match(name, kind).Concat(_matcher.Match(val, kind)).ToList();
                if (hits.Count == 0 && string.IsNullOrWhiteSpace(val))
                    continue;

                entries.Add(new PersistenceEntry(
                    kind,
                    name,
                    ForensicHashHelper.HashText(val),
                    hits));
            }
        }
    }

    private void CollectScheduledTasks(List<PersistenceEntry> entries, CancellationToken ct)
    {
        var taskRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");
        if (!Directory.Exists(taskRoot))
            return;

        foreach (var file in Directory.EnumerateFiles(taskRoot, "*", SearchOption.AllDirectories))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var name = Path.GetRelativePath(taskRoot, file);
                var content = File.ReadAllText(file);
                var hits = _matcher.Match(name, "ScheduledTask")
                    .Concat(_matcher.Match(content, "ScheduledTask"))
                    .ToList();
                if (hits.Count == 0)
                    continue;

                entries.Add(new PersistenceEntry(
                    "ScheduledTask",
                    name,
                    ForensicHashHelper.HashText(file),
                    hits));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed reading scheduled task {File}", file);
            }
        }
    }
}

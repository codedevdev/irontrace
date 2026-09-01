using System.Diagnostics;
using System.Text.Json;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Forensics;
using Microsoft.Extensions.Logging;

namespace IronTrace.Forensics.Collectors;

public interface IMemoryIntegrityCollector
{
    Task<MemoryIntegritySnapshot> CollectAsync(bool consentGranted, CancellationToken cancellationToken);
}

public sealed class MemoryIntegrityCollector : IMemoryIntegrityCollector
{
    private readonly ILogger<MemoryIntegrityCollector> _logger;
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromMinutes(3);

    public MemoryIntegrityCollector(ILogger<MemoryIntegrityCollector> logger)
    {
        _logger = logger;
    }

    public async Task<MemoryIntegritySnapshot> CollectAsync(bool consentGranted, CancellationToken cancellationToken)
    {
        if (!consentGranted)
        {
            return new MemoryIntegritySnapshot(
                ForensicAvailability.Skipped,
                "Memory scan skipped — consent not granted.",
                false,
                null,
                []);
        }

        var toolPath = MemoryScanToolLocator.ResolvePath();
        if (toolPath is null)
        {
            return new MemoryIntegritySnapshot(
                ForensicAvailability.Unavailable,
                $"hollows_hunter64.exe not found. {MemoryScanToolLocator.InstallHint}",
                true,
                null,
                []);
        }

        var hits = new List<MemoryIntegrityHit>();
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = toolPath,
                    Arguments = "/json /quiet",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            proc.Start();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(ToolTimeout);
            var output = await proc.StandardOutput.ReadToEndAsync(cts.Token).ConfigureAwait(false);
            await proc.WaitForExitAsync(cts.Token).ConfigureAwait(false);

            ParseHollowsHunterJson(output, hits);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Memory integrity scan failed");
            return new MemoryIntegritySnapshot(
                ForensicAvailability.Partial,
                ex.Message,
                true,
                toolPath,
                hits);
        }

        return new MemoryIntegritySnapshot(
            ForensicAvailability.Available,
            $"Hits={hits.Count}",
            true,
            toolPath,
            hits);
    }

    private static void ParseHollowsHunterJson(string output, List<MemoryIntegrityHit> hits)
    {
        if (string.IsNullOrWhiteSpace(output))
            return;

        try
        {
            using var doc = JsonDocument.Parse(output);
            if (!doc.RootElement.TryGetProperty("scans", out var scans))
                return;

            foreach (var scan in scans.EnumerateArray())
            {
                var pid = scan.TryGetProperty("pid", out var p) ? p.GetInt32() : 0;
                var name = scan.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                var nameHash = ForensicHashHelper.HashText(name);

                if (scan.TryGetProperty("suspicious", out var sus) && sus.GetInt32() > 0)
                {
                    hits.Add(new MemoryIntegrityHit(
                        nameHash,
                        pid,
                        "implant",
                        "PE-sieve reported suspicious implants.",
                        FindingConfidence.Medium));
                }

                if (scan.TryGetProperty("hooks", out var hooks) && hooks.GetInt32() > 0)
                {
                    hits.Add(new MemoryIntegrityHit(
                        nameHash,
                        pid,
                        "hook",
                        "PE-sieve reported hooks.",
                        FindingConfidence.Medium));
                }

                if (scan.TryGetProperty("replaced", out var rep) && rep.GetInt32() > 0)
                {
                    hits.Add(new MemoryIntegrityHit(
                        nameHash,
                        pid,
                        "replaced_pe",
                        "Replaced/injected PE modules detected.",
                        FindingConfidence.Medium));
                }
            }
        }
        catch
        {
            // Tool output format may vary; treat non-JSON as no hits
        }
    }
}

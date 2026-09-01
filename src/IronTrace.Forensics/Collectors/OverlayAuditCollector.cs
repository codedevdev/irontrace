using System.Diagnostics;
using IronTrace.Contracts.Forensics;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging;

namespace IronTrace.Forensics.Collectors;

public interface IOverlayAuditCollector
{
    Task<OverlayAuditSnapshot> CollectAsync(CancellationToken cancellationToken);
}

public sealed class OverlayAuditCollector : IOverlayAuditCollector
{
    private static readonly string[] KnownOverlayNames =
    [
        "discord", "nvidia share", "nvcontainer", "obs64", "obs32", "overwolf",
        "steam", "gamebar", "geforce"
    ];

    private readonly ICheatSignatureProvider _signatures;
    private readonly ILogger<OverlayAuditCollector> _logger;

    public OverlayAuditCollector(ICheatSignatureProvider signatures, ILogger<OverlayAuditCollector> logger)
    {
        _signatures = signatures;
        _logger = logger;
    }

    public Task<OverlayAuditSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var overlays = new List<OverlayProcessEntry>();
        var hooks = new List<OverlayHookSignal>();

        try
        {
            var gameNames = _signatures.Database.KnownGameProcesses
                .Select(g => Path.GetFileNameWithoutExtension(g))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName;
                    var lower = name.ToLowerInvariant();
                    if (KnownOverlayNames.Any(o => lower.Contains(o, StringComparison.OrdinalIgnoreCase)))
                    {
                        string? path = null;
                        try { path = proc.MainModule?.FileName; } catch { }
                        overlays.Add(new OverlayProcessEntry(
                            name,
                            ForensicHashHelper.HashText(path),
                            true));
                    }

                    if (gameNames.Contains(name))
                    {
                        foreach (var overlay in overlays.Where(o => o.Running))
                        {
                            hooks.Add(new OverlayHookSignal(
                                overlay.Name,
                                ForensicHashHelper.HashText(name),
                                "Game process running while known overlay software is active (context only)."));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Overlay audit failed for process");
                }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Overlay audit failed");
            return Task.FromResult(new OverlayAuditSnapshot(
                ForensicAvailability.Partial,
                ex.Message,
                overlays,
                hooks));
        }

        return Task.FromResult(new OverlayAuditSnapshot(
            ForensicAvailability.Available,
            $"Overlays={overlays.Count}",
            overlays,
            hooks));
    }
}

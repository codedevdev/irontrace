using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Scanning;
using IronTrace.Forensics.Collectors;
using Microsoft.Extensions.Logging;

namespace IronTrace.Forensics;

public sealed class ForensicScanPipeline : IForensicScanPipeline
{
    private readonly IExecutionArtifactsCollector _execution;
    private readonly IProcessServiceCollector _processService;
    private readonly IPersistenceCollector _persistence;
    private readonly IByovdDeepCollector _byovdDeep;
    private readonly IHwidForensicCollector _hwidForensic;
    private readonly IMemoryIntegrityCollector _memory;
    private readonly IOverlayAuditCollector _overlay;
    private readonly IAiVisionInputDeviceCollector _aiVision;
    private readonly IAnticheatContextCollector _anticheat;
    private readonly ILogger<ForensicScanPipeline> _logger;

    public ForensicScanPipeline(
        IExecutionArtifactsCollector execution,
        IProcessServiceCollector processService,
        IPersistenceCollector persistence,
        IByovdDeepCollector byovdDeep,
        IHwidForensicCollector hwidForensic,
        IMemoryIntegrityCollector memory,
        IOverlayAuditCollector overlay,
        IAiVisionInputDeviceCollector aiVision,
        IAnticheatContextCollector anticheat,
        ILogger<ForensicScanPipeline> logger)
    {
        _execution = execution;
        _processService = processService;
        _persistence = persistence;
        _byovdDeep = byovdDeep;
        _hwidForensic = hwidForensic;
        _memory = memory;
        _overlay = overlay;
        _aiVision = aiVision;
        _anticheat = anticheat;
        _logger = logger;
    }

    public async Task<ForensicEvidenceSnapshot?> CollectAsync(
        ScanOptions options,
        IReadOnlyList<InventoriedDriver> drivers,
        MotherboardInfo? board,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (!options.IsForensicEnabled)
            return null;

        var consent = options.EffectiveConsent;
        Report(progress, "forensic", "Collecting forensic execution artifacts...", 85);

        ExecutionArtifactsSnapshot? execution = null;
        ProcessServiceSnapshot? processService = null;
        PersistenceSnapshot? persistence = null;
        ByovdDeepSnapshot? byovd = null;
        HwidForensicSnapshot? hwid = null;
        MemoryIntegritySnapshot? memory = null;
        OverlayAuditSnapshot? overlay = null;
        AiVisionInputDeviceSnapshot? aiVision = null;
        AnticheatContextSnapshot? anticheat = null;

        try
        {
            if (consent.IncludeExecutionArtifacts)
                execution = await _execution.CollectAsync(cancellationToken).ConfigureAwait(false);

            if (consent.IncludeProcessInventory)
            {
                Report(progress, "forensic", "Collecting process and service inventory...", 87);
                processService = await _processService.CollectAsync(true, cancellationToken).ConfigureAwait(false);
            }

            if (consent.IncludePersistence)
            {
                Report(progress, "forensic", "Checking persistence entries...", 88);
                persistence = await _persistence.CollectAsync(
                    consent.IncludeProcessInventory, cancellationToken).ConfigureAwait(false);
            }

            Report(progress, "forensic", "Deep BYOVD / driver analysis...", 89);
            byovd = await _byovdDeep.CollectAsync(drivers, cancellationToken).ConfigureAwait(false);

            Report(progress, "forensic", "HWID cross-source and DMA dev artifacts...", 90);
            hwid = await _hwidForensic.CollectAsync(board, cancellationToken).ConfigureAwait(false);

            if (consent.IncludeMemoryScan)
            {
                Report(progress, "forensic", "Optional memory integrity scan...", 91);
                memory = await _memory.CollectAsync(true, cancellationToken).ConfigureAwait(false);
            }

            if (consent.IncludeOverlayAudit)
            {
                Report(progress, "forensic", "Overlay audit...", 92);
                overlay = await _overlay.CollectAsync(cancellationToken).ConfigureAwait(false);
            }

            if (consent.IncludeAiVisionScan)
            {
                Report(progress, "forensic", "AI-vision and input device signals...", 93);
                aiVision = await _aiVision.CollectAsync(
                    options.Profile, execution, processService, cancellationToken).ConfigureAwait(false);
            }

            anticheat = await _anticheat.CollectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Forensic pipeline partial failure");
        }

        var snapshot = new ForensicEvidenceSnapshot(
            options.Profile,
            consent,
            null,
            execution,
            processService,
            persistence,
            byovd,
            hwid,
            memory,
            overlay,
            aiVision,
            anticheat);

        var banner = ForensicVerdictMapper.ComputeBanner(snapshot);
        return snapshot with { VerdictBanner = banner };
    }

    private static void Report(IProgress<ScanProgress>? progress, string stage, string message, double percent)
        => progress?.Report(new ScanProgress(stage, message, percent));
}

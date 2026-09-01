using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Findings;
using IronTrace.Contracts.Forensics;

namespace IronTrace.RiskEngine;

public static class ForensicFindingGenerator
{
    public static void AssessForensicEvidence(ForensicEvidenceSnapshot? forensic, List<Finding> findings)
    {
        if (forensic is null)
            return;

        AssessExecution(forensic.Execution, findings);
        AssessProcessService(forensic.ProcessService, findings);
        AssessPersistence(forensic.Persistence, findings);
        AssessByovd(forensic.ByovdDeep, findings);
        AssessHwid(forensic.HwidForensic, findings);
        AssessMemory(forensic.Memory, findings);
        AssessOverlay(forensic.Overlay, findings);
        AssessAiVision(forensic.AiVision, findings);
        AssessAnticheat(forensic.Anticheat, findings);
        AssessForensicClusters(findings);
    }

    private static void AssessExecution(ExecutionArtifactsSnapshot? snap, List<Finding> findings)
    {
        if (snap is null)
            return;

        foreach (var hit in snap.Hits)
        {
            if (hit.RecencyDemoted)
            {
                Add(findings, ForensicFindingCodes.ExecutionArtifactRecencyDemoted,
                    FindingSeverity.Information, FindingConfidence.Medium,
                    "Historical artifact (recency demoted)",
                    $"Keyword '{hit.Keyword}' in {hit.Source} ({hit.AgeDays} days old).",
                    hit.MatchedText, hit.Source);
                continue;
            }

            var code = hit.Category.Equals("cheat_brands", StringComparison.OrdinalIgnoreCase)
                ? ForensicFindingCodes.ExecutionArtifactBrandHit
                : ForensicFindingCodes.ExecutionArtifactKeywordHit;

            Add(findings, code, CapSeverity(hit.EffectiveSeverity), FindingConfidence.Medium,
                $"Execution artifact: {hit.Keyword}",
                $"Matched in {hit.Source}.",
                hit.MatchedText, hit.Source);
        }
    }

    private static void AssessProcessService(ProcessServiceSnapshot? snap, List<Finding> findings)
    {
        if (snap is null || !snap.ConsentGranted)
            return;

        foreach (var hit in snap.ProcessKeywordHits)
        {
            var sev = hit.Category.Equals("dual_use_tools", StringComparison.OrdinalIgnoreCase)
                ? FindingSeverity.Medium
                : CapSeverity(hit.EffectiveSeverity);
            Add(findings, ForensicFindingCodes.ProcessKeywordHit, sev, FindingConfidence.Medium,
                $"Process keyword: {hit.Keyword}",
                hit.MatchedText, hit.MatchedText, hit.Source);
        }

        foreach (var proc in snap.Processes)
        {
            foreach (var mod in proc.SuspiciousModules.Where(m => !m.OnVendorAllowlist))
            {
                Add(findings, ForensicFindingCodes.ProcessSuspiciousModuleLoad,
                    FindingSeverity.Medium, FindingConfidence.Medium,
                    "Suspicious module from user-writable path",
                    mod.ModuleFileName ?? "unknown module",
                    mod.ModulePathHash ?? "", "ProcessModules");
            }
        }

        foreach (var svc in snap.Services)
        {
            foreach (var hit in svc.KeywordHits)
            {
                Add(findings, ForensicFindingCodes.ServiceKeywordHit,
                    CapSeverity(hit.EffectiveSeverity), FindingConfidence.Medium,
                    $"Service keyword: {hit.Keyword}",
                    svc.Name, svc.Name, hit.Source);
            }
        }
    }

    private static void AssessPersistence(PersistenceSnapshot? snap, List<Finding> findings)
    {
        if (snap is null || !snap.ConsentGranted)
            return;

        foreach (var entry in snap.Entries.Where(e => e.KeywordHits.Count > 0))
        {
            Add(findings, ForensicFindingCodes.PersistenceSuspiciousEntry,
                FindingSeverity.Medium, FindingConfidence.Medium,
                $"Persistence entry: {entry.Name}",
                entry.Kind, entry.Name, "Persistence");
        }
    }

    private static void AssessByovd(ByovdDeepSnapshot? snap, List<Finding> findings)
    {
        if (snap is null)
            return;

        foreach (var match in snap.MsBlocklistMatches)
        {
            Add(findings, ForensicFindingCodes.MsBlocklistDriverPresent,
                FindingSeverity.Medium, FindingConfidence.High,
                "Microsoft blocklist driver present",
                match, match, "MsBlocklist");
        }

        foreach (var pkg in snap.DriverStoreStalePackages)
        {
            Add(findings, ForensicFindingCodes.DriverStoreStalePackage,
                FindingSeverity.Information, FindingConfidence.Low,
                "DriverStore package without INF",
                pkg, pkg, "DriverStore");
        }

        if (snap.TestSigningEnabled || snap.NoIntegrityChecksEnabled)
        {
            Add(findings, ForensicFindingCodes.BcdIntegrityBypassEnabled,
                FindingSeverity.Medium, FindingConfidence.High,
                "BCD integrity bypass flags enabled",
                $"testsigning={snap.TestSigningEnabled}, nointegritychecks={snap.NoIntegrityChecksEnabled}",
                "BCD", "BCD");
        }

        foreach (var evt in snap.KernelServiceInstalls.Take(10))
        {
            Add(findings, ForensicFindingCodes.KernelServiceInstallTrace,
                FindingSeverity.Information, FindingConfidence.Medium,
                "Kernel service install (Event 7045)",
                evt.ServiceName, evt.ImagePathTruncated ?? evt.ServiceName, "SystemLog");
        }

        foreach (var fp in snap.CapabilityFingerprints)
        {
            Add(findings, ForensicFindingCodes.DriverCapabilityFingerprint,
                FindingSeverity.Medium, FindingConfidence.Low,
                "Driver capability fingerprint",
                fp.Detail, fp.FileName, "PeImportScan");
        }
    }

    private static void AssessHwid(HwidForensicSnapshot? snap, List<Finding> findings)
    {
        if (snap is null)
            return;

        foreach (var field in snap.Fields.Where(f => !f.Consistent))
        {
            Add(findings, ForensicFindingCodes.HwidCrossSourceMismatch,
                FindingSeverity.Medium, FindingConfidence.Low,
                $"HWID mismatch: {field.FieldName}",
                $"{field.SourceA} vs {field.SourceB}",
                field.FieldName, "CrossSource");
        }

        foreach (var art in snap.DmaDevArtifacts)
        {
            Add(findings, ForensicFindingCodes.DmaDevArtifactOnDisk,
                FindingSeverity.Medium, FindingConfidence.Medium,
                "DMA development artifact on disk",
                art.FileName, art.RelativePath, "FileScan");
        }

        foreach (var hit in snap.SpooferRegistryHits)
        {
            Add(findings, ForensicFindingCodes.SpooferRegistryTrace,
                CapSeverity(hit.EffectiveSeverity), FindingConfidence.Low,
                "Spoofer-related registry trace",
                hit.Keyword, hit.MatchedText, hit.Source);
        }
    }

    private static void AssessMemory(MemoryIntegritySnapshot? snap, List<Finding> findings)
    {
        if (snap is null || !snap.ConsentGranted)
            return;

        foreach (var hit in snap.Hits)
        {
            var code = hit.FindingType switch
            {
                "hook" => ForensicFindingCodes.MemoryHookDetected,
                "replaced_pe" or "implant" => ForensicFindingCodes.MemoryImplantDetected,
                _ => ForensicFindingCodes.MemoryUnbackedExecutable
            };
            Add(findings, code, FindingSeverity.Medium, hit.Confidence,
                $"Memory scan: {hit.FindingType}",
                hit.Detail, hit.ProcessNameHash, "PeSieve");
        }
    }

    private static void AssessOverlay(OverlayAuditSnapshot? snap, List<Finding> findings)
    {
        if (snap is null)
            return;

        foreach (var hook in snap.HookSignals)
        {
            Add(findings, ForensicFindingCodes.OverlayHookRisk,
                FindingSeverity.Low, FindingConfidence.Low,
                "Overlay + game process context",
                hook.Detail, hook.OverlayName, "OverlayAudit");
        }
    }

    private static void AssessAiVision(AiVisionInputDeviceSnapshot? snap, List<Finding> findings)
    {
        if (snap is null)
            return;

        foreach (var hit in snap.InputDeviceHits)
        {
            Add(findings, ForensicFindingCodes.InputDeviceSoftwarePresent,
                FindingSeverity.Medium, FindingConfidence.Medium,
                $"Input device software: {hit.Keyword}",
                hit.MatchedText, hit.MatchedText, hit.Source);
        }

        foreach (var signal in snap.AiVisionSignals.Where(s => s.Severity >= FindingSeverity.Medium))
        {
            Add(findings, ForensicFindingCodes.AiVisionStackDetected,
                CapSeverity(signal.Severity), FindingConfidence.Medium,
                $"AI-vision signal: {signal.SignalType}",
                signal.Detail, signal.PathOrNameHash, "AiVision");
        }
    }

    private static void AssessAnticheat(AnticheatContextSnapshot? snap, List<Finding> findings)
    {
        if (snap is null)
            return;

        foreach (var product in snap.Products)
        {
            Add(findings, ForensicFindingCodes.AnticheatPresent,
                FindingSeverity.Information, FindingConfidence.High,
                $"Anti-cheat present: {product.Product}",
                product.Detail, product.Product, product.DetectionSource);
        }
    }

    private static void AssessForensicClusters(List<Finding> findings)
    {
        var sources = findings
            .Where(f => ForensicFindingCodes.ClusterSources.Contains(f.Code))
            .Select(f => f.Source)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (sources.Count >= 2)
        {
            Add(findings, ForensicFindingCodes.ForensicSignalCluster,
                FindingSeverity.Medium, FindingConfidence.Medium,
                "Multiple independent forensic signals",
                string.Join(", ", sources.Take(5)),
                "cluster", "ForensicEngine");
        }
    }

    private static FindingSeverity CapSeverity(FindingSeverity severity)
        => severity > FindingSeverity.Medium ? FindingSeverity.Medium : severity;

    private static void Add(
        List<Finding> findings,
        string code,
        FindingSeverity severity,
        FindingConfidence confidence,
        string title,
        string explanation,
        string evidence,
        string source)
    {
        findings.Add(new Finding(
            code,
            severity,
            confidence,
            title,
            explanation,
            evidence,
            source,
            TriageHint: ForensicFindingCodes.TriageHintFor(code)));
    }
}

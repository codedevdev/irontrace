using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Forensics;

namespace IronTrace.Forensics;

public static class ForensicVerdictMapper
{
    public static ForensicVerdictBanner ComputeBanner(ForensicEvidenceSnapshot snapshot)
    {
        var hasHighCheat = HasHighCheatSignal(snapshot);
        if (hasHighCheat)
            return ForensicVerdictBanner.CheatsDetected;

        if (HasInputDeviceSignal(snapshot))
            return ForensicVerdictBanner.InputDevicesDetected;

        if (HasMediumReviewSignal(snapshot))
            return ForensicVerdictBanner.ReviewRecommended;

        return ForensicVerdictBanner.Clean;
    }

    public static string BannerDisplayText(ForensicVerdictBanner banner) => banner switch
    {
        ForensicVerdictBanner.CheatsDetected => "Cheats Detected",
        ForensicVerdictBanner.InputDevicesDetected => "Input Devices Detected",
        ForensicVerdictBanner.ReviewRecommended => "Review Recommended",
        ForensicVerdictBanner.Clean => "Clean",
        _ => "Unknown"
    };

    private static bool HasHighCheatSignal(ForensicEvidenceSnapshot s)
    {
        if (s.Execution?.Hits.Any(h =>
                h.Category.Equals("cheat_brands", StringComparison.OrdinalIgnoreCase) &&
                h.EffectiveSeverity >= FindingSeverity.High) == true)
            return true;

        if (s.AiVision?.AiVisionSignals.Any(a => a.Severity >= FindingSeverity.High) == true)
            return true;

        if (s.Memory?.Hits.Count > 0)
            return true;

        if (s.HwidForensic?.DmaDevArtifacts.Count > 0 &&
            s.Execution?.Hits.Any(h => h.Category.Equals("cheat_brands", StringComparison.OrdinalIgnoreCase)) == true)
            return true;

        return false;
    }

    private static bool HasInputDeviceSignal(ForensicEvidenceSnapshot s)
        => s.AiVision?.InputDeviceHits.Count > 0;

    private static bool HasMediumReviewSignal(ForensicEvidenceSnapshot s)
    {
        if (s.Execution?.Hits.Any(h => h.EffectiveSeverity >= FindingSeverity.Medium) == true)
            return true;
        if (s.ProcessService?.ProcessKeywordHits.Any(h => h.EffectiveSeverity >= FindingSeverity.Medium) == true)
            return true;
        if (s.Persistence?.Entries.Any(e => e.KeywordHits.Count > 0) == true)
            return true;
        if (s.ByovdDeep?.MsBlocklistMatches.Count > 0)
            return true;
        return false;
    }
}

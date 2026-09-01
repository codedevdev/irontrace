namespace IronTrace.Contracts.Scanning;

public enum ScanProfile
{
    /// <summary>Phases 1–5 hardware/platform scan only (default for backward-compatible upload).</summary>
    HardwareOnly = 0,

    /// <summary>Full forensic scan for administrators (process, memory, overlay when consented).</summary>
    FullForensic = 1,

    /// <summary>Player self-audit: forensic evidence with local-first privacy defaults.</summary>
    SelfAudit = 2,

    /// <summary>Self-audit variant for console-rig PC (capture card / input adapters).</summary>
    SelfAuditConsoleRig = 3
}

public sealed record ScanConsentFlags(
    bool IncludeExecutionArtifacts = true,
    bool IncludeProcessInventory = false,
    bool IncludePersistence = false,
    bool IncludeMemoryScan = false,
    bool IncludeOverlayAudit = true,
    bool IncludeAiVisionScan = true)
{
    public static ScanConsentFlags ForProfile(ScanProfile profile) => profile switch
    {
        ScanProfile.HardwareOnly => new ScanConsentFlags(
            IncludeExecutionArtifacts: false,
            IncludeProcessInventory: false,
            IncludePersistence: false,
            IncludeMemoryScan: false,
            IncludeOverlayAudit: false,
            IncludeAiVisionScan: false),
        ScanProfile.FullForensic => new ScanConsentFlags(
            IncludeExecutionArtifacts: true,
            IncludeProcessInventory: true,
            IncludePersistence: true,
            IncludeMemoryScan: true,
            IncludeOverlayAudit: true,
            IncludeAiVisionScan: true),
        ScanProfile.SelfAudit => new ScanConsentFlags(
            IncludeExecutionArtifacts: true,
            IncludeProcessInventory: true,
            IncludePersistence: true,
            IncludeMemoryScan: false,
            IncludeOverlayAudit: true,
            IncludeAiVisionScan: true),
        ScanProfile.SelfAuditConsoleRig => new ScanConsentFlags(
            IncludeExecutionArtifacts: true,
            IncludeProcessInventory: true,
            IncludePersistence: true,
            IncludeMemoryScan: false,
            IncludeOverlayAudit: true,
            IncludeAiVisionScan: true),
        _ => new ScanConsentFlags()
    };
}

public sealed record ScanOptions(
    ScanProfile Profile = ScanProfile.HardwareOnly,
    ScanConsentFlags? Consent = null)
{
    public ScanConsentFlags EffectiveConsent => Consent ?? ScanConsentFlags.ForProfile(Profile);

    public static ScanOptions Default { get; } = new();

    public bool IsForensicEnabled => Profile != ScanProfile.HardwareOnly;
}

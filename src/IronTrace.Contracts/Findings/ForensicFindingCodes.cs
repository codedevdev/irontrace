namespace IronTrace.Contracts.Findings;

public static class ForensicFindingCodes
{
    public const string ExecutionArtifactKeywordHit = "EXECUTION_ARTIFACT_KEYWORD_HIT";
    public const string ExecutionArtifactBrandHit = "EXECUTION_ARTIFACT_BRAND_HIT";
    public const string ExecutionArtifactRecencyDemoted = "EXECUTION_ARTIFACT_RECENCY_DEMOTED";
    public const string ProcessSuspiciousModuleLoad = "PROCESS_SUSPICIOUS_MODULE_LOAD";
    public const string ProcessKeywordHit = "PROCESS_KEYWORD_HIT";
    public const string PersistenceSuspiciousEntry = "PERSISTENCE_SUSPICIOUS_ENTRY";
    public const string ServiceKeywordHit = "SERVICE_KEYWORD_HIT";
    public const string MsBlocklistDriverPresent = "MS_BLOCKLIST_DRIVER_PRESENT";
    public const string DriverStoreStalePackage = "DRIVERSTORE_STALE_PACKAGE";
    public const string BcdIntegrityBypassEnabled = "BCD_INTEGRITY_BYPASS_ENABLED";
    public const string KernelServiceInstallTrace = "KERNEL_SERVICE_INSTALL_TRACE";
    public const string DriverCapabilityFingerprint = "DRIVER_CAPABILITY_FINGERPRINT";
    public const string HwidCrossSourceMismatch = "HWID_CROSS_SOURCE_MISMATCH";
    public const string DmaDevArtifactOnDisk = "DMA_DEV_ARTIFACT_ON_DISK";
    public const string SpooferRegistryTrace = "SPOOFER_REGISTRY_TRACE";
    public const string MemoryImplantDetected = "MEMORY_IMPLANT_DETECTED";
    public const string MemoryHookDetected = "MEMORY_HOOK_DETECTED";
    public const string MemoryUnbackedExecutable = "MEMORY_UNBACKED_EXECUTABLE";
    public const string InputDeviceSoftwarePresent = "INPUT_DEVICE_SOFTWARE_PRESENT";
    public const string AiVisionStackDetected = "AI_VISION_STACK_DETECTED";
    public const string OverlayHookRisk = "OVERLAY_HOOK_RISK";
    public const string AnticheatPresent = "ANTICHEAT_PRESENT";
    public const string ForensicSignalCluster = "FORENSIC_SIGNAL_CLUSTER";

    public static readonly HashSet<string> All = new(StringComparer.OrdinalIgnoreCase)
    {
        ExecutionArtifactKeywordHit,
        ExecutionArtifactBrandHit,
        ExecutionArtifactRecencyDemoted,
        ProcessSuspiciousModuleLoad,
        ProcessKeywordHit,
        PersistenceSuspiciousEntry,
        ServiceKeywordHit,
        MsBlocklistDriverPresent,
        DriverStoreStalePackage,
        BcdIntegrityBypassEnabled,
        KernelServiceInstallTrace,
        DriverCapabilityFingerprint,
        HwidCrossSourceMismatch,
        DmaDevArtifactOnDisk,
        SpooferRegistryTrace,
        MemoryImplantDetected,
        MemoryHookDetected,
        MemoryUnbackedExecutable,
        InputDeviceSoftwarePresent,
        AiVisionStackDetected,
        OverlayHookRisk,
        AnticheatPresent,
        ForensicSignalCluster
    };

    public static readonly HashSet<string> ClusterSources = new(StringComparer.OrdinalIgnoreCase)
    {
        ExecutionArtifactBrandHit,
        ProcessSuspiciousModuleLoad,
        ProcessKeywordHit,
        PersistenceSuspiciousEntry,
        MsBlocklistDriverPresent,
        DriverCapabilityFingerprint,
        HwidCrossSourceMismatch,
        DmaDevArtifactOnDisk,
        MemoryImplantDetected,
        MemoryHookDetected,
        AiVisionStackDetected
    };

    public static bool IsForensicRelated(string? code)
        => !string.IsNullOrEmpty(code) && All.Contains(code);

    public static string? TriageHintFor(string code) => code switch
    {
        ExecutionArtifactKeywordHit =>
            "Historical execution artifact matched a keyword. Correlate with other sources; do not auto-ban.",
        ExecutionArtifactBrandHit =>
            "Named cheat brand artifact found. Verify with second independent signal before action.",
        ProcessSuspiciousModuleLoad =>
            "DLL loaded from user-writable path. May be mod or injector; review context only.",
        ProcessKeywordHit =>
            "Running process matched keyword database. Dual-use tools are Medium only.",
        PersistenceSuspiciousEntry =>
            "Startup/persistence entry matched keyword. Review manually; do not auto-ban.",
        MsBlocklistDriverPresent =>
            "Driver matches Microsoft vulnerable driver blocklist. Evidence only.",
        BcdIntegrityBypassEnabled =>
            "Boot config allows test-signing or integrity bypass. Weak posture signal.",
        KernelServiceInstallTrace =>
            "Kernel service install event in System log. BYOVD staging evidence only.",
        DriverCapabilityFingerprint =>
            "Small driver with cross-process/physical memory imports. High FP risk on OEM tools.",
        HwidCrossSourceMismatch =>
            "Hardware identity fields disagree across sources. May indicate spoofer; not proof.",
        DmaDevArtifactOnDisk =>
            "DMA development artifact on disk. Does not prove active DMA cheat in-game.",
        MemoryImplantDetected =>
            "In-memory implant signal from optional scan. No dumps collected; review only.",
        AiVisionStackDetected =>
            "AI-vision aimbot stack indicators. Context-dependent; capture-card rigs vary.",
        InputDeviceSoftwarePresent =>
            "Commercial input adapter software detected. Rules depend on game policy.",
        AnticheatPresent =>
            "Anti-cheat software detected for context. Absence of findings is not proof of clean play.",
        ForensicSignalCluster =>
            "Multiple independent forensic signals. Prioritize human review; still not auto-ban.",
        _ => null
    };
}

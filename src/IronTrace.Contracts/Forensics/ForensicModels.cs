using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Scanning;

namespace IronTrace.Contracts.Forensics;

public enum ForensicAvailability
{
    Unknown = 0,
    Available = 1,
    Partial = 2,
    Unavailable = 3,
    Skipped = 4
}

public enum ForensicVerdictBanner
{
    Clean = 0,
    InputDevicesDetected = 1,
    ReviewRecommended = 2,
    CheatsDetected = 3
}

public sealed record SignatureMatchHit(
    string Category,
    string Keyword,
    string MatchedText,
    string Source,
    FindingSeverity OriginalSeverity,
    FindingSeverity EffectiveSeverity,
    DateTimeOffset? LastSeenUtc,
    int? AgeDays,
    bool RecencyDemoted);

public sealed record ExecutionArtifactsSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    IReadOnlyList<SignatureMatchHit> Hits,
    int PrefetchEntryCount,
    int BamEntryCount,
    int ShimCacheEntryCount,
    int UserAssistEntryCount);

public sealed record ProcessModuleEntry(
    string ProcessNameHash,
    string? ModuleFileName,
    string? ModulePathHash,
    bool FromUserWritablePath,
    bool OnVendorAllowlist);

public sealed record ProcessEntry(
    string Name,
    string? ImagePathHash,
    string? CommandLineHash,
    int ProcessId,
    int? ParentProcessId,
    IReadOnlyList<ProcessModuleEntry> SuspiciousModules);

public sealed record ServiceEntry(
    string Name,
    string? DisplayName,
    string? ImagePathHash,
    IReadOnlyList<SignatureMatchHit> KeywordHits);

public sealed record ProcessServiceSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    bool ConsentGranted,
    IReadOnlyList<ProcessEntry> Processes,
    IReadOnlyList<ServiceEntry> Services,
    IReadOnlyList<SignatureMatchHit> ProcessKeywordHits);

public sealed record PersistenceEntry(
    string Kind,
    string Name,
    string? TargetPathHash,
    IReadOnlyList<SignatureMatchHit> KeywordHits);

public sealed record PersistenceSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    bool ConsentGranted,
    IReadOnlyList<PersistenceEntry> Entries);

public sealed record ByovdDeepSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    bool TestSigningEnabled,
    bool NoIntegrityChecksEnabled,
    IReadOnlyList<string> MsBlocklistMatches,
    IReadOnlyList<string> DriverStoreStalePackages,
    IReadOnlyList<KernelServiceInstallEvent> KernelServiceInstalls,
    IReadOnlyList<DriverCapabilityFingerprint> CapabilityFingerprints);

public sealed record KernelServiceInstallEvent(
    DateTimeOffset TimeCreated,
    string ServiceName,
    string? ImagePathTruncated);

public sealed record DriverCapabilityFingerprint(
    string FileName,
    string? Sha256,
    long FileSizeBytes,
    IReadOnlyList<string> MatchedImports,
    string Detail);

public sealed record HwidForensicSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    IReadOnlyList<HwidCrossSourceField> Fields,
    IReadOnlyList<SignatureMatchHit> SpooferRegistryHits,
    IReadOnlyList<DmaDevArtifact> DmaDevArtifacts);

public sealed record HwidCrossSourceField(
    string FieldName,
    string SourceA,
    string SourceB,
    string ValueAHash,
    string ValueBHash,
    bool Consistent);

public sealed record DmaDevArtifact(
    string RelativePath,
    string FileName,
    long SizeBytes,
    string Detail);

public sealed record MemoryIntegrityHit(
    string ProcessNameHash,
    int ProcessId,
    string FindingType,
    string Detail,
    FindingConfidence Confidence);

public sealed record MemoryIntegritySnapshot(
    ForensicAvailability Availability,
    string? Detail,
    bool ConsentGranted,
    string? ToolPath,
    IReadOnlyList<MemoryIntegrityHit> Hits);

public sealed record OverlayAuditSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    IReadOnlyList<OverlayProcessEntry> KnownOverlays,
    IReadOnlyList<OverlayHookSignal> HookSignals);

public sealed record OverlayProcessEntry(
    string Name,
    string? ImagePathHash,
    bool Running);

public sealed record OverlayHookSignal(
    string OverlayName,
    string GameProcessNameHash,
    string Detail);

public sealed record AiVisionInputDeviceSnapshot(
    ForensicAvailability Availability,
    string? Detail,
    IReadOnlyList<SignatureMatchHit> InputDeviceHits,
    IReadOnlyList<AiVisionSignal> AiVisionSignals,
    IReadOnlyList<SignatureMatchHit> ConsoleRigHits);

public sealed record AiVisionSignal(
    string SignalType,
    string PathOrNameHash,
    string Detail,
    FindingSeverity Severity);

public sealed record AnticheatContextSnapshot(
    ForensicAvailability Availability,
    IReadOnlyList<AnticheatProductEntry> Products);

public sealed record AnticheatProductEntry(
    string Product,
    string DetectionSource,
    string Detail);

public sealed record ForensicEvidenceSnapshot(
    ScanProfile Profile,
    ScanConsentFlags Consent,
    ForensicVerdictBanner? VerdictBanner,
    ExecutionArtifactsSnapshot? Execution,
    ProcessServiceSnapshot? ProcessService,
    PersistenceSnapshot? Persistence,
    ByovdDeepSnapshot? ByovdDeep,
    HwidForensicSnapshot? HwidForensic,
    MemoryIntegritySnapshot? Memory,
    OverlayAuditSnapshot? Overlay,
    AiVisionInputDeviceSnapshot? AiVision,
    AnticheatContextSnapshot? Anticheat);

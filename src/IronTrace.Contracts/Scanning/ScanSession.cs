using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Findings;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;

namespace IronTrace.Contracts.Scanning;

public sealed record ScanProgress(string Stage, string Message, double? Percent = null);

public sealed record ScanSession(
    Guid SessionId,
    string ApplicationVersion,
    string ReportSchemaVersion,
    DateTimeOffset ScanStartedAt,
    DateTimeOffset? ScanCompletedAt,
    OperatingSystemInfo? OperatingSystem,
    PlatformSecurityState? PlatformSecurity,
    MotherboardInfo? Motherboard,
    IReadOnlyList<PciDevice> PciDevices,
    IReadOnlyList<UsbDevice> UsbDevices,
    IReadOnlyList<InventoriedDriver> Drivers,
    IReadOnlyList<VulnerableDriverMatch> VulnerableDriverMatches,
    CodeIntegrityLogSnapshot? CodeIntegrity,
    IdentityConsistencyReport? IdentityConsistency,
    KernelEvidenceSnapshot? KernelEvidence,
    ChallengeEvidenceSnapshot? ChallengeEvidence,
    SpdmEvidenceSnapshot? SpdmEvidence,
    MeasuredBootEvidenceSnapshot? MeasuredBootEvidence,
    PnPHistorySnapshot? PnPHistory,
    ScanProfile ScanProfile,
    ScanConsentFlags? ScanConsent,
    ForensicEvidenceSnapshot? ForensicEvidence,
    RiskAssessment? RiskAssessment,
    IReadOnlyList<string> Errors,
    IReadOnlyDictionary<string, string> Metadata);

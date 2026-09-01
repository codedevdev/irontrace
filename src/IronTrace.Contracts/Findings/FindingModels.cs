using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Findings;

public sealed record RiskIndicator(
    string Code,
    FindingSeverity Severity,
    FindingConfidence Confidence,
    string Evidence,
    string Source,
    string Explanation,
    string? RelatedInstanceId = null);

public sealed record Finding(
    string Code,
    FindingSeverity Severity,
    FindingConfidence Confidence,
    string Title,
    string Explanation,
    string Evidence,
    string Source,
    string? RelatedInstanceId = null,
    string? TriageHint = null);

public sealed record RiskAssessment(
    IntegrityVerdict Verdict,
    string Summary,
    int InformationalCount,
    int LowCount,
    int MediumCount,
    int HighCount,
    int CriticalCount,
    int ConsistentDeviceCount,
    int ReviewDeviceCount,
    IReadOnlyList<Finding> Findings);

namespace IronTrace.Contracts.Platform;

public sealed record CodeIntegrityEvent(
    int EventId,
    DateTimeOffset? TimeCreated,
    string? FilePathTruncated,
    string? ProcessName,
    string? StatusMessage,
    string? ActivityId);

public sealed record CodeIntegrityLogSnapshot(
    bool Accessible,
    string? AccessDetail,
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    int LookbackDays,
    int EventCount,
    IReadOnlyList<CodeIntegrityEvent> Events);

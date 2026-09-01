using IronTrace.Contracts.Api;

namespace IronTrace.Server.Data;

public sealed class ApiKeyEntity
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string KeyPrefix { get; set; } = "";
    public string KeyHash { get; set; } = "";
    public ApiKeyScope Scope { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class ChallengeEntity
{
    public Guid SessionId { get; set; }
    public string Nonce { get; set; } = "";
    public Guid ApiKeyId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}

public sealed class ScanSubmissionEntity
{
    public Guid Id { get; set; }
    public Guid SessionId { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }
    public string ReportSchemaVersion { get; set; } = "";
    public string ApplicationVersion { get; set; } = "";
    public string? Verdict { get; set; }
    public string? Summary { get; set; }
    public string? HostMachineNameHash { get; set; }
    public string PayloadJson { get; set; } = "{}";
    public ScanReviewStatus ReviewStatus { get; set; }
    public string? ReviewNotes { get; set; }
    public Guid? ReviewerKeyId { get; set; }
    public Guid UploadApiKeyId { get; set; }
}

namespace IronTrace.Contracts.Api;

public enum ApiKeyScope
{
    Upload = 0,
    Admin = 1
}

public enum ScanReviewStatus
{
    Pending = 0,
    Accepted = 1,
    Rejected = 2,
    NeedsInfo = 3
}

public sealed record ChallengeResponse(
    Guid SessionId,
    string Nonce,
    DateTimeOffset ExpiresAt);

public sealed record ScanUploadResponse(
    Guid ScanId,
    ScanReviewStatus Status,
    string Message);

public sealed record ScanListItemDto(
    Guid Id,
    Guid SessionId,
    DateTimeOffset ReceivedAt,
    string? Verdict,
    string? Summary,
    string ReportSchemaVersion,
    string ApplicationVersion,
    ScanReviewStatus ReviewStatus);

public sealed record ScanDetailDto(
    Guid Id,
    Guid SessionId,
    DateTimeOffset ReceivedAt,
    string? Verdict,
    string? Summary,
    string ReportSchemaVersion,
    string ApplicationVersion,
    string? HostMachineNameHash,
    ScanReviewStatus ReviewStatus,
    string? ReviewNotes,
    string PayloadJson);

public sealed record ReviewScanRequest(
    ScanReviewStatus Status,
    string? Notes);

public static class UploadHmac
{
    public const string SessionHeader = "X-IronTrace-SessionId";
    public const string NonceHeader = "X-IronTrace-Nonce";
    public const string SignatureHeader = "X-IronTrace-Signature";

    public static string CanonicalString(Guid sessionId, string nonce, string bodySha256Hex)
        => $"{sessionId:D}|{nonce}|{bodySha256Hex.ToLowerInvariant()}";

    public static string ComputeSignature(string apiKeySecret, Guid sessionId, string nonce, ReadOnlySpan<byte> body)
    {
        var bodyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(body)).ToLowerInvariant();
        var canonical = CanonicalString(sessionId, nonce, bodyHash);
        using var hmac = new System.Security.Cryptography.HMACSHA256(
            System.Text.Encoding.UTF8.GetBytes(apiKeySecret));
        return Convert.ToHexString(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public static bool FixedTimeEqualsHex(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        try
        {
            var ba = Convert.FromHexString(a);
            var bb = Convert.FromHexString(b);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
        }
        catch
        {
            return false;
        }
    }
}

namespace IronTrace.Contracts.Reference;

public sealed class ReferenceArtifactSpec
{
    public string FileName { get; set; } = "";
    public int SchemaVersion { get; set; }
    public string DatabaseSha256 { get; set; } = "";
    public long SizeBytes { get; set; }
    public string ContentUri { get; set; } = "";
    public string? RetrievedAt { get; set; }
}

/// <summary>
/// Signed reference update manifest. Algorithm: ECDSA P-256 with SHA-256 (IEEE P1363 signature).
/// Canonical payload for signing is UTF-8 JSON of all fields except <see cref="SignatureBase64"/>.
/// </summary>
public sealed class ReferenceUpdateManifest
{
    public int ManifestVersion { get; set; } = 1;
    public string Algorithm { get; set; } = "ECDSA-P256-SHA256";
    public string? IssuedAt { get; set; }
    public List<ReferenceArtifactSpec> Artifacts { get; set; } = [];
    public string? SignatureBase64 { get; set; }
}

public sealed class ReferenceUpdateOptions
{
    public const string SectionName = "IronTrace:ReferenceUpdates";

    public bool Enabled { get; set; }
    public string ManifestUrl { get; set; } = "";
    public string PublicKeyRelativePath { get; set; } = "reference/trust/irontrace-ref.pub";
    /// <summary>Optional offline package directory containing manifest.json + DB files.</summary>
    public string? OfflinePackageDirectory { get; set; }
}

public sealed class ElevatedSecurityOptions
{
    public const string SectionName = "IronTrace:ElevatedSecurityDetails";

    /// <summary>Off | WhenElevated</summary>
    public string Mode { get; set; } = "WhenElevated";
    public int ElevatedCiLookbackDays { get; set; } = 30;
    public int ElevatedCiMaxEvents { get; set; } = 250;
    public int StandardCiLookbackDays { get; set; } = 14;
    public int StandardCiMaxEvents { get; set; } = 100;
}

public sealed class ReferenceUpdateResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = "";
    public IReadOnlyList<string> UpdatedFiles { get; init; } = Array.Empty<string>();
}

public interface IReferenceUpdateService
{
    Task<ReferenceUpdateResult> CheckAndApplyAsync(CancellationToken cancellationToken);
}

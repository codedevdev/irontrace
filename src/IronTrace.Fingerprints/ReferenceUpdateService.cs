using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IronTrace.Contracts.Reference;
using Microsoft.Extensions.Logging;

namespace IronTrace.Fingerprints;

public static class ReferenceManifestCrypto
{
    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static byte[] GetCanonicalPayloadBytes(ReferenceUpdateManifest manifest)
    {
        var unsigned = new ReferenceUpdateManifest
        {
            ManifestVersion = manifest.ManifestVersion,
            Algorithm = manifest.Algorithm,
            IssuedAt = manifest.IssuedAt,
            Artifacts = manifest.Artifacts
                .OrderBy(a => a.FileName, StringComparer.Ordinal)
                .Select(a => new ReferenceArtifactSpec
                {
                    FileName = a.FileName,
                    SchemaVersion = a.SchemaVersion,
                    DatabaseSha256 = a.DatabaseSha256.ToLowerInvariant(),
                    SizeBytes = a.SizeBytes,
                    ContentUri = a.ContentUri,
                    RetrievedAt = a.RetrievedAt
                })
                .ToList(),
            SignatureBase64 = null
        };

        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(unsigned, CanonicalJson));
    }

    public static string Sign(ReferenceUpdateManifest manifest, ECDsa privateKey)
    {
        var payload = GetCanonicalPayloadBytes(manifest);
        var signature = privateKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Convert.ToBase64String(signature);
    }

    public static bool Verify(ReferenceUpdateManifest manifest, ECDsa publicKey)
    {
        if (string.IsNullOrWhiteSpace(manifest.SignatureBase64))
        {
            return false;
        }

        var payload = GetCanonicalPayloadBytes(manifest);
        var signature = Convert.FromBase64String(manifest.SignatureBase64);
        return publicKey.VerifyData(
            payload,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public static void GenerateKeyPair(string privateKeyPath, string publicKeyPath)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        EnsureParent(privateKeyPath);
        EnsureParent(publicKeyPath);
        File.WriteAllText(privateKeyPath, ecdsa.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicKeyPath, ecdsa.ExportSubjectPublicKeyInfoPem());
    }

    public static ECDsa LoadPublicKeyPem(string pemPath)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(File.ReadAllText(pemPath));
        return ecdsa;
    }

    public static ECDsa LoadPrivateKeyPem(string pemPath)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(File.ReadAllText(pemPath));
        return ecdsa;
    }

    public static string SerializePretty(ReferenceUpdateManifest manifest)
        => JsonSerializer.Serialize(manifest, PrettyJson);

    public static ReferenceUpdateManifest Deserialize(string json)
        => JsonSerializer.Deserialize<ReferenceUpdateManifest>(json, PrettyJson)
           ?? throw new InvalidOperationException("Invalid reference manifest JSON.");

    public static string Sha256HexFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void EnsureParent(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }
}

public sealed class ReferenceUpdateService : IReferenceUpdateService
{
    private readonly ReferenceUpdateOptions _options;
    private readonly string _targetDirectory;
    private readonly string _publicKeyPath;
    private readonly ILogger<ReferenceUpdateService>? _logger;

    public ReferenceUpdateService(
        ReferenceUpdateOptions options,
        string targetDirectory,
        string publicKeyPath,
        ILogger<ReferenceUpdateService>? logger = null)
    {
        _options = options;
        _targetDirectory = targetDirectory;
        _publicKeyPath = publicKeyPath;
        _logger = logger;
    }

    public async Task<ReferenceUpdateResult> CheckAndApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(_targetDirectory);

            if (!File.Exists(_publicKeyPath))
            {
                return Fail($"Public key not found at {_publicKeyPath}.");
            }

            var (manifestJson, packageRoot) = await LoadManifestAsync(cancellationToken).ConfigureAwait(false);
            if (manifestJson is null)
            {
                return Fail(
                    "No update package found. Drop a signed package into %LocalAppData%\\IronTrace\\reference\\pending\\ " +
                    "or enable IronTrace:ReferenceUpdates with ManifestUrl / OfflinePackageDirectory.");
            }

            var manifest = ReferenceManifestCrypto.Deserialize(manifestJson);
            using var publicKey = ReferenceManifestCrypto.LoadPublicKeyPem(_publicKeyPath);
            if (!ReferenceManifestCrypto.Verify(manifest, publicKey))
            {
                return Fail("Manifest signature verification failed. Update aborted.");
            }

            var updated = new List<string>();
            foreach (var artifact in manifest.Artifacts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sourcePath = await ResolveArtifactFileAsync(artifact, packageRoot, cancellationToken)
                    .ConfigureAwait(false);
                if (sourcePath is null || !File.Exists(sourcePath))
                {
                    return Fail($"Artifact file missing: {artifact.FileName}", updated);
                }

                var hash = ReferenceManifestCrypto.Sha256HexFile(sourcePath);
                if (!string.Equals(hash, artifact.DatabaseSha256, StringComparison.OrdinalIgnoreCase))
                {
                    return Fail(
                        $"Hash mismatch for {artifact.FileName}. Expected {artifact.DatabaseSha256}, got {hash}.",
                        updated);
                }

                var dest = Path.Combine(_targetDirectory, artifact.FileName);
                AtomicReplace(dest, sourcePath);
                updated.Add(artifact.FileName);
            }

            await File.WriteAllTextAsync(
                Path.Combine(_targetDirectory, "manifest.json"),
                ReferenceManifestCrypto.SerializePretty(manifest),
                cancellationToken).ConfigureAwait(false);

            _logger?.LogInformation("Applied {Count} reference DB update(s).", updated.Count);
            return new ReferenceUpdateResult
            {
                Success = true,
                Message = updated.Count == 0
                    ? "Manifest verified; no artifacts to apply."
                    : $"Updated {updated.Count} reference database(s).",
                UpdatedFiles = updated
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Reference update failed");
            return Fail($"Reference update failed: {ex.Message}");
        }
    }

    private static ReferenceUpdateResult Fail(string message, IReadOnlyList<string>? updated = null)
        => new()
        {
            Success = false,
            Message = message,
            UpdatedFiles = updated ?? Array.Empty<string>()
        };

    private async Task<(string? Json, string? PackageRoot)> LoadManifestAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(_options.OfflinePackageDirectory) &&
            Directory.Exists(_options.OfflinePackageDirectory))
        {
            var localManifest = Path.Combine(_options.OfflinePackageDirectory, "manifest.json");
            if (File.Exists(localManifest))
            {
                var json = await File.ReadAllTextAsync(localManifest, cancellationToken).ConfigureAwait(false);
                return (json, _options.OfflinePackageDirectory);
            }
        }

        var staged = Path.Combine(_targetDirectory, "pending", "manifest.json");
        if (File.Exists(staged))
        {
            var json = await File.ReadAllTextAsync(staged, cancellationToken).ConfigureAwait(false);
            return (json, Path.GetDirectoryName(staged));
        }

        if (_options.Enabled && !string.IsNullOrWhiteSpace(_options.ManifestUrl))
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            var json = await http.GetStringAsync(_options.ManifestUrl, cancellationToken).ConfigureAwait(false);
            return (json, null);
        }

        return (null, null);
    }

    private async Task<string?> ResolveArtifactFileAsync(
        ReferenceArtifactSpec artifact,
        string? packageRoot,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(packageRoot))
        {
            var relative = artifact.ContentUri;
            if (string.IsNullOrWhiteSpace(relative) || relative.Contains("://", StringComparison.Ordinal))
            {
                relative = artifact.FileName;
            }

            var candidate = Path.GetFullPath(
                Path.Combine(packageRoot, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (File.Exists(candidate))
            {
                return candidate;
            }

            candidate = Path.Combine(packageRoot, artifact.FileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        if (_options.Enabled &&
            !string.IsNullOrWhiteSpace(artifact.ContentUri) &&
            artifact.ContentUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var temp = Path.Combine(
                Path.GetTempPath(),
                "irontrace-ref-" + Guid.NewGuid().ToString("N") + "-" + artifact.FileName);
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            await using var remote = await http.GetStreamAsync(artifact.ContentUri, cancellationToken)
                .ConfigureAwait(false);
            await using var local = File.Create(temp);
            await remote.CopyToAsync(local, cancellationToken).ConfigureAwait(false);
            return temp;
        }

        return null;
    }

    private static void AtomicReplace(string destPath, string sourcePath)
    {
        var directory = Path.GetDirectoryName(destPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = destPath + ".tmp";
        if (File.Exists(temp))
        {
            File.Delete(temp);
        }

        File.Copy(sourcePath, temp, overwrite: true);

        if (File.Exists(destPath))
        {
            var bak = destPath + ".bak";
            if (File.Exists(bak))
            {
                File.Delete(bak);
            }

            File.Move(destPath, bak);
        }

        File.Move(temp, destPath);
    }
}

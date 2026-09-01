using FluentAssertions;
using IronTrace.Contracts.Reference;
using IronTrace.Fingerprints;

namespace IronTrace.Fingerprints.Tests;

public class ReferenceManifestTests
{
    [Fact]
    public async Task Sign_Verify_And_Apply_Offline_Package()
    {
        var root = Path.Combine(Path.GetTempPath(), "irontrace-ref-tests", Guid.NewGuid().ToString("N"));
        var package = Path.Combine(root, "package");
        var target = Path.Combine(root, "target");
        var keys = Path.Combine(root, "keys");
        Directory.CreateDirectory(package);
        Directory.CreateDirectory(target);
        Directory.CreateDirectory(keys);

        var priv = Path.Combine(keys, "priv.pem");
        var pub = Path.Combine(keys, "pub.pem");
        ReferenceManifestCrypto.GenerateKeyPair(priv, pub);

        var dbPath = Path.Combine(package, "pci-reference.db");
        await File.WriteAllBytesAsync(dbPath, "sqlite-fake-content"u8.ToArray());

        var manifest = new ReferenceUpdateManifest
        {
            ManifestVersion = 1,
            Algorithm = "ECDSA-P256-SHA256",
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            Artifacts =
            [
                new ReferenceArtifactSpec
                {
                    FileName = "pci-reference.db",
                    SchemaVersion = 1,
                    DatabaseSha256 = ReferenceManifestCrypto.Sha256HexFile(dbPath),
                    SizeBytes = new FileInfo(dbPath).Length,
                    ContentUri = "pci-reference.db",
                    RetrievedAt = DateTimeOffset.UtcNow.ToString("O")
                }
            ]
        };

        using (var key = ReferenceManifestCrypto.LoadPrivateKeyPem(priv))
        {
            manifest.SignatureBase64 = ReferenceManifestCrypto.Sign(manifest, key);
        }

        using (var pubKey = ReferenceManifestCrypto.LoadPublicKeyPem(pub))
        {
            ReferenceManifestCrypto.Verify(manifest, pubKey).Should().BeTrue();
        }

        var manifestPath = Path.Combine(package, "manifest.json");
        await File.WriteAllTextAsync(manifestPath, ReferenceManifestCrypto.SerializePretty(manifest));

        var service = new ReferenceUpdateService(
            new ReferenceUpdateOptions { OfflinePackageDirectory = package },
            target,
            pub);

        var result = await service.CheckAndApplyAsync(CancellationToken.None);
        result.Success.Should().BeTrue(result.Message);
        File.Exists(Path.Combine(target, "pci-reference.db")).Should().BeTrue();
    }

    [Fact]
    public async Task Tampered_Hash_Is_Rejected()
    {
        var root = Path.Combine(Path.GetTempPath(), "irontrace-ref-tests", Guid.NewGuid().ToString("N"));
        var package = Path.Combine(root, "package");
        var target = Path.Combine(root, "target");
        var keys = Path.Combine(root, "keys");
        Directory.CreateDirectory(package);
        Directory.CreateDirectory(target);
        Directory.CreateDirectory(keys);

        var priv = Path.Combine(keys, "priv.pem");
        var pub = Path.Combine(keys, "pub.pem");
        ReferenceManifestCrypto.GenerateKeyPair(priv, pub);

        var dbPath = Path.Combine(package, "pci-reference.db");
        await File.WriteAllBytesAsync(dbPath, "good"u8.ToArray());

        var manifest = new ReferenceUpdateManifest
        {
            ManifestVersion = 1,
            Algorithm = "ECDSA-P256-SHA256",
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            Artifacts =
            [
                new ReferenceArtifactSpec
                {
                    FileName = "pci-reference.db",
                    SchemaVersion = 1,
                    DatabaseSha256 = ReferenceManifestCrypto.Sha256HexFile(dbPath),
                    SizeBytes = 4,
                    ContentUri = "pci-reference.db"
                }
            ]
        };

        using (var key = ReferenceManifestCrypto.LoadPrivateKeyPem(priv))
        {
            manifest.SignatureBase64 = ReferenceManifestCrypto.Sign(manifest, key);
        }

        // Tamper file after signing
        await File.WriteAllBytesAsync(dbPath, "evil"u8.ToArray());
        await File.WriteAllTextAsync(
            Path.Combine(package, "manifest.json"),
            ReferenceManifestCrypto.SerializePretty(manifest));

        var service = new ReferenceUpdateService(
            new ReferenceUpdateOptions { OfflinePackageDirectory = package },
            target,
            pub);

        var result = await service.CheckAndApplyAsync(CancellationToken.None);
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Hash mismatch");
        File.Exists(Path.Combine(target, "pci-reference.db")).Should().BeFalse();
    }

    [Fact]
    public void Wrong_Key_Fails_Verify()
    {
        var root = Path.Combine(Path.GetTempPath(), "irontrace-ref-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var priv1 = Path.Combine(root, "p1.pem");
        var pub1 = Path.Combine(root, "u1.pem");
        var priv2 = Path.Combine(root, "p2.pem");
        var pub2 = Path.Combine(root, "u2.pem");
        ReferenceManifestCrypto.GenerateKeyPair(priv1, pub1);
        ReferenceManifestCrypto.GenerateKeyPair(priv2, pub2);

        var manifest = new ReferenceUpdateManifest
        {
            ManifestVersion = 1,
            Algorithm = "ECDSA-P256-SHA256",
            Artifacts =
            [
                new ReferenceArtifactSpec
                {
                    FileName = "x.db",
                    SchemaVersion = 1,
                    DatabaseSha256 = "aa",
                    SizeBytes = 1,
                    ContentUri = "x.db"
                }
            ]
        };

        using (var key = ReferenceManifestCrypto.LoadPrivateKeyPem(priv1))
        {
            manifest.SignatureBase64 = ReferenceManifestCrypto.Sign(manifest, key);
        }

        using var wrong = ReferenceManifestCrypto.LoadPublicKeyPem(pub2);
        ReferenceManifestCrypto.Verify(manifest, wrong).Should().BeFalse();
    }
}

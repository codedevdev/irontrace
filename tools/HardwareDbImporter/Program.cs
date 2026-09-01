using IronTrace.Contracts;
using IronTrace.Contracts.Reference;
using IronTrace.Fingerprints;

static class Program
{
    static async Task<int> Main(string[] args)
    {
        string? mode = null;
        string? input = null;
        string? output = null;
        string? privateKey = null;
        string? publicKey = null;
        string? packageDir = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--mode" or "-m" && i + 1 < args.Length) mode = args[++i];
            else if (args[i] is "--input" or "-i" && i + 1 < args.Length) input = args[++i];
            else if (args[i] is "--output" or "-o" && i + 1 < args.Length) output = args[++i];
            else if (args[i] is "--private-key" && i + 1 < args.Length) privateKey = args[++i];
            else if (args[i] is "--public-key" && i + 1 < args.Length) publicKey = args[++i];
            else if (args[i] is "--package" && i + 1 < args.Length) packageDir = args[++i];
        }

        mode ??= "pci";

        try
        {
            switch (mode.ToLowerInvariant())
            {
                case "pci":
                    Require(input, output, "pci");
                    Console.WriteLine($"Importing (pci) {input} -> {output}");
                    await PciIdsImporter.ImportAsync(input!, output!);
                    break;
                case "usb":
                    Require(input, output, "usb");
                    Console.WriteLine($"Importing (usb) {input} -> {output}");
                    await UsbIdsImporter.ImportAsync(input!, output!);
                    break;
                case "loldrivers":
                    Require(input, output, "loldrivers");
                    Console.WriteLine($"Importing (loldrivers) {input} -> {output}");
                    await LolDriversImporter.ImportAsync(input!, output!);
                    break;
                case "gen-keys":
                    if (string.IsNullOrWhiteSpace(privateKey) || string.IsNullOrWhiteSpace(publicKey))
                    {
                        Console.Error.WriteLine("Usage: --mode gen-keys --private-key <out.pem> --public-key <out.pub.pem>");
                        return 1;
                    }

                    ReferenceManifestCrypto.GenerateKeyPair(privateKey, publicKey);
                    Console.WriteLine($"Wrote {privateKey} and {publicKey}");
                    break;
                case "sign-manifest":
                    if (string.IsNullOrWhiteSpace(packageDir) || string.IsNullOrWhiteSpace(privateKey) ||
                        string.IsNullOrWhiteSpace(output))
                    {
                        Console.Error.WriteLine(
                            "Usage: --mode sign-manifest --package <dir-with-dbs> --private-key <pem> --output <manifest.json>");
                        return 1;
                    }

                    await SignManifestAsync(packageDir, privateKey, output);
                    break;
                default:
                    Console.Error.WriteLine($"Unknown mode: {mode}");
                    PrintUsage();
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        Console.WriteLine("Done.");
        return 0;
    }

    private static void Require(string? input, string? output, string mode)
    {
        if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(output))
        {
            Console.Error.WriteLine($"Usage: HardwareDbImporter --mode {mode} --input <file> --output <db>");
            throw new ArgumentException("Missing input/output");
        }
    }

    private static async Task SignManifestAsync(string packageDir, string privateKeyPath, string outputManifest)
    {
        string[] names = ["pci-reference.db", "usb-reference.db", "loldrivers-reference.db"];
        var artifacts = new List<ReferenceArtifactSpec>();
        foreach (var name in names)
        {
            var path = Path.Combine(packageDir, name);
            if (!File.Exists(path))
            {
                continue;
            }

            var fi = new FileInfo(path);
            var schema = name.StartsWith("usb", StringComparison.OrdinalIgnoreCase)
                ? IronTraceVersions.UsbReferenceDbSchema
                : name.StartsWith("lol", StringComparison.OrdinalIgnoreCase)
                    ? IronTraceVersions.LolDriversDbSchema
                    : IronTraceVersions.ReferenceDbSchema;

            artifacts.Add(new ReferenceArtifactSpec
            {
                FileName = name,
                SchemaVersion = schema,
                DatabaseSha256 = ReferenceManifestCrypto.Sha256HexFile(path),
                SizeBytes = fi.Length,
                ContentUri = name,
                RetrievedAt = DateTimeOffset.UtcNow.ToString("O")
            });
        }

        if (artifacts.Count == 0)
        {
            throw new InvalidOperationException($"No reference DBs found in {packageDir}");
        }

        var manifest = new ReferenceUpdateManifest
        {
            ManifestVersion = 1,
            Algorithm = "ECDSA-P256-SHA256",
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            Artifacts = artifacts
        };

        using var key = ReferenceManifestCrypto.LoadPrivateKeyPem(privateKeyPath);
        manifest.SignatureBase64 = ReferenceManifestCrypto.Sign(manifest, key);
        await File.WriteAllTextAsync(outputManifest, ReferenceManifestCrypto.SerializePretty(manifest));
        Console.WriteLine($"Signed manifest with {artifacts.Count} artifact(s) -> {outputManifest}");
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine(
            """
            Usage:
              HardwareDbImporter --mode pci --input <pci.ids> --output <pci-reference.db>
              HardwareDbImporter --mode usb --input <usb.ids> --output <usb-reference.db>
              HardwareDbImporter --mode loldrivers --input <drivers.json> --output <loldrivers-reference.db>
              HardwareDbImporter --mode gen-keys --private-key <priv.pem> --public-key <pub.pem>
              HardwareDbImporter --mode sign-manifest --package <dir> --private-key <priv.pem> --output <manifest.json>
            """);
    }
}

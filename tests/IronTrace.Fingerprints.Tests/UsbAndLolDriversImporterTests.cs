using FluentAssertions;
using IronTrace.Contracts.Hardware;
using IronTrace.Fingerprints;
using Microsoft.Extensions.Logging.Abstractions;

namespace IronTrace.Fingerprints.Tests;

public class UsbAndLolDriversImporterTests
{
    [Fact]
    public async Task UsbIds_Import_And_Resolve()
    {
        var usbIds = """
            # test
            046D  Logitech, Inc.
            	C077  M105 Optical Mouse
            """;
        var dir = Path.Combine(Path.GetTempPath(), "irontrace-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var idsPath = Path.Combine(dir, "usb.ids");
        var dbPath = Path.Combine(dir, "usb-reference.db");
        await File.WriteAllTextAsync(idsPath, usbIds);

        await UsbIdsImporter.ImportAsync(idsPath, dbPath);
        await using var provider = new LocalUsbIdsProvider(dbPath, NullLogger<LocalUsbIdsProvider>.Instance);
        var resolved = await provider.ResolveAsync(new UsbDeviceIdentity(0x046D, 0xC077, null), CancellationToken.None);
        resolved.Should().NotBeNull();
        resolved!.VendorName.Should().Contain("Logitech");
        resolved.ProductName.Should().Contain("M105");
    }

    [Fact]
    public async Task LolDrivers_Import_And_Match_By_Hash_And_Name()
    {
        var json = """
            [
              {
                "Id": "capcom-example",
                "Category": "vulnerable driver",
                "Tags": ["Capcom.sys"],
                "KnownVulnerableSamples": [
                  { "Filename": "capcom.sys", "SHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
                ]
              }
            ]
            """;
        var dir = Path.Combine(Path.GetTempPath(), "irontrace-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var jsonPath = Path.Combine(dir, "drivers.json");
        var dbPath = Path.Combine(dir, "loldrivers-reference.db");
        await File.WriteAllTextAsync(jsonPath, json);

        await LolDriversImporter.ImportAsync(jsonPath, dbPath);
        await using var provider = new LocalLolDriversProvider(dbPath, NullLogger<LocalLolDriversProvider>.Instance);

        var byHash = await provider.MatchBySha256Async(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CancellationToken.None);
        byHash.Should().NotBeNull();
        byHash!.MatchKind.Should().Be("sha256");

        var byName = await provider.MatchByFileNameAsync("CAPCOM.SYS", CancellationToken.None);
        byName.Should().NotBeNull();
        byName!.MatchKind.Should().Be("filename");
    }
}

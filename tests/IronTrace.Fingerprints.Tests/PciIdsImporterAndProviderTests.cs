using FluentAssertions;
using IronTrace.Contracts.Hardware;
using IronTrace.Fingerprints;
using Microsoft.Extensions.Logging.Abstractions;

namespace IronTrace.Fingerprints.Tests;

public class PciIdsImporterAndProviderTests
{
    [Fact]
    public async Task Import_And_Resolve_KnownDevice()
    {
        var pciIds = """
            # test pci.ids
            8086  Intel Corporation
            	15F3  Ethernet Connection (2) I225-V
            		0000 8086  Ethernet Connection (2) I225-V
            10EC  Realtek Semiconductor Co., Ltd.
            	8125  RTL8125 2.5GbE Controller
            		87D7 1043  RTL8125B
            C 02  Network controller
            	00  Ethernet controller
            		00  Ethernet controller
            """;

        var dir = Path.Combine(Path.GetTempPath(), "irontrace-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var idsPath = Path.Combine(dir, "pci.ids");
        var dbPath = Path.Combine(dir, "pci-reference.db");
        await File.WriteAllTextAsync(idsPath, pciIds);

        await PciIdsImporter.ImportAsync(idsPath, dbPath);

        await using var provider = new LocalPciIdsProvider(dbPath, NullLogger<LocalPciIdsProvider>.Instance);
        var identity = new PciDeviceIdentity(0x8086, 0x15F3, 0x8086, 0x0000, 0x00, 0x02, 0x00, 0x00);
        var resolved = await provider.ResolveAsync(identity, CancellationToken.None);

        resolved.Should().NotBeNull();
        resolved!.VendorName.Should().Contain("Intel");
        resolved.DeviceName.Should().Contain("I225");
        resolved.Source.Should().Be("pci.ids");

        var missing = await provider.ResolveAsync(
            new PciDeviceIdentity(0xFFFF, 0xFFFF, null, null, null, null, null, null),
            CancellationToken.None);
        missing.Should().BeNull();
    }
}

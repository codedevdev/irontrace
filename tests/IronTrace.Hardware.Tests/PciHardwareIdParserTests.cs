using FluentAssertions;
using IronTrace.Hardware.Parsing;

namespace IronTrace.Hardware.Tests;

public class PciHardwareIdParserTests
{
    [Theory]
    [InlineData("PCI\\VEN_8086&DEV_15F3", 0x8086, 0x15F3, null, null, null)]
    [InlineData("PCI\\VEN_8086&DEV_15F3&SUBSYS_00008086", 0x8086, 0x15F3, 0x8086, 0x0000, null)]
    [InlineData("PCI\\VEN_10EC&DEV_8125&SUBSYS_87D71043&REV_05", 0x10EC, 0x8125, 0x1043, 0x87D7, (byte)0x05)]
    [InlineData("pci\\ven_10de&dev_2484&subsys_146219da&rev_a1", 0x10DE, 0x2484, 0x19DA, 0x1462, (byte)0xA1)]
    public void TryParse_ValidIds_Succeeds(
        string hardwareId,
        int vendorId,
        int deviceId,
        int? subsystemVendorId,
        int? subsystemDeviceId,
        byte? revision)
    {
        var ok = PciHardwareIdParser.TryParse(hardwareId, out var identity);

        ok.Should().BeTrue();
        identity.VendorId.Should().Be((ushort)vendorId);
        identity.DeviceId.Should().Be((ushort)deviceId);
        identity.SubsystemVendorId.Should().Be((ushort?)subsystemVendorId);
        identity.SubsystemDeviceId.Should().Be((ushort?)subsystemDeviceId);
        identity.Revision.Should().Be(revision);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("USB\\VID_1234&PID_5678")]
    [InlineData("PCI\\VEN_GGGG&DEV_15F3")]
    [InlineData("PCI\\VEN_8086")]
    [InlineData("PCI\\VEN_8086&DEV_15F")]
    [InlineData("PCI\\VEN_8086&DEV_15F3&SUBSYS_ABCD")]
    [InlineData("PCI\\VEN_8086&DEV_15F3&REV_ZZ")]
    public void TryParse_Malformed_Fails(string? hardwareId)
    {
        PciHardwareIdParser.TryParse(hardwareId, out _).Should().BeFalse();
    }

    [Fact]
    public void TryParseClassCode_ParsesCompatibleId()
    {
        var ok = PciHardwareIdParser.TryParseClassCode("PCI\\CC_020000", out var cc, out var sc, out var pi);

        ok.Should().BeTrue();
        cc.Should().Be(0x02);
        sc.Should().Be(0x00);
        pi.Should().Be(0x00);
    }

    [Fact]
    public void ParseFirst_UsesFirstValidHardwareId()
    {
        var ids = new[]
        {
            "PCI\\VEN_8086&DEV_15F3&CC_020000",
            "PCI\\VEN_8086&DEV_15F3&SUBSYS_00008086&REV_00"
        };

        var identity = PciHardwareIdParser.ParseFirst(ids);

        identity.Should().NotBeNull();
        identity!.VendorId.Should().Be(0x8086);
        identity.DeviceId.Should().Be(0x15F3);
    }
}

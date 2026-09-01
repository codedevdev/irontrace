using FluentAssertions;
using IronTrace.Hardware.Parsing;

namespace IronTrace.Hardware.Tests;

public class UsbHardwareIdParserTests
{
    [Fact]
    public void Parses_VidPid()
    {
        UsbHardwareIdParser.TryParse("USB\\VID_046D&PID_C077&REV_0001", out var id).Should().BeTrue();
        id.VendorId.Should().Be(0x046D);
        id.ProductId.Should().Be(0xC077);
        id.DeviceRelease.Should().Be(0x0001);
    }
}

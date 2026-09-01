using System.Runtime.InteropServices;
using FluentAssertions;
using IronTrace.Contracts;
using IronTrace.Contracts.Driver;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Capabilities;

namespace IronTrace.Core.Tests;

public class DriverProtocolTests
{
    [Fact]
    public void Versions_Are_P1P2()
    {
        IronTraceVersions.Application.Should().Be("0.7.0");
        IronTraceVersions.ReportSchema.Should().Be("1.6");
        IronTraceVersions.DriverProtocol.Should().Be(2);
        DriverProtocol.Version.Should().Be(2);
        IronTraceCapabilities.Phase1["KernelDriver"].Should().Be(CapabilityStatus.Supported);
        IronTraceCapabilities.Phase1["DeviceResetChallenge"].Should().Be(CapabilityStatus.Partial);
        IronTraceCapabilities.Phase1["SpdmAttestation"].Should().Be(CapabilityStatus.Partial);
        IronTraceCapabilities.Phase1["MeasuredBootEvidence"].Should().Be(CapabilityStatus.Partial);
    }

    [Fact]
    public void Struct_Sizes_Match_Packed_Layout()
    {
        Marshal.SizeOf<IronTraceBdf>().Should().Be(4);
        Marshal.SizeOf<IronTraceProtocolInfo>().Should().Be(24);
        Marshal.SizeOf<IronTraceReadPciConfigRequest>().Should().Be(8);
        Marshal.SizeOf<IronTraceReadPciConfigResponseHeader>().Should().Be(4);
        Marshal.SizeOf<IronTraceEnumCapsRequest>().Should().Be(8);
        Marshal.SizeOf<IronTraceCapabilityEntry>().Should().Be(8);
        Marshal.SizeOf<IronTraceEnumCapsResponseHeader>().Should().Be(4);
        Marshal.SizeOf<IronTraceQueryBarRequest>().Should().Be(4);
        Marshal.SizeOf<IronTraceBarInfo>().Should().Be(20);
        Marshal.SizeOf<IronTraceQueryBarResponse>().Should().Be(4 + 20 * 6);
        Marshal.SizeOf<IronTraceQueryExpressRequest>().Should().Be(4);
        Marshal.SizeOf<IronTraceQueryExpressResponse>().Should().Be(12);
        Marshal.SizeOf<IronTraceSafeResetRequest>().Should().Be(8);
    }

    [Fact]
    public void CtlCodes_Are_Stable_And_SafeReset_Never_Advertised()
    {
        DriverProtocol.IoctlGetProtocolInfo.Should().Be(DriverProtocol.CtlCode(0x8000, 0x800, 0, 0));
        DriverProtocol.IoctlReadPciConfig.Should().Be(DriverProtocol.CtlCode(0x8000, 0x801, 0, 0));
        DriverProtocol.IoctlSafeDeviceReset.Should().Be(DriverProtocol.CtlCode(0x8000, 0x805, 0, 0));
        (DriverProtocol.MvpCapabilityFlags & DriverProtocol.CapSafeDeviceReset).Should().Be(0u);
        (DriverProtocol.Protocol2CapabilityFlags & DriverProtocol.CapSafeDeviceReset).Should().Be(0u);
        (DriverProtocol.Protocol2CapabilityFlags & DriverProtocol.CapQueryBarSizeProbe).Should().NotBe(0u);
    }

    [Fact]
    public void Protocol_Negotiation_Accepts_V1_And_V2()
    {
        DriverProtocol.IsCompatible(1).Should().BeTrue();
        DriverProtocol.IsCompatible(2).Should().BeTrue();
        DriverProtocol.IsCompatible(0).Should().BeFalse();
        DriverProtocol.IsCompatible(3).Should().BeFalse();
    }

    [Fact]
    public void Bdf_Validation()
    {
        new IronTraceBdf(0, 31, 7).IsValid().Should().BeTrue();
        new IronTraceBdf(0, 32, 0).IsValid().Should().BeFalse();
        new IronTraceBdf(0, 0, 8).IsValid().Should().BeFalse();
    }
}

using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Hardware.Classification;

namespace IronTrace.Hardware.Tests;

public class DeviceKindClassifierTests
{
    [Fact]
    public void HyperV_Netvsc_Is_Virtual()
    {
        var result = DeviceKindClassifier.Classify(
            @"VMBUS\{guid}\0",
            "netvsc",
            "Microsoft Hyper-V Network Adapter",
            "Hyper-V Virtual Ethernet Adapter",
            "Microsoft",
            [@"VMBUS\"]);
        result.Kind.Should().Be(DeviceKind.VirtualOrSoftware);
        result.Reason.Should().Contain("service");
    }

    [Fact]
    public void WireGuard_Is_Virtual()
    {
        var result = DeviceKindClassifier.Classify(
            @"ROOT\NET\0001",
            "wireguard",
            "WireGuard Tunnel",
            "WireGuard Tunnel",
            "WireGuard LLC",
            [@"ROOT\NET\0001"]);
        result.Kind.Should().Be(DeviceKind.VirtualOrSoftware);
    }

    [Fact]
    public void PhysicalGpu_Is_Physical()
    {
        var result = DeviceKindClassifier.Classify(
            @"PCI\VEN_10DE&DEV_2484\...",
            "nvlddmkm",
            "NVIDIA GeForce RTX 3070",
            "NVIDIA GeForce RTX 3070",
            "NVIDIA",
            [@"PCI\VEN_10DE&DEV_2484"]);
        result.Kind.Should().Be(DeviceKind.Physical);
        result.Reason.Should().BeNull();
    }

    [Fact]
    public void Marketing_Virtual_Alone_Is_Not_Enough()
    {
        var result = DeviceKindClassifier.Classify(
            @"PCI\VEN_8086&DEV_15F3\...",
            "e2fexpress",
            "Intel Virtual Something Marketing Name",
            "Ethernet",
            "Intel",
            [@"PCI\VEN_8086&DEV_15F3"]);
        result.Kind.Should().Be(DeviceKind.Physical);
    }

    [Fact]
    public void Root_Prefix_Is_Virtual()
    {
        var result = DeviceKindClassifier.Classify(
            @"ROOT\SYSTEM\0000",
            null,
            "System device",
            null,
            null,
            [@"ROOT\SYSTEM\0000"]);
        result.Kind.Should().Be(DeviceKind.VirtualOrSoftware);
        result.Reason.Should().Contain("idPrefix");
    }
}

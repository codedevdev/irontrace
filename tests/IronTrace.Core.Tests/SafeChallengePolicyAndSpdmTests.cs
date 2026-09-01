using FluentAssertions;
using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Core.Challenge;

namespace IronTrace.Core.Tests;

public class SafeChallengePolicyEngineTests
{
    private readonly SafeChallengePolicyEngine _engine = new();

    [Theory]
    [InlineData(0x01, 0x00, ChallengePolicyDecision.DenyCritical)]
    [InlineData(0x02, 0x00, ChallengePolicyDecision.DenyCritical)]
    [InlineData(0x03, 0x00, ChallengePolicyDecision.DenyCritical)]
    [InlineData(0x06, 0x04, ChallengePolicyDecision.DenyCritical)]
    [InlineData(0x0C, 0x03, ChallengePolicyDecision.DenyCritical)]
    [InlineData(0x04, 0x01, ChallengePolicyDecision.AllowListedEligible)]
    [InlineData(0x09, 0x00, ChallengePolicyDecision.AllowListedEligible)]
    [InlineData(0x0C, 0x00, ChallengePolicyDecision.DenyDefault)]
    [InlineData(0xFF, 0x00, ChallengePolicyDecision.DenyDefault)]
    public void Classify_Maps_Class_Codes(byte classCode, byte subclass, ChallengePolicyDecision expected)
    {
        var (decision, reason) = SafeChallengePolicyEngine.Classify(classCode, subclass);
        decision.Should().Be(expected);
        reason.Should().NotBeNullOrWhiteSpace();
        if (expected == ChallengePolicyDecision.AllowListedEligible)
            reason.Should().Contain("ExecutionNotEnabled");
    }

    [Fact]
    public void Classify_Missing_Class_Is_Unsupported()
    {
        var (decision, _) = SafeChallengePolicyEngine.Classify(null, null);
        decision.Should().Be(ChallengePolicyDecision.Unsupported);
    }

    [Fact]
    public void Evaluate_Uses_Kernel_Class_When_Usermode_Missing()
    {
        var pci = Pci(null, null, 1, 2, 0);
        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0xF, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 1, 2, 0,
                    0x8086, 0x1234, 0, 0x03, 0x00, 0,
                    Array.Empty<KernelPciCapability>(),
                    Array.Empty<KernelPciBar>(),
                    new KernelPciExpressCaps(true, false, false, false, false, true, null, null, null, null),
                    Array.Empty<string>())
            ]);

        var snap = _engine.Evaluate([pci], kernel);
        snap.Availability.Should().Be(CapabilityStatus.Partial);
        snap.Decisions.Should().ContainSingle();
        snap.Decisions[0].Decision.Should().Be(ChallengePolicyDecision.DenyCritical);
        snap.Decisions[0].SupportsFlr.Should().BeTrue();
        snap.Detail.Should().Contain("no reset");
    }

    [Fact]
    public void Evaluate_Virtual_Devices_DenyDefault()
    {
        var pci = Pci(0x04, 0x00, 0, 0, 0) with { Kind = DeviceKind.VirtualOrSoftware };
        var snap = _engine.Evaluate([pci], null);
        snap.Decisions[0].Decision.Should().Be(ChallengePolicyDecision.DenyDefault);
    }

    private static PciDevice Pci(byte? classCode, byte? subclass, int bus, int dev, int fn)
        => new(
            $"PCI\\VEN_8086&DEV_0001&BUS_{bus}",
            new PciDeviceIdentity(0x8086, 0x0001, null, null, null, classCode, subclass, null),
            "Dev", "Dev", "Intel", null,
            bus, dev, fn, null,
            null, null,
            DeviceKind.Physical,
            Array.Empty<string>(),
            Array.Empty<string>());
}

public class DoeSpdmDetectorTests
{
    private readonly DoeSpdmDetector _detector = new();

    [Fact]
    public void Detect_No_Kernel_Is_Unknown_Not_Suspicious()
    {
        var snap = _detector.Detect(null);
        snap.Availability.Should().Be(CapabilityStatus.Unknown);
        snap.Devices.Should().BeEmpty();
    }

    [Fact]
    public void Detect_No_Doe_Is_Unsupported()
    {
        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0xF, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    null, 0, 1, 0, 0x8086, 0x1, 0, 0x02, 0, 0,
                    [new KernelPciCapability(0x10, 0x40, true)],
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>())
            ]);

        var snap = _detector.Detect(kernel);
        snap.Availability.Should().Be(CapabilityStatus.Unsupported);
        snap.Devices[0].DoePresent.Should().BeFalse();
        snap.Devices[0].SpdmStackStatus.Should().Be(SpdmStackStatus.NotIntegrated);
    }

    [Fact]
    public void Detect_Doe_0x2E_Is_Partial()
    {
        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0xF, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    null, 0, 1, 0, 0x8086, 0x1, 0, 0x02, 0, 0,
                    [new KernelPciCapability(DoeSpdmConstants.DoeExtendedCapabilityId, 0x100, true)],
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>())
            ]);

        var snap = _detector.Detect(kernel);
        snap.Availability.Should().Be(CapabilityStatus.Partial);
        snap.Devices[0].DoePresent.Should().BeTrue();
    }
}

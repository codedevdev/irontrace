using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Scanning;
using IronTrace.Reporting;
using IronTrace.RiskEngine;

namespace IronTrace.Core.Tests;

public class KernelEvidenceReportAndRiskTests
{
    private static ScanSession Session(KernelEvidenceSnapshot? kernel, IReadOnlyList<PciDevice>? pci = null)
        => new(
            Guid.NewGuid(),
            "0.5.1",
            "1.4",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            new OperatingSystemInfo("Windows", "10", "1", "1", "X64", null, null),
            new PlatformSecurityState(
                new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("TPM", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("VBS", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("HVCI", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("Kernel DMA Protection", SecurityFeatureState.Unsupported, null),
                new SecurityFeatureStatus("Virtualization", SecurityFeatureState.Enabled, null),
                false,
                Array.Empty<string>()),
            null,
            pci ?? Array.Empty<PciDevice>(),
            Array.Empty<UsbDevice>(),
            Array.Empty<InventoriedDriver>(),
            Array.Empty<VulnerableDriverMatch>(),
            null,
            null,
            kernel,
            null,
            null,
            null,
            null,
            ScanProfile.HardwareOnly,
            null,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>());

    [Fact]
    public void Export_Includes_KernelEvidence_On_Schema_1_4()
    {
        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Unavailable,
            CapabilityStatus.Unsupported,
            null,
            null,
            null,
            "not installed",
            Array.Empty<KernelPciDeviceEvidence>());

        var json = new JsonScanReportExporter().ToJson(Session(kernel));
        json.Should().Contain("\"schemaVersion\": \"1.4\"");
        json.Should().Contain("kernelEvidence");
        json.Should().Contain("Unavailable");
    }

    [Fact]
    public async Task Risk_Unavailable_Is_Informational_Not_High()
    {
        var engine = new ConservativeRiskAssessmentEngine(
            new Microsoft.Extensions.Logging.Abstractions.NullLogger<ConservativeRiskAssessmentEngine>());
        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Unavailable,
            CapabilityStatus.Unsupported,
            null, null, null, "missing", Array.Empty<KernelPciDeviceEvidence>());

        var result = await engine.AssessAsync(Session(kernel), CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == "KERNEL_EVIDENCE_UNAVAILABLE");
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().NotBe(IntegrityVerdict.HighRisk);
        result.Verdict.Should().NotBe(IntegrityVerdict.Suspicious);
    }

    [Fact]
    public async Task Risk_Identity_Mismatch_Is_Medium_Review()
    {
        var engine = new ConservativeRiskAssessmentEngine(
            new Microsoft.Extensions.Logging.Abstractions.NullLogger<ConservativeRiskAssessmentEngine>());

        var pci = new PciDevice(
            "PCI\\VEN_8086&DEV_1234",
            new PciDeviceIdentity(0x8086, 0x1234, null, null, null, 0x02, 0x00, 0x00),
            "Dev", "Dev", "Intel", "PCI bus 0, device 1, function 0",
            0, 1, 0, null,
            new DriverInfo("svc", "x.sys", "1", "Intel", null, "Signed"),
            new ResolvedIdentity("Intel", "Dev", null, null, "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_8086&DEV_1234"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1,
            DriverProtocolMvpFlags(),
            4096,
            "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 0, 1, 0,
                    0x10EE, 0x9999, 0x00, 0x02, 0x00, 0x00,
                    Array.Empty<KernelPciCapability>(),
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>())
            ]);

        var result = await engine.AssessAsync(Session(kernel, [pci]), CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == "KERNEL_PCI_IDENTITY_MISMATCH");
        result.Findings.Single(f => f.Code == "KERNEL_PCI_IDENTITY_MISMATCH").Severity
            .Should().Be(FindingSeverity.Medium);
        result.Verdict.Should().Be(IntegrityVerdict.ReviewRecommended);
    }

    private static uint DriverProtocolMvpFlags()
        => IronTrace.Contracts.Driver.DriverProtocol.MvpCapabilityFlags;
}

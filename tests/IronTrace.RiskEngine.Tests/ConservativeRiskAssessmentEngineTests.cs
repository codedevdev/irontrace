using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Scanning;
using IronTrace.RiskEngine;

namespace IronTrace.RiskEngine.Tests;

public class ConservativeRiskAssessmentEngineTests
{
    private static ScanSession Session(
        PlatformSecurityState? security = null,
        IReadOnlyList<PciDevice>? pci = null,
        IReadOnlyList<UsbDevice>? usb = null,
        IReadOnlyList<VulnerableDriverMatch>? matches = null,
        CodeIntegrityLogSnapshot? ci = null,
        IdentityConsistencyReport? identity = null,
        KernelEvidenceSnapshot? kernel = null,
        IReadOnlyList<string>? errors = null)
        => new(
            Guid.NewGuid(), "0.2.0", "1.2", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            new OperatingSystemInfo("Windows", "10", "1", "1", "X64", null, null),
            security,
            null,
            pci ?? Array.Empty<PciDevice>(),
            usb ?? Array.Empty<UsbDevice>(),
            Array.Empty<InventoriedDriver>(),
            matches ?? Array.Empty<VulnerableDriverMatch>(),
            ci,
            identity,
            kernel,
            null,
            null,
            null,
            null,
            ScanProfile.HardwareOnly,
            null,
            null,
            null,
            errors ?? Array.Empty<string>(),
            new Dictionary<string, string>());

    private static PlatformSecurityState DefaultSecurity()
        => new(
            new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Enabled, null),
            new SecurityFeatureStatus("TPM", SecurityFeatureState.Enabled, "2.0"),
            new SecurityFeatureStatus("VBS", SecurityFeatureState.Enabled, null),
            new SecurityFeatureStatus("HVCI", SecurityFeatureState.Enabled, null),
            new SecurityFeatureStatus("Kernel DMA Protection", SecurityFeatureState.Unsupported, null),
            new SecurityFeatureStatus("Virtualization", SecurityFeatureState.Enabled, null),
            false,
            Array.Empty<string>());

    private static ConservativeRiskAssessmentEngine Engine()
        => new(new Microsoft.Extensions.Logging.Abstractions.NullLogger<ConservativeRiskAssessmentEngine>());

    [Fact]
    public async Task Assess_UnknownDevice_ProducesLowFinding_NotHighRisk()
    {
        var device = new PciDevice(
            "PCI\\VEN_FFFF&DEV_FFFF",
            new PciDeviceIdentity(0xFFFF, 0xFFFF, null, null, null, 0x02, 0x00, 0x00),
            "Mystery",
            "Mystery",
            "Unknown",
            null, 0, 1, 0, null,
            new DriverInfo("mystery", "mystery.sys", "1.0", "Acme", null, "Unknown"),
            Resolved: null,
            DeviceKind.Physical,
            ["PCI\\VEN_FFFF&DEV_FFFF"],
            Array.Empty<string>());

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [device]), CancellationToken.None);

        result.Findings.Should().Contain(f => f.Code == "UNKNOWN_PCI_DEVICE");
        result.Verdict.Should().Be(IntegrityVerdict.ReviewRecommended);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
    }

    [Fact]
    public async Task Assess_UnsupportedDma_DoesNotCreateSuspiciousFinding()
    {
        var session = Session(
            new PlatformSecurityState(
                new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("TPM", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("VBS", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("HVCI", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("Kernel DMA Protection", SecurityFeatureState.Unsupported, "unsupported"),
                new SecurityFeatureStatus("Virtualization", SecurityFeatureState.Enabled, null),
                false,
                Array.Empty<string>()));

        var result = await Engine().AssessAsync(session, CancellationToken.None);

        result.Findings.Should().NotContain(f => f.Code.Contains("DMA", StringComparison.OrdinalIgnoreCase) && f.Severity >= FindingSeverity.Medium);
        result.Verdict.Should().Be(IntegrityVerdict.Normal);
    }

    [Fact]
    public async Task Assess_LolDriversHashMatch_IsMedium_NotHigh()
    {
        var session = Session(
            new PlatformSecurityState(
                new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("TPM", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("VBS", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("HVCI", SecurityFeatureState.Disabled, null),
                new SecurityFeatureStatus("Kernel DMA Protection", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("Virtualization", SecurityFeatureState.Enabled, null),
                false,
                Array.Empty<string>()),
            matches:
            [
                new VulnerableDriverMatch(
                    "sha256",
                    FindingConfidence.High,
                    "capcom.sys",
                    "aaaa",
                    "capcom-example",
                    "Capcom.sys",
                    "vulnerable driver",
                    "hash match",
                    @"C:\windows\system32\drivers\capcom.sys")
            ]);

        var result = await Engine().AssessAsync(session, CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == "VULNERABLE_DRIVER_MATCH" && f.Severity == FindingSeverity.Medium);
        result.Findings.Should().Contain(f => f.Code == "VULNERABLE_DRIVER_BLOCKLIST_GAP");
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().Be(IntegrityVerdict.ReviewRecommended);
    }

    [Fact]
    public async Task Assess_CodeIntegrityEvents_ProduceLowFindings()
    {
        var ci = new CodeIntegrityLogSnapshot(
            true, null, DateTimeOffset.UtcNow.AddDays(-7), DateTimeOffset.UtcNow, 7, 2,
            [
                new CodeIntegrityEvent(3004, DateTimeOffset.UtcNow, @"C:\temp\bad.sys", null, "unsigned", null),
                new CodeIntegrityEvent(3076, DateTimeOffset.UtcNow, @"C:\temp\blocked.sys", null, "audit", null)
            ]);

        var result = await Engine().AssessAsync(Session(ci: ci), CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == "CI_UNSIGNED_OR_INVALID_IMAGE");
        result.Findings.Should().Contain(f => f.Code == "CI_WDAC_AUDIT_OR_BLOCK");
    }

    [Fact]
    public async Task Assess_UnknownUsb_ProducesLowFinding()
    {
        var usb = new UsbDevice(
            "USB\\VID_FFFF&PID_FFFF\\1",
            new UsbDeviceIdentity(0xFFFF, 0xFFFF, null),
            "Mystery USB",
            "Mystery USB",
            null,
            null,
            null,
            null,
            ["USB\\VID_FFFF&PID_FFFF"]);

        var result = await Engine().AssessAsync(Session(usb: [usb]), CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == "UNKNOWN_USB_DEVICE");
    }

    [Fact]
    public async Task Assess_StockPcileechIdentity_IsMedium_NotHigh()
    {
        var device = new PciDevice(
            "PCI\\VEN_10EE&DEV_0666",
            new PciDeviceIdentity(0x10EE, 0x0666, 0x10EE, 0x0007, 0x02, 0x02, 0x00, 0x00),
            "Xilinx Ethernet Adapter",
            "Xilinx Ethernet Adapter",
            "Xilinx",
            null, 1, 0, 0, null,
            new DriverInfo("xilinx", "x.sys", "1", "Xilinx", null, "Signed"),
            new ResolvedIdentity("Xilinx", "Device", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_10EE&DEV_0666"],
            Array.Empty<string>());

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [device]), CancellationToken.None);

        result.Findings.Should().Contain(f =>
            f.Code == "STOCK_PCILEECH_IDENTITY" &&
            f.Severity == FindingSeverity.Medium &&
            f.Confidence == FindingConfidence.High);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().Be(IntegrityVerdict.ReviewRecommended);
    }

    [Fact]
    public async Task Assess_DuplicatePciIdentity_IsMedium()
    {
        PciDevice Clone(string instanceId) => new(
            instanceId,
            new PciDeviceIdentity(0x10EC, 0x8168, 0x1043, 0x1234, 0x15, 0x02, 0x00, 0x00),
            "Realtek",
            "Realtek",
            "Realtek",
            null, 2, 0, 0, null,
            new DriverInfo("rt64", "rt64win7.sys", "1", "Realtek", null, "Signed"),
            new ResolvedIdentity("Realtek", "RTL8168", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            [$"PCI\\VEN_10EC&DEV_8168\\{instanceId}"],
            Array.Empty<string>());

        var result = await Engine().AssessAsync(
            Session(DefaultSecurity(), [Clone("A"), Clone("B")]),
            CancellationToken.None);

        result.Findings.Should().Contain(f =>
            f.Code == "DUPLICATE_PCI_IDENTITY" && f.Severity == FindingSeverity.Medium);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
    }

    [Fact]
    public async Task Assess_DonorClassWithoutDriver_ProducesMismatchFinding()
    {
        var device = new PciDevice(
            "PCI\\VEN_10EC&DEV_8153",
            new PciDeviceIdentity(0x10EC, 0x8153, null, null, null, 0x02, 0x00, 0x00),
            "Realtek USB NIC",
            "Realtek USB NIC",
            "Realtek",
            null, 3, 0, 0, null,
            Driver: null,
            new ResolvedIdentity("Realtek", "RTL8153", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_10EC&DEV_8153"],
            Array.Empty<string>());

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [device]), CancellationToken.None);

        result.Findings.Should().Contain(f => f.Code == "DRIVER_MISSING");
        result.Findings.Should().Contain(f =>
            f.Code == "DONOR_IDENTITY_DRIVER_MISMATCH" && f.Severity == FindingSeverity.Low);
    }

    [Fact]
    public async Task Assess_DefaultPcileechCapLayout_IsMedium()
    {
        var pci = new PciDevice(
            "PCI\\VEN_10EE&DEV_0666",
            new PciDeviceIdentity(0x10EE, 0x0666, null, null, null, 0x02, 0x00, 0x00),
            "Dev", "Dev", "Xilinx", null,
            0, 1, 0, null,
            new DriverInfo("svc", "x.sys", "1", "Xilinx", null, "Signed"),
            new ResolvedIdentity("Xilinx", "Dev", null, null, "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_10EE&DEV_0666"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1,
            0,
            4096,
            "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 0, 1, 0,
                    0x10EE, 0x0666, 0x02, 0x02, 0x00, 0x00,
                    [
                        new KernelPciCapability(0x01, 0x40, false),
                        new KernelPciCapability(0x05, 0x50, false),
                        new KernelPciCapability(0x10, 0x60, false)
                    ],
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>())
            ]);

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [pci], kernel: kernel), CancellationToken.None);

        result.Findings.Should().Contain(f => f.Code == "STOCK_PCILEECH_IDENTITY");
        result.Findings.Should().Contain(f =>
            f.Code == "PCILEECH_DEFAULT_CAP_LAYOUT" && f.Severity == FindingSeverity.Medium);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Findings.Single(f => f.Code == "STOCK_PCILEECH_IDENTITY").TriageHint.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Assess_BarShape_NetworkZeroBars_IsLow()
    {
        var pci = new PciDevice(
            "PCI\\VEN_10EC&DEV_8168",
            new PciDeviceIdentity(0x10EC, 0x8168, null, null, null, 0x02, 0x00, 0x00),
            "NIC", "NIC", "Realtek", null,
            0, 2, 0, null,
            new DriverInfo("rt", "rt.sys", "1", "Realtek", null, "Signed"),
            new ResolvedIdentity("Realtek", "RTL8168", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_10EC&DEV_8168"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 0, 2, 0,
                    0x10EC, 0x8168, 0x15, 0x02, 0x00, 0x00,
                    Array.Empty<KernelPciCapability>(),
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>())
            ]);

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [pci], kernel: kernel), CancellationToken.None);

        result.Findings.Should().Contain(f =>
            f.Code == "PCI_BAR_SHAPE_ANOMALY" && f.Severity == FindingSeverity.Low);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().NotBe(IntegrityVerdict.Suspicious);
    }

    [Fact]
    public async Task Assess_KernelClassMismatch_IsMedium_NotSuspicious()
    {
        var pci = new PciDevice(
            "PCI\\VEN_8086&DEV_1539",
            new PciDeviceIdentity(0x8086, 0x1539, null, null, null, 0x02, 0x00, 0x00),
            "NIC", "NIC", "Intel", null,
            0, 3, 0, null,
            new DriverInfo("e1i", "e1i65x64.sys", "1", "Intel", null, "Signed"),
            new ResolvedIdentity("Intel", "I211", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_8086&DEV_1539"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 0, 3, 0,
                    0x8086, 0x1539, 0x03, 0x01, 0x06, 0x00, // class storage vs UM network
                    Array.Empty<KernelPciCapability>(),
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>())
            ]);

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [pci], kernel: kernel), CancellationToken.None);

        result.Findings.Should().Contain(f =>
            f.Code == "KERNEL_PCI_CLASS_MISMATCH" &&
            f.Severity == FindingSeverity.Medium &&
            f.TriageHint != null);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().NotBe(IntegrityVerdict.Suspicious);
    }

    [Fact]
    public async Task Assess_ZeroDsn_IsInformational()
    {
        var pci = new PciDevice(
            "PCI\\VEN_8086&DEV_1539",
            new PciDeviceIdentity(0x8086, 0x1539, null, null, null, 0x02, 0x00, 0x00),
            "NIC", "NIC", "Intel", null,
            0, 4, 0, null,
            new DriverInfo("e1i", "e1i.sys", "1", "Intel", null, "Signed"),
            new ResolvedIdentity("Intel", "I211", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_8086&DEV_1539"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 0, 4, 0,
                    0x8086, 0x1539, 0x03, 0x02, 0x00, 0x00,
                    [new KernelPciCapability(0x0003, 0x100, true)],
                    Array.Empty<KernelPciBar>(),
                    null,
                    Array.Empty<string>(),
                    DeviceSerialNumberHex: "0000000000000000")
            ]);

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [pci], kernel: kernel), CancellationToken.None);

        result.Findings.Should().Contain(f =>
            f.Code == "PCI_DSN_WEAK_SIGNAL" && f.Severity == FindingSeverity.Information);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().NotBe(IntegrityVerdict.Suspicious);
    }

    [Fact]
    public async Task Assess_StockTinyBar_IsMedium()
    {
        var pci = new PciDevice(
            "PCI\\VEN_10EE&DEV_0666",
            new PciDeviceIdentity(0x10EE, 0x0666, null, null, null, 0x02, 0x00, 0x00),
            "Dev", "Dev", "Xilinx", null,
            0, 5, 0, null,
            new DriverInfo("svc", "x.sys", "1", "Xilinx", null, "Signed"),
            new ResolvedIdentity("Xilinx", "Dev", null, null, "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_10EE&DEV_0666"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            1, 0, 4096, "ok",
            [
                new KernelPciDeviceEvidence(
                    pci.InstanceId, 0, 5, 0,
                    0x10EE, 0x0666, 0x02, 0x02, 0x00, 0x00,
                    Array.Empty<KernelPciCapability>(),
                    [new KernelPciBar(0, "Memory32", 0xF0000000, 0x1000)],
                    null,
                    Array.Empty<string>())
            ]);

        var result = await Engine().AssessAsync(Session(DefaultSecurity(), [pci], kernel: kernel), CancellationToken.None);

        result.Findings.Should().Contain(f =>
            f.Code == "PCI_BAR_SHAPE_ANOMALY" && f.Severity == FindingSeverity.Medium);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
    }
}

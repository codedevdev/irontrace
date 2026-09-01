using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Reporting;
using IronTrace.Contracts.Scanning;
using IronTrace.Reporting;

namespace IronTrace.Core.Tests;

public class JsonReportExporterTests
{
    [Fact]
    public void Export_OmitsRawSerial_By_Default_And_IsVersioned()
    {
        var session = new ScanSession(
            Guid.NewGuid(),
            "0.2.0",
            "1.2",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            new OperatingSystemInfo("Windows", "10", "26100", "24H2", "X64", "Client", "Professional"),
            null,
            new MotherboardInfo("ASUS", "BOARD", "Rev", SerialRaw: "SHOULD_NOT_APPEAR", SerialHash: "abc", SerialHandling.Hashed, "AMI", "1.0", "2024-01-01", "UEFI"),
            Array.Empty<PciDevice>(),
            Array.Empty<UsbDevice>(),
            Array.Empty<InventoriedDriver>(),
            Array.Empty<VulnerableDriverMatch>(),
            null, // CodeIntegrity
            null, // IdentityConsistency
            null, // KernelEvidence
            null, // ChallengeEvidence
            null, // SpdmEvidence
            null, // MeasuredBootEvidence
            null, // PnPHistory
            ScanProfile.HardwareOnly,
            null, // ScanConsent
            null, // ForensicEvidence
            null, // RiskAssessment
            Array.Empty<string>(),
            new Dictionary<string, string> { ["k"] = "v" });

        var json = new JsonScanReportExporter().ToJson(session);
        json.Should().Contain("\"schemaVersion\": \"1.2\"");
        json.Should().Contain("ironTraceVersion");
        json.Should().Contain("usbDevices");
        json.Should().Contain("abc");
        json.Should().NotContain("SHOULD_NOT_APPEAR");
    }

    [Fact]
    public void Export_Respects_Privacy_Toggles()
    {
        var session = new ScanSession(
            Guid.NewGuid(),
            "0.2.0",
            "1.2",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            null,
            null,
            new MotherboardInfo("ASUS", "BOARD", "Rev", SerialRaw: "RAW123", SerialHash: "hashhash", SerialHandling.Raw, null, null, null, null),
            Array.Empty<PciDevice>(),
            Array.Empty<UsbDevice>(),
            [new InventoriedDriver("svc", "drv", @"C:\windows\system32\drivers\x.sys", "aa", "x.sys", null, "Services")],
            Array.Empty<VulnerableDriverMatch>(),
            new CodeIntegrityLogSnapshot(true, null, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 7, 0, Array.Empty<CodeIntegrityEvent>()),
            null, // IdentityConsistency
            null, // KernelEvidence
            null, // ChallengeEvidence
            null, // SpdmEvidence
            null, // MeasuredBootEvidence
            null, // PnPHistory
            ScanProfile.HardwareOnly,
            null, // ScanConsent
            null, // ForensicEvidence
            null, // RiskAssessment
            Array.Empty<string>(),
            new Dictionary<string, string>());

        var stripped = new ExportPrivacyOptions(
            IncludeSerialHash: false,
            IncludeDriverImagePaths: false,
            IncludeCodeIntegrityEvents: false,
            IncludeInstanceIds: false,
            IncludeRawSerial: false);
        var json = new JsonScanReportExporter().ToJson(session, stripped);
        json.Should().NotContain("hashhash");
        json.Should().NotContain("RAW123");
        json.Should().NotContain(@"C:\\windows\\system32\\drivers\\x.sys");
        json.Should().NotContain("codeIntegrity");

        var withRaw = new ExportPrivacyOptions(IncludeRawSerial: true);
        var rawJson = new JsonScanReportExporter().ToJson(session, withRaw);
        rawJson.Should().Contain("RAW123");
    }
}

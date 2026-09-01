using FluentAssertions;
using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Reporting;
using IronTrace.Contracts.Scanning;
using IronTrace.Reporting;
using IronTrace.RiskEngine;
using IronTrace.Windows.Collectors;

namespace IronTrace.Core.Tests;

public class Phase5EvidenceReportAndRiskTests
{
    private static ScanSession Session(
        ChallengeEvidenceSnapshot? challenge = null,
        SpdmEvidenceSnapshot? spdm = null,
        MeasuredBootEvidenceSnapshot? measured = null,
        KernelEvidenceSnapshot? kernel = null)
        => new(
            Guid.NewGuid(),
            "0.5.1",
            "1.4",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            new OperatingSystemInfo("Windows", "10", "1", "1", "X64", null, null),
            new PlatformSecurityState(
                new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("TPM", SecurityFeatureState.Enabled, "TPM present (2.0)."),
                new SecurityFeatureStatus("VBS", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("HVCI", SecurityFeatureState.Enabled, null),
                new SecurityFeatureStatus("Kernel DMA Protection", SecurityFeatureState.Unsupported, null),
                new SecurityFeatureStatus("Virtualization", SecurityFeatureState.Enabled, null),
                false,
                Array.Empty<string>()),
            null,
            Array.Empty<PciDevice>(),
            Array.Empty<UsbDevice>(),
            Array.Empty<InventoriedDriver>(),
            Array.Empty<VulnerableDriverMatch>(),
            null,
            null,
            kernel,
            challenge,
            spdm,
            measured,
            null,
            ScanProfile.HardwareOnly,
            null,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>());

    [Fact]
    public void Export_Includes_Phase5_Sections_On_Schema_1_4()
    {
        var challenge = new ChallengeEvidenceSnapshot(
            CapabilityStatus.Partial,
            "policy",
            [
                new ChallengeDeviceDecision(0, 1, 0, 0x03, 0x00, ChallengePolicyDecision.DenyCritical, "GPU", false)
            ]);
        var spdm = new SpdmEvidenceSnapshot(
            CapabilityStatus.Unsupported,
            "no DOE",
            Array.Empty<SpdmDeviceEvidence>());
        var measured = new MeasuredBootEvidenceSnapshot(
            CapabilityStatus.Unknown,
            true,
            "2.0",
            null,
            Array.Empty<PcrDigestEntry>(),
            "TBS failed");

        var json = new JsonScanReportExporter().ToJson(Session(challenge, spdm, measured));
        json.Should().Contain("\"schemaVersion\": \"1.4\"");
        json.Should().Contain("challengeEvidence");
        json.Should().Contain("DenyCritical");
        json.Should().Contain("spdmEvidence");
        json.Should().Contain("measuredBootEvidence");
        json.Should().Contain("includePcrDigests");
    }

    [Fact]
    public void Export_Omits_Pcr_Digests_When_Privacy_Toggled()
    {
        var measured = new MeasuredBootEvidenceSnapshot(
            CapabilityStatus.Supported,
            true,
            "2.0",
            "sha256",
            [new PcrDigestEntry(0, "aabbcc")],
            "ok");

        var privacy = new ExportPrivacyOptions(IncludePcrDigests: false);
        var json = new JsonScanReportExporter().ToJson(Session(measured: measured), privacy);
        json.Should().Contain("measuredBootEvidence");
        json.Should().NotContain("aabbcc");
    }

    [Fact]
    public async Task Risk_Missing_Spdm_And_Tpm_Never_Suspicious()
    {
        var engine = new ConservativeRiskAssessmentEngine(
            new Microsoft.Extensions.Logging.Abstractions.NullLogger<ConservativeRiskAssessmentEngine>());

        var spdm = new SpdmEvidenceSnapshot(
            CapabilityStatus.Unsupported, "none", Array.Empty<SpdmDeviceEvidence>());
        var measured = new MeasuredBootEvidenceSnapshot(
            CapabilityStatus.Unknown, null, null, null, Array.Empty<PcrDigestEntry>(), "fail");
        var challenge = new ChallengeEvidenceSnapshot(
            CapabilityStatus.Partial,
            "policy",
            [
                new ChallengeDeviceDecision(0, 0, 0, 0x04, 0x00, ChallengePolicyDecision.AllowListedEligible, "ExecutionNotEnabled", null)
            ]);

        var result = await engine.AssessAsync(Session(challenge, spdm, measured), CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == "SAFE_CHALLENGE_POLICY_APPLIED");
        result.Findings.Should().NotContain(f => f.Code.Contains("SPDM") && f.Severity >= FindingSeverity.Low);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
        result.Verdict.Should().NotBe(IntegrityVerdict.Suspicious);
        result.Verdict.Should().NotBe(IntegrityVerdict.HighRisk);
    }

    [Fact]
    public void Pcr_Command_Builder_Is_Stable_Size()
    {
        var cmd = MeasuredBootCollector.BuildPcrReadCommandSha256_0_7();
        cmd.Length.Should().Be(20);
        cmd[17].Should().Be(0xFF);
    }

    [Fact]
    public void Pcr_Response_Parser_Reads_Digests()
    {
        // Minimal synthetic response: header(10) + update(4) + selCount(4)=0 + digestCount(4)=1 + size(2)=2 + aa bb
        var response = new byte[10 + 4 + 4 + 4 + 2 + 2];
        response[10 + 4 + 4] = 0;
        response[10 + 4 + 4 + 1] = 0;
        response[10 + 4 + 4 + 2] = 0;
        response[10 + 4 + 4 + 3] = 1; // digestCount = 1 (big-endian)
        // Actually Write big-endian: digestCount at offset 18
        // offset: 10 header, +4 update = 14, +4 selCount=0 at 14 → 18, digestCount at 18
        Array.Clear(response);
        // header unused
        // pcrUpdateCounter at 10
        // selCount = 0 at 14
        response[14] = 0; response[15] = 0; response[16] = 0; response[17] = 0;
        // digestCount = 1 at 18
        response[18] = 0; response[19] = 0; response[20] = 0; response[21] = 1;
        // size = 2 at 22
        response[22] = 0; response[23] = 2;
        response[24] = 0xAA; response[25] = 0xBB;

        var list = new List<PcrDigestEntry>();
        MeasuredBootCollector.ParsePcrReadResponse(response.AsSpan(0, 26), list);
        list.Should().ContainSingle();
        list[0].Index.Should().Be(0);
        list[0].DigestHex.Should().Be("aabb");
    }
}

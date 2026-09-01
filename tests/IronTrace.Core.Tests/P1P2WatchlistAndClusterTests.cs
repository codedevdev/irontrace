using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Findings;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Reference;
using IronTrace.Contracts.Scanning;
using IronTrace.Fingerprints;
using IronTrace.Reporting;
using IronTrace.RiskEngine;
using Microsoft.Extensions.Logging.Abstractions;

namespace IronTrace.Core.Tests;

public class P1P2WatchlistAndClusterTests
{
    private static ScanSession Session(
        IReadOnlyList<PciDevice>? pci = null,
        KernelEvidenceSnapshot? kernel = null,
        PnPHistorySnapshot? pnp = null)
        => new(
            Guid.NewGuid(),
            "0.6.0",
            "1.5",
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
            pnp,
            ScanProfile.HardwareOnly,
            null,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>());

    [Fact]
    public async Task Watchlist_NonStock_Emits_DmaWatchlistHit()
    {
        var watchlist = new FakeWatchlist(new DmaWatchlistEntry(
            0x1234, 0xABCD, null, null, "Lab custom", "review", null));
        var engine = new ConservativeRiskAssessmentEngine(
            watchlist,
            NullLogger<ConservativeRiskAssessmentEngine>.Instance);

        var device = new PciDevice(
            "PCI\\VEN_1234&DEV_ABCD\\1",
            new PciDeviceIdentity(0x1234, 0xABCD, null, null, null, 0x02, 0x00, 0x00),
            "Custom", "Custom", "Lab", null, 1, 0, 0, null,
            new DriverInfo("x", "x.sys", "1", "Lab", null, "Signed"),
            new ResolvedIdentity("Lab", "Custom", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_1234&DEV_ABCD"],
            Array.Empty<string>());

        var result = await engine.AssessAsync(Session([device]), CancellationToken.None);
        result.Findings.Should().Contain(f =>
            f.Code == DmaMasqueradeFindingCodes.DmaWatchlistHit &&
            f.Severity == FindingSeverity.Medium);
        result.Findings.Should().NotContain(f => f.Code == DmaMasqueradeFindingCodes.StockPcileechIdentity);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
    }

    [Fact]
    public async Task Cluster_Emits_When_Two_Dma_Codes_Share_Instance()
    {
        var engine = new ConservativeRiskAssessmentEngine(
            NullLogger<ConservativeRiskAssessmentEngine>.Instance);

        var instanceId = "PCI\\VEN_10EE&DEV_0666\\1";
        var device = new PciDevice(
            instanceId,
            new PciDeviceIdentity(0x10EE, 0x0666, 0x10EE, 0x0007, 0x02, 0x02, 0x00, 0x00),
            "Xilinx", "Xilinx", "Xilinx", null, 1, 0, 0, null,
            new DriverInfo("x", "x.sys", "1", "Xilinx", null, "Signed"),
            new ResolvedIdentity("Xilinx", "Device", null, "Network", "pci.ids", null, FindingConfidence.ReferenceIdentity),
            DeviceKind.Physical,
            ["PCI\\VEN_10EE&DEV_0666"],
            Array.Empty<string>());

        var kernel = new KernelEvidenceSnapshot(
            KernelDriverAvailability.Available,
            CapabilityStatus.Supported,
            2,
            IronTrace.Contracts.Driver.DriverProtocol.Protocol2CapabilityFlags,
            4096,
            "ok",
            [
                new KernelPciDeviceEvidence(
                    instanceId, 1, 0, 0,
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

        var result = await engine.AssessAsync(Session([device], kernel), CancellationToken.None);
        result.Findings.Should().Contain(f => f.Code == DmaMasqueradeFindingCodes.StockPcileechIdentity);
        result.Findings.Should().Contain(f => f.Code == DmaMasqueradeFindingCodes.PcileechDefaultCapLayout);
        result.Findings.Should().Contain(f => f.Code == DmaMasqueradeFindingCodes.DmaSignalCluster);
        result.Findings.Single(f => f.Code == DmaMasqueradeFindingCodes.DmaSignalCluster)
            .Severity.Should().Be(FindingSeverity.Information);
    }

    [Fact]
    public async Task PnP_History_OptIn_Hit_Is_Medium()
    {
        var engine = new ConservativeRiskAssessmentEngine(
            NullLogger<ConservativeRiskAssessmentEngine>.Instance);
        var pnp = new PnPHistorySnapshot(
            CapabilityStatus.Partial,
            OptInEnabled: true,
            "hit",
            [new PnPHistoryHit(@"PCI\VEN_10EE&DEV_0666\OLD", 0x10EE, 0x0666, "old", false)]);

        var result = await engine.AssessAsync(Session(pnp: pnp), CancellationToken.None);
        result.Findings.Should().Contain(f =>
            f.Code == DmaMasqueradeFindingCodes.PnpHistoryWatchlistHit &&
            f.Severity == FindingSeverity.Medium);
        result.Findings.Should().NotContain(f => f.Severity >= FindingSeverity.High);
    }

    [Fact]
    public void Export_Includes_PnPHistory_On_Schema_1_5()
    {
        var pnp = new PnPHistorySnapshot(
            CapabilityStatus.Supported,
            OptInEnabled: true,
            "ok",
            Array.Empty<PnPHistoryHit>());
        var json = new JsonScanReportExporter().ToJson(Session(pnp: pnp));
        json.Should().Contain("\"schemaVersion\": \"1.5\"");
        json.Should().Contain("pnpHistory");
        json.Should().Contain("optInEnabled");
    }

    [Fact]
    public void FileDmaWatchlist_BuiltIn_Matches_Stock()
    {
        var provider = new FileDmaWatchlistProvider(NullLogger<FileDmaWatchlistProvider>.Instance);
        var id = new PciDeviceIdentity(0x10EE, 0x0666, null, null, null, null, null, null);
        provider.TryMatch(id, out var match).Should().BeTrue();
        match.VendorId.Should().Be(0x10EE);
        match.DeviceId.Should().Be(0x0666);
    }

    private sealed class FakeWatchlist : IDmaWatchlistProvider
    {
        private readonly DmaWatchlistEntry _entry;
        public FakeWatchlist(DmaWatchlistEntry entry) => _entry = entry;
        public IReadOnlyList<DmaWatchlistEntry> Entries => [_entry];
        public bool TryMatch(PciDeviceIdentity identity, out DmaWatchlistEntry match)
        {
            if (DmaWatchlistMatching.Matches(_entry, identity.VendorId, identity.DeviceId,
                    identity.SubsystemVendorId, identity.SubsystemDeviceId))
            {
                match = _entry;
                return true;
            }

            match = null!;
            return false;
        }
    }
}

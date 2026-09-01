using IronTrace.Contracts;
using IronTrace.Contracts.Reference;
using IronTrace.Contracts.Reporting;
using IronTrace.Contracts.Scanning;
using IronTrace.Core.Challenge;
using IronTrace.Core.Paths;
using IronTrace.Core.Scanning;
using IronTrace.Fingerprints;
using IronTrace.Forensics.DependencyInjection;
using IronTrace.Hardware.Collectors;
using IronTrace.Hardware.Signing;
using IronTrace.Reporting;
using IronTrace.RiskEngine;
using IronTrace.Windows.Collectors;
using IronTrace.Windows.Driver;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IronTrace.Cli;

internal static class ScanHostBuilder
{
    public static IHost Build(string[] args)
    {
        IronTracePaths.EnsureCreated();
        return Host.CreateDefaultBuilder(args)
            .ConfigureServices(services =>
            {
                services.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Information));
                services.AddSingleton(new PrivacyScanOptions());
                services.AddSingleton(new ElevatedSecurityOptions());
                services.AddSingleton<IOperatingSystemCollector, OperatingSystemCollector>();
                services.AddSingleton<IPlatformSecurityCollector>(sp =>
                    new PlatformSecurityCollector(
                        sp.GetRequiredService<ILogger<PlatformSecurityCollector>>(),
                        sp.GetRequiredService<ElevatedSecurityOptions>()));
                services.AddSingleton<IMotherboardCollector, MotherboardCollector>();
                services.AddSingleton<IDriverSignatureAnalyzer, DriverSignatureAnalyzer>();
                services.AddSingleton<IPciInventoryCollector, PciInventoryCollector>();
                services.AddSingleton<IUsbInventoryCollector, UsbInventoryCollector>();
                services.AddSingleton<IIdentityConsistencyCollector, IdentityConsistencyCollector>();
                services.AddSingleton<IIronTraceDriverClient, IronTraceDriverClient>();
                services.AddSingleton<IKernelEvidenceCollector, KernelEvidenceCollector>();
                services.AddSingleton<ISafeChallengePolicyEngine, SafeChallengePolicyEngine>();
                services.AddSingleton<IDoeSpdmDetector, DoeSpdmDetector>();
                services.AddSingleton<IMeasuredBootEvidenceCollector, MeasuredBootCollector>();
                services.AddSingleton<IDmaWatchlistProvider>(sp =>
                {
                    var path = ResolveRef("dma-watchlist.json");
                    var logger = sp.GetRequiredService<ILogger<FileDmaWatchlistProvider>>();
                    return File.Exists(path) ? new FileDmaWatchlistProvider(path, logger) : new FileDmaWatchlistProvider(logger);
                });
                services.AddSingleton<IPnPHistoryCollector, PnPHistoryCollector>();
                services.AddSingleton<ICodeIntegrityLogCollector>(sp =>
                    new CodeIntegrityLogCollector(
                        sp.GetRequiredService<ILogger<CodeIntegrityLogCollector>>(),
                        sp.GetRequiredService<ElevatedSecurityOptions>()));
                services.AddSingleton<ISerialPrivacyService, DpapiSerialPrivacyService>();
                services.AddSingleton<IRiskAssessmentEngine, ConservativeRiskAssessmentEngine>();
                services.AddSingleton<IScanReportExporter, JsonScanReportExporter>();
                services.AddSingleton<ISelfAuditHtmlExporter, SelfAuditHtmlExporter>();
                services.AddSingleton<IHardwareReferenceProvider>(sp =>
                    new LocalPciIdsProvider(ResolveRef("pci-reference.db"), sp.GetRequiredService<ILogger<LocalPciIdsProvider>>()));
                services.AddSingleton<IUsbReferenceProvider>(sp =>
                    new LocalUsbIdsProvider(ResolveRef("usb-reference.db"), sp.GetRequiredService<ILogger<LocalUsbIdsProvider>>()));
                services.AddSingleton<ILolDriversProvider>(sp =>
                    new LocalLolDriversProvider(ResolveRef("loldrivers-reference.db"), sp.GetRequiredService<ILogger<LocalLolDriversProvider>>()));
                services.AddSingleton<ILolDriversMatchService, LolDriversMatchService>();
                services.AddSingleton<IDriverInventoryCollector, DriverInventoryCollector>();
                services.AddIronTraceForensics(ResolveRef("cheat-signatures.json"));
                services.AddSingleton<IScanOrchestrator, ScanOrchestrator>();
            })
            .Build();
    }

    private static string ResolveRef(string fileName)
    {
        var bundled = Path.Combine(AppContext.BaseDirectory, "reference", fileName);
        if (File.Exists(bundled))
            return bundled;
        var repo = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "data", "reference", fileName));
        return File.Exists(repo) ? repo : bundled;
    }
}

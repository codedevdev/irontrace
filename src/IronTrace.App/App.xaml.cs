using System.IO;
using System.Windows;
using IronTrace.App.Services;
using IronTrace.App.ViewModels;
using IronTrace.App.Views;
using IronTrace.Contracts;
using IronTrace.Contracts.Reference;
using IronTrace.Core.Challenge;
using IronTrace.Core.Paths;
using IronTrace.Core.Scanning;
using IronTrace.Fingerprints;
using IronTrace.Hardware.Collectors;
using IronTrace.Hardware.Signing;
using IronTrace.Forensics.DependencyInjection;
using IronTrace.Reporting;
using IronTrace.RiskEngine;
using IronTrace.Windows.Collectors;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IronTrace.App;

public partial class App : Application
{
    private IHost? _host;
    private Mutex? _singleInstanceMutex;

    protected override async void OnStartup(StartupEventArgs e)
    {
        const string mutexName = @"Local\IronTrace.SingleInstance.v1";
        _singleInstanceMutex = new Mutex(true, mutexName, out var createdNew);
        if (!createdNew)
        {
            MessageBox.Show(
                "IronTrace is already running.",
                "IronTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            Shutdown();
            return;
        }

        IronTracePaths.EnsureCreated();
        ConfigureLogging();

        _host = Host.CreateDefaultBuilder()
            .ConfigureAppConfiguration(cfg =>
            {
                cfg.SetBasePath(AppContext.BaseDirectory);
                cfg.AddJsonFile("appsettings.json", optional: true, reloadOnChange: false);
            })
            .ConfigureServices((context, services) =>
            {
                var refUpdate = new ReferenceUpdateOptions();
                context.Configuration.GetSection(ReferenceUpdateOptions.SectionName).Bind(refUpdate);
                var elevated = new ElevatedSecurityOptions();
                context.Configuration.GetSection(ElevatedSecurityOptions.SectionName).Bind(elevated);
                var serverUpload = new ServerUploadOptions();
                context.Configuration.GetSection(ServerUploadOptions.SectionName).Bind(serverUpload);
                var privacy = new PrivacyScanOptions();
                context.Configuration.GetSection(PrivacyScanOptions.SectionName).Bind(privacy);
                services.AddSingleton(refUpdate);
                services.AddSingleton(elevated);
                services.AddSingleton(serverUpload);
                services.AddSingleton(privacy);
                services.AddSingleton<DpapiUploadApiKeyStore>();
                services.AddHttpClient("IronTraceUpload");
                services.AddSingleton<IScanUploadService, ScanUploadService>();

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
                services.AddSingleton<IronTrace.Windows.Driver.IIronTraceDriverClient, IronTrace.Windows.Driver.IronTraceDriverClient>();
                services.AddSingleton<IKernelEvidenceCollector, IronTrace.Windows.Driver.KernelEvidenceCollector>();
                services.AddSingleton<ISafeChallengePolicyEngine, SafeChallengePolicyEngine>();
                services.AddSingleton<IDoeSpdmDetector, DoeSpdmDetector>();
                services.AddSingleton<IMeasuredBootEvidenceCollector, MeasuredBootCollector>();
                services.AddSingleton<IDmaWatchlistProvider>(sp =>
                {
                    var logger = sp.GetRequiredService<ILogger<FileDmaWatchlistProvider>>();
                    var path = ResolveReferenceDbPath("dma-watchlist.json");
                    return File.Exists(path)
                        ? new FileDmaWatchlistProvider(path, logger)
                        : new FileDmaWatchlistProvider(logger);
                });
                services.AddSingleton<IPnPHistoryCollector, PnPHistoryCollector>();
                services.AddSingleton<ICodeIntegrityLogCollector>(sp =>
                    new CodeIntegrityLogCollector(
                        sp.GetRequiredService<ILogger<CodeIntegrityLogCollector>>(),
                        sp.GetRequiredService<ElevatedSecurityOptions>()));
                services.AddSingleton<ISerialPrivacyService, DpapiSerialPrivacyService>();
                services.AddSingleton<IRiskAssessmentEngine>(sp =>
                    new ConservativeRiskAssessmentEngine(
                        sp.GetRequiredService<IDmaWatchlistProvider>(),
                        sp.GetRequiredService<ILogger<ConservativeRiskAssessmentEngine>>()));
                services.AddSingleton<IScanReportExporter, JsonScanReportExporter>();
                services.AddSingleton<ISelfAuditHtmlExporter, SelfAuditHtmlExporter>();
                services.AddSingleton<IHardwareReferenceProvider>(sp =>
                {
                    var logger = sp.GetRequiredService<ILogger<LocalPciIdsProvider>>();
                    var path = ResolveReferenceDbPath("pci-reference.db");
                    return new LocalPciIdsProvider(path, logger);
                });
                services.AddSingleton<IUsbReferenceProvider>(sp =>
                {
                    var logger = sp.GetRequiredService<ILogger<LocalUsbIdsProvider>>();
                    var path = ResolveReferenceDbPath("usb-reference.db");
                    return new LocalUsbIdsProvider(path, logger);
                });
                services.AddSingleton<ILolDriversProvider>(sp =>
                {
                    var logger = sp.GetRequiredService<ILogger<LocalLolDriversProvider>>();
                    var path = ResolveReferenceDbPath("loldrivers-reference.db");
                    return new LocalLolDriversProvider(path, logger);
                });
                services.AddSingleton<ILolDriversMatchService, LolDriversMatchService>();
                services.AddSingleton<IDriverInventoryCollector, DriverInventoryCollector>();
                services.AddSingleton<IReferenceUpdateService>(sp =>
                {
                    var opts = sp.GetRequiredService<ReferenceUpdateOptions>();
                    var logger = sp.GetRequiredService<ILogger<ReferenceUpdateService>>();
                    return new ReferenceUpdateService(
                        opts,
                        IronTracePaths.Reference,
                        ResolvePublicKeyPath(opts.PublicKeyRelativePath),
                        logger);
                });
                services.AddIronTraceForensics(ResolveReferenceDbPath("cheat-signatures.json"));
                services.AddSingleton<IScanOrchestrator, ScanOrchestrator>();
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<MainWindow>();
            })
            .ConfigureLogging((context, logging) =>
            {
                logging.ClearProviders();
                logging.AddDebug();
                logging.AddConsole();
                logging.AddProvider(new FileLoggerProvider(IronTracePaths.Logs));
            })
            .Build();

        await _host.StartAsync();

        var window = _host.Services.GetRequiredService<MainWindow>();
        window.DataContext = _host.Services.GetRequiredService<MainViewModel>();
        MainWindow = window;
        window.Show();

        base.OnStartup(e);
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            await _host.StopAsync(TimeSpan.FromSeconds(2));
            _host.Dispose();
        }

        _singleInstanceMutex?.ReleaseMutex();
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }

    private static string ResolveReferenceDbPath(string fileName)
    {
        var local = Path.Combine(IronTracePaths.Reference, fileName);
        if (File.Exists(local))
        {
            return local;
        }

        var bundled = Path.Combine(AppContext.BaseDirectory, "reference", fileName);
        if (File.Exists(bundled))
        {
            return bundled;
        }

        // Repo-relative fallback for `dotnet run` from source tree
        var repo = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "data", "reference", fileName));
        return File.Exists(repo) ? repo : bundled;
    }

    private static string ResolvePublicKeyPath(string relativePath)
    {
        relativePath = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var bundled = Path.Combine(AppContext.BaseDirectory, relativePath);
        if (File.Exists(bundled))
        {
            return bundled;
        }

        var local = Path.Combine(IronTracePaths.Reference, "trust", Path.GetFileName(relativePath));
        if (File.Exists(local))
        {
            return local;
        }

        var repo = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "data", relativePath));
        return File.Exists(repo) ? repo : bundled;
    }

    private static void ConfigureLogging()
    {
        // Placeholder for early bootstrap; host configures providers.
    }
}

internal sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _directory;

    public FileLoggerProvider(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(_directory, categoryName);

    public void Dispose()
    {
    }
}

internal sealed class FileLogger : ILogger
{
    private readonly string _path;
    private readonly string _category;
    private static readonly object Gate = new();

    public FileLogger(string directory, string category)
    {
        _category = category;
        _path = Path.Combine(directory, $"irontrace-{DateTime.UtcNow:yyyyMMdd}.log");
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var line = $"{DateTimeOffset.UtcNow:O} [{logLevel}] {_category}: {formatter(state, exception)}";
        if (exception is not null)
        {
            line += Environment.NewLine + exception;
        }

        lock (Gate)
        {
            File.AppendAllText(_path, line + Environment.NewLine);
        }
    }
}

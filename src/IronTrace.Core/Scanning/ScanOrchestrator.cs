using IronTrace.Contracts;
using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Reference;
using IronTrace.Contracts.Scanning;
using IronTrace.Core.Challenge;
using Microsoft.Extensions.Logging;

namespace IronTrace.Core.Scanning;

public interface IOperatingSystemCollector
{
    Task<OperatingSystemInfo> CollectAsync(CancellationToken cancellationToken);
}

public interface IPlatformSecurityCollector
{
    Task<PlatformSecurityState> CollectAsync(CancellationToken cancellationToken);
}

public interface IMotherboardCollector
{
    Task<MotherboardInfo> CollectAsync(CancellationToken cancellationToken);
}

public interface IPciInventoryCollector
{
    Task<IReadOnlyList<PciDevice>> CollectAsync(CancellationToken cancellationToken);
}

public interface IUsbInventoryCollector
{
    Task<IReadOnlyList<UsbDevice>> CollectAsync(CancellationToken cancellationToken);
}

public interface IDriverInventoryCollector
{
    Task<(IReadOnlyList<InventoriedDriver> Drivers, IReadOnlyList<VulnerableDriverMatch> Matches)> CollectAsync(
        IReadOnlyList<PciDevice> pciDevices,
        CancellationToken cancellationToken);
}

public interface ILolDriversMatchService
{
    Task<VulnerableDriverMatch?> MatchBySha256Async(string sha256Hex, CancellationToken cancellationToken);

    Task<VulnerableDriverMatch?> MatchByFileNameAsync(string fileName, CancellationToken cancellationToken);
}

public interface ICodeIntegrityLogCollector
{
    Task<CodeIntegrityLogSnapshot> CollectAsync(CancellationToken cancellationToken);
}

public interface IIdentityConsistencyCollector
{
    Task<IdentityConsistencyReport> CollectAsync(MotherboardInfo? board, CancellationToken cancellationToken);
}

public interface IKernelEvidenceCollector
{
    Task<KernelEvidenceSnapshot> CollectAsync(
        IReadOnlyList<PciDevice> pciDevices,
        CancellationToken cancellationToken);
}

public interface IMeasuredBootEvidenceCollector
{
    Task<MeasuredBootEvidenceSnapshot> CollectAsync(
        PlatformSecurityState? platformSecurity,
        CancellationToken cancellationToken);
}

public interface IPnPHistoryCollector
{
    Task<PnPHistorySnapshot> CollectAsync(
        IReadOnlyList<PciDevice> currentPci,
        CancellationToken cancellationToken);
}

public interface IRiskAssessmentEngine
{
    Task<Contracts.Findings.RiskAssessment> AssessAsync(
        ScanSession sessionDraft,
        CancellationToken cancellationToken);
}

public interface IScanOrchestrator
{
    Task<ScanSession> RunAsync(
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken,
        ScanOptions? options = null);
}

public sealed class ScanOrchestrator : IScanOrchestrator
{
    private readonly IOperatingSystemCollector _osCollector;
    private readonly IPlatformSecurityCollector _securityCollector;
    private readonly IMotherboardCollector _motherboardCollector;
    private readonly IPciInventoryCollector _pciCollector;
    private readonly IUsbInventoryCollector _usbCollector;
    private readonly IDriverInventoryCollector _driverCollector;
    private readonly ICodeIntegrityLogCollector _ciCollector;
    private readonly IIdentityConsistencyCollector _identityCollector;
    private readonly IKernelEvidenceCollector _kernelEvidenceCollector;
    private readonly ISafeChallengePolicyEngine _challengePolicy;
    private readonly IDoeSpdmDetector _doeSpdmDetector;
    private readonly IMeasuredBootEvidenceCollector _measuredBootCollector;
    private readonly IPnPHistoryCollector _pnpHistoryCollector;
    private readonly IForensicScanPipeline? _forensicPipeline;
    private readonly IHardwareReferenceProvider _referenceProvider;
    private readonly IUsbReferenceProvider _usbReferenceProvider;
    private readonly ILolDriversProvider _lolDriversProvider;
    private readonly IRiskAssessmentEngine _riskEngine;
    private readonly ILogger<ScanOrchestrator> _logger;

    public ScanOrchestrator(
        IOperatingSystemCollector osCollector,
        IPlatformSecurityCollector securityCollector,
        IMotherboardCollector motherboardCollector,
        IPciInventoryCollector pciCollector,
        IUsbInventoryCollector usbCollector,
        IDriverInventoryCollector driverCollector,
        ICodeIntegrityLogCollector ciCollector,
        IIdentityConsistencyCollector identityCollector,
        IKernelEvidenceCollector kernelEvidenceCollector,
        ISafeChallengePolicyEngine challengePolicy,
        IDoeSpdmDetector doeSpdmDetector,
        IMeasuredBootEvidenceCollector measuredBootCollector,
        IPnPHistoryCollector pnpHistoryCollector,
        IHardwareReferenceProvider referenceProvider,
        IUsbReferenceProvider usbReferenceProvider,
        ILolDriversProvider lolDriversProvider,
        IRiskAssessmentEngine riskEngine,
        ILogger<ScanOrchestrator> logger,
        IForensicScanPipeline? forensicPipeline = null)
    {
        _osCollector = osCollector;
        _securityCollector = securityCollector;
        _motherboardCollector = motherboardCollector;
        _pciCollector = pciCollector;
        _usbCollector = usbCollector;
        _driverCollector = driverCollector;
        _ciCollector = ciCollector;
        _identityCollector = identityCollector;
        _kernelEvidenceCollector = kernelEvidenceCollector;
        _challengePolicy = challengePolicy;
        _doeSpdmDetector = doeSpdmDetector;
        _measuredBootCollector = measuredBootCollector;
        _pnpHistoryCollector = pnpHistoryCollector;
        _forensicPipeline = forensicPipeline;
        _referenceProvider = referenceProvider;
        _usbReferenceProvider = usbReferenceProvider;
        _lolDriversProvider = lolDriversProvider;
        _riskEngine = riskEngine;
        _logger = logger;
    }

    public async Task<ScanSession> RunAsync(
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken,
        ScanOptions? options = null)
    {
        options ??= ScanOptions.Default;
        var started = DateTimeOffset.UtcNow;
        var errors = new List<string>();
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["hostMachineNameHash"] = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(Environment.MachineName))).ToLowerInvariant()[..16]
        };

        OperatingSystemInfo? os = null;
        PlatformSecurityState? security = null;
        MotherboardInfo? board = null;
        IReadOnlyList<PciDevice> devices = Array.Empty<PciDevice>();
        IReadOnlyList<UsbDevice> usbDevices = Array.Empty<UsbDevice>();
        IReadOnlyList<InventoriedDriver> drivers = Array.Empty<InventoriedDriver>();
        IReadOnlyList<VulnerableDriverMatch> vulnerableMatches = Array.Empty<VulnerableDriverMatch>();
        CodeIntegrityLogSnapshot? codeIntegrity = null;
        IdentityConsistencyReport? identity = null;
        KernelEvidenceSnapshot? kernelEvidence = null;
        ChallengeEvidenceSnapshot? challengeEvidence = null;
        SpdmEvidenceSnapshot? spdmEvidence = null;
        MeasuredBootEvidenceSnapshot? measuredBootEvidence = null;
        PnPHistorySnapshot? pnpHistory = null;
        ForensicEvidenceSnapshot? forensicEvidence = null;

        metadata["scanProfile"] = options.Profile.ToString();
        Report(progress, "os", "Checking Windows security...", 5);
        try
        {
            os = await SafeCollectAsync(() => _osCollector.CollectAsync(cancellationToken), "OperatingSystem", errors);
            security = await SafeCollectAsync(() => _securityCollector.CollectAsync(cancellationToken), "PlatformSecurity", errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected failure collecting OS/security");
            errors.Add("Unexpected failure collecting OS/security information.");
        }

        Report(progress, "motherboard", "Checking motherboard...", 18);
        try
        {
            board = await SafeCollectAsync(() => _motherboardCollector.CollectAsync(cancellationToken), "Motherboard", errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected failure collecting motherboard");
            errors.Add("Unexpected failure collecting motherboard information.");
        }

        Report(progress, "pci", "Enumerating PCIe devices...", 32);
        try
        {
            var raw = await SafeCollectAsync(() => _pciCollector.CollectAsync(cancellationToken), "PciInventory", errors)
                      ?? Array.Empty<PciDevice>();
            Report(progress, "drivers", "Checking PCI drivers...", 42);
            devices = await ResolvePciDevicesAsync(raw, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected failure collecting PCI inventory");
            errors.Add("Unexpected failure enumerating PCI devices.");
        }

        Report(progress, "kernel", "Collecting kernel PCI evidence...", 48);
        try
        {
            kernelEvidence = await SafeCollectAsync(
                () => _kernelEvidenceCollector.CollectAsync(devices, cancellationToken),
                "KernelEvidence",
                errors);
            if (kernelEvidence is not null)
            {
                metadata["kernelDriverAvailability"] = kernelEvidence.Availability.ToString();
                if (kernelEvidence.ProtocolVersion is not null)
                    metadata["kernelDriverProtocol"] = kernelEvidence.ProtocolVersion.Value.ToString();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Kernel evidence collection failed");
            errors.Add("IronTrace could not complete optional collector 'KernelEvidence'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "challenge", "Evaluating safe challenge policy...", 50);
        try
        {
            challengeEvidence = _challengePolicy.Evaluate(devices, kernelEvidence);
            spdmEvidence = _doeSpdmDetector.Detect(kernelEvidence);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Challenge / SPDM detection failed");
            errors.Add("IronTrace could not complete optional collector 'ChallengeEvidence'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "measuredBoot", "Collecting Measured Boot / PCR evidence...", 51);
        try
        {
            measuredBootEvidence = await SafeCollectAsync(
                () => _measuredBootCollector.CollectAsync(security, cancellationToken),
                "MeasuredBoot",
                errors);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Measured Boot collection failed");
            errors.Add("IronTrace could not complete optional collector 'MeasuredBoot'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "usb", "Enumerating USB devices...", 52);
        try
        {
            var rawUsb = await SafeCollectAsync(() => _usbCollector.CollectAsync(cancellationToken), "UsbInventory", errors)
                         ?? Array.Empty<UsbDevice>();
            usbDevices = await ResolveUsbDevicesAsync(rawUsb, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected failure collecting USB inventory");
            errors.Add("Unexpected failure enumerating USB devices.");
        }

        Report(progress, "driverTrust", "Checking driver trust / LOLDrivers...", 62);
        try
        {
            var result = await _driverCollector.CollectAsync(devices, cancellationToken);
            drivers = result.Drivers;
            vulnerableMatches = result.Matches;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Driver inventory / LOLDrivers match failed");
            errors.Add("IronTrace could not complete optional collector 'DriverInventory'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "codeIntegrity", "Reading Code Integrity logs...", 72);
        try
        {
            codeIntegrity = await SafeCollectAsync(() => _ciCollector.CollectAsync(cancellationToken), "CodeIntegrity", errors);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Code Integrity collection failed");
            errors.Add("IronTrace could not complete optional collector 'CodeIntegrity'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "identity", "Checking identity consistency...", 80);
        try
        {
            identity = await SafeCollectAsync(() => _identityCollector.CollectAsync(board, cancellationToken), "IdentityConsistency", errors);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Identity consistency collection failed");
            errors.Add("IronTrace could not complete optional collector 'IdentityConsistency'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "pnpHistory", "Checking PnP history (if opted in)...", 84);
        try
        {
            pnpHistory = await SafeCollectAsync(
                () => _pnpHistoryCollector.CollectAsync(devices, cancellationToken),
                "PnPHistory",
                errors);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PnP history collection failed");
            errors.Add("IronTrace could not complete optional collector 'PnPHistory'. Affected data will be unknown rather than marked suspicious.");
        }

        Report(progress, "reference", "Comparing hardware references...", 86);
        await AddReferenceMetaAsync(metadata, errors, cancellationToken);

        if (options.IsForensicEnabled && _forensicPipeline is not null)
        {
            try
            {
                forensicEvidence = await _forensicPipeline.CollectAsync(
                    options, drivers, board, progress, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Forensic pipeline failed");
                errors.Add("IronTrace could not complete optional forensic collectors. Affected data will be unknown rather than marked suspicious.");
            }
        }

        var draft = new ScanSession(
            SessionId: Guid.NewGuid(),
            ApplicationVersion: IronTraceVersions.Application,
            ReportSchemaVersion: IronTraceVersions.ReportSchema,
            ScanStartedAt: started,
            ScanCompletedAt: null,
            OperatingSystem: os,
            PlatformSecurity: security,
            Motherboard: board,
            PciDevices: devices,
            UsbDevices: usbDevices,
            Drivers: drivers,
            VulnerableDriverMatches: vulnerableMatches,
            CodeIntegrity: codeIntegrity,
            IdentityConsistency: identity,
            KernelEvidence: kernelEvidence,
            ChallengeEvidence: challengeEvidence,
            SpdmEvidence: spdmEvidence,
            MeasuredBootEvidence: measuredBootEvidence,
            PnPHistory: pnpHistory,
            ScanProfile: options.Profile,
            ScanConsent: options.EffectiveConsent,
            ForensicEvidence: forensicEvidence,
            RiskAssessment: null,
            Errors: errors,
            Metadata: metadata);

        Report(progress, "risk", "Calculating integrity result...", 93);
        Contracts.Findings.RiskAssessment? assessment = null;
        try
        {
            assessment = await _riskEngine.AssessAsync(draft, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Risk assessment failed");
            errors.Add("Risk assessment failed; result remains unverified.");
        }

        Report(progress, "done", "Scan complete.", 100);
        return draft with
        {
            ScanCompletedAt = DateTimeOffset.UtcNow,
            RiskAssessment = assessment,
            Errors = errors
        };
    }

    private async Task AddReferenceMetaAsync(
        Dictionary<string, string> metadata,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        try
        {
            var info = await _referenceProvider.GetInfoAsync(cancellationToken);
            if (info is not null)
            {
                metadata["referenceDbPath"] = info.DatabasePath;
                metadata["referenceDbHash"] = info.ContentHash ?? "";
                metadata["referenceSource"] = info.SourceName;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read PCI reference DB metadata");
            errors.Add("Could not read hardware reference database metadata.");
        }

        try
        {
            var usbInfo = await _usbReferenceProvider.GetInfoAsync(cancellationToken);
            if (usbInfo is not null)
            {
                metadata["usbReferenceDbPath"] = usbInfo.DatabasePath;
                metadata["usbReferenceDbHash"] = usbInfo.ContentHash ?? "";
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "USB reference metadata unavailable");
        }

        try
        {
            var lolInfo = await _lolDriversProvider.GetInfoAsync(cancellationToken);
            if (lolInfo is not null)
            {
                metadata["lolDriversDbPath"] = lolInfo.DatabasePath;
                metadata["lolDriversDbHash"] = lolInfo.ContentHash ?? "";
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "LOLDrivers metadata unavailable");
        }
    }

    private async Task<IReadOnlyList<PciDevice>> ResolvePciDevicesAsync(
        IReadOnlyList<PciDevice> devices,
        CancellationToken cancellationToken)
    {
        var list = new List<PciDevice>(devices.Count);
        foreach (var device in devices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var resolved = await _referenceProvider.ResolveAsync(device.Identity, cancellationToken);
                list.Add(device with { Resolved = resolved });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Reference resolve failed for {InstanceId}", device.InstanceId);
                list.Add(device);
            }
        }

        return list;
    }

    private async Task<IReadOnlyList<UsbDevice>> ResolveUsbDevicesAsync(
        IReadOnlyList<UsbDevice> devices,
        CancellationToken cancellationToken)
    {
        var list = new List<UsbDevice>(devices.Count);
        foreach (var device in devices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var resolved = await _usbReferenceProvider.ResolveAsync(device.Identity, cancellationToken);
                list.Add(device with { Resolved = resolved });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "USB reference resolve failed for {InstanceId}", device.InstanceId);
                list.Add(device);
            }
        }

        return list;
    }

    private async Task<T?> SafeCollectAsync<T>(Func<Task<T>> action, string name, List<string> errors)
        where T : class
    {
        try
        {
            return await action();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Collector {Name} failed", name);
            errors.Add($"IronTrace could not complete optional collector '{name}'. Affected data will be unknown rather than marked suspicious.");
            return null;
        }
    }

    private static void Report(IProgress<ScanProgress>? progress, string stage, string message, double percent)
        => progress?.Report(new ScanProgress(stage, message, percent));
}

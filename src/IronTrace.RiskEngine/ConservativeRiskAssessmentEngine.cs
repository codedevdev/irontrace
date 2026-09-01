using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Findings;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Reference;
using IronTrace.Contracts.Scanning;
using IronTrace.Core.Scanning;
using Microsoft.Extensions.Logging;

namespace IronTrace.RiskEngine;

public sealed class ConservativeRiskAssessmentEngine : IRiskAssessmentEngine
{
    /// <summary>PCI capability IDs and stock pcileech-fpga standard-chain offsets.</summary>
    private const ushort CapIdPowerManagement = 0x01;
    private const ushort CapIdMsi = 0x05;
    private const ushort CapIdPciExpress = 0x10;
    private const ushort StockCapOffsetPm = 0x40;
    private const ushort StockCapOffsetMsi = 0x50;
    private const ushort StockCapOffsetPcie = 0x60;
    private const ushort ExtCapIdDsn = 0x0003;
    private const ulong TinyBarSizeThreshold = 8192;
    private const byte ClassNetwork = 0x02;
    private const ushort StockPcileechVendorId = 0x10EE;
    private const ushort StockPcileechDeviceId = 0x0666;

    private readonly IDmaWatchlistProvider _watchlist;
    private readonly ILogger<ConservativeRiskAssessmentEngine> _logger;

    public ConservativeRiskAssessmentEngine(
        IDmaWatchlistProvider watchlist,
        ILogger<ConservativeRiskAssessmentEngine> logger)
    {
        _watchlist = watchlist;
        _logger = logger;
    }

    public ConservativeRiskAssessmentEngine(ILogger<ConservativeRiskAssessmentEngine> logger)
        : this(new BuiltInDmaWatchlistProvider(), logger)
    {
    }

    public Task<RiskAssessment> AssessAsync(ScanSession sessionDraft, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var findings = new List<Finding>();

        AssessPlatform(sessionDraft, findings);
        AssessDevices(sessionDraft.PciDevices, findings);
        AssessUsb(sessionDraft.UsbDevices, findings);
        AssessVulnerableDrivers(sessionDraft, findings);
        AssessCodeIntegrity(sessionDraft, findings);
        AssessIdentity(sessionDraft, findings);
        AssessKernelEvidence(sessionDraft, findings);
        AssessChallengeEvidence(sessionDraft, findings);
        AssessSpdmEvidence(sessionDraft, findings);
        AssessMeasuredBootEvidence(sessionDraft, findings);
        AssessPnPHistory(sessionDraft, findings);
        AssessDmaSignalClusters(findings);
        ForensicFindingGenerator.AssessForensicEvidence(sessionDraft.ForensicEvidence, findings);

        var informational = findings.Count(f => f.Severity == FindingSeverity.Information);
        var low = findings.Count(f => f.Severity == FindingSeverity.Low);
        var medium = findings.Count(f => f.Severity == FindingSeverity.Medium);
        var high = findings.Count(f => f.Severity == FindingSeverity.High);
        var critical = findings.Count(f => f.Severity == FindingSeverity.Critical);

        var physical = sessionDraft.PciDevices.Where(d => d.Kind != DeviceKind.VirtualOrSoftware).ToList();
        var reviewDevices = physical.Count(NeedsReview);
        var consistent = Math.Max(0, physical.Count - reviewDevices);

        var verdict = MapVerdict(critical, high, medium, low, reviewDevices, sessionDraft.Errors.Count);
        var summary = verdict switch
        {
            IntegrityVerdict.Normal => "No high-severity integrity issues were identified from available user-mode evidence.",
            IntegrityVerdict.LowRisk => "Minor informational or low-severity findings were identified. Review details if needed.",
            IntegrityVerdict.ReviewRecommended => "One or more devices or findings warrant administrator review. This does not prove malicious hardware.",
            IntegrityVerdict.Unverified => "The scan could not produce a complete assessment. Results remain unverified.",
            _ => "Assessment completed with elevated findings. Treat as evidence for review, not an automatic ban."
        };

        _logger.LogInformation(
            "Risk assessment complete: {Verdict}, findings={Count}, reviewDevices={Review}",
            verdict, findings.Count, reviewDevices);

        return Task.FromResult(new RiskAssessment(
            verdict,
            summary,
            informational,
            low,
            medium,
            high,
            critical,
            consistent,
            reviewDevices,
            findings));
    }

    private static void AssessPlatform(ScanSession session, List<Finding> findings)
    {
        var security = session.PlatformSecurity;
        if (security is null)
        {
            findings.Add(Create(
                "PLATFORM_SECURITY_UNAVAILABLE",
                FindingSeverity.Information,
                FindingConfidence.Low,
                "Platform security unavailable",
                "IronTrace could not collect platform security details. This is informational.",
                "PlatformSecurity is null",
                "RiskEngine"));
            return;
        }

        if (security.SecureBoot.State == SecurityFeatureState.Disabled)
        {
            findings.Add(Create(
                "SECURE_BOOT_DISABLED",
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "Secure Boot disabled",
                "Secure Boot is disabled. This is security configuration information, not proof of malicious hardware.",
                security.SecureBoot.Detail ?? "Disabled",
                "PlatformSecurity"));
        }

        if (security.SecureBoot.State == SecurityFeatureState.Enabled &&
            security.VirtualizationBasedSecurity.State == SecurityFeatureState.Disabled)
        {
            findings.Add(Create(
                "PLATFORM_SECURITY_INCONSISTENCY",
                FindingSeverity.Information,
                FindingConfidence.Low,
                "Platform security inconsistency",
                "Secure Boot is enabled while VBS appears disabled. This can be a normal configuration and is informational only.",
                $"SecureBoot={security.SecureBoot.State}; VBS={security.VirtualizationBasedSecurity.State}",
                "PlatformSecurity"));
        }

        // Supported-but-off only — Unsupported must never become a finding by itself.
        if (security.KernelDmaProtection.State == SecurityFeatureState.Disabled)
        {
            findings.Add(Create(
                "KERNEL_DMA_PROTECTION_OFF",
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "Kernel DMA Protection off",
                "Kernel DMA Protection appears supported but disabled. This is posture evidence for review, not proof of a DMA cheat.",
                security.KernelDmaProtection.Detail ?? "Disabled",
                "PlatformSecurity"));
        }
    }

    private void AssessDevices(IReadOnlyList<PciDevice> devices, List<Finding> findings)
    {
        foreach (var device in devices)
        {
            if (device.Kind == DeviceKind.VirtualOrSoftware)
            {
                findings.Add(Create(
                    "VIRTUAL_OR_SOFTWARE_DEVICE",
                    FindingSeverity.Information,
                    FindingConfidence.Medium,
                    "Virtual or software device",
                    "This device appears virtual or software-based (for example Hyper-V or VPN). It is classified separately and is not treated as a DMA signature.",
                    $"{device.FriendlyName ?? device.Description}; {FormatPciId(device.Identity)}",
                    "RiskEngine",
                    device.InstanceId));
                continue;
            }

            if (_watchlist.TryMatch(device.Identity, out var watch))
            {
                var isStock = string.Equals(watch.Severity, "stock", StringComparison.OrdinalIgnoreCase)
                              || (watch.VendorId == StockPcileechVendorId && watch.DeviceId == StockPcileechDeviceId);
                findings.Add(Create(
                    isStock
                        ? DmaMasqueradeFindingCodes.StockPcileechIdentity
                        : DmaMasqueradeFindingCodes.DmaWatchlistHit,
                    FindingSeverity.Medium,
                    FindingConfidence.High,
                    isStock ? "Stock PCILeech-class PCI identity" : "DMA watchlist identity match",
                    isStock
                        ? "This physical device reports the publicly documented stock PCILeech/Squirrel FPGA identity (VEN_10EE&DEV_0666). Legitimate lab Xilinx boards can match; treat as review evidence, not an automatic cheat verdict."
                        : $"This physical device matched the local DMA identity watchlist ({watch.Label}). Treat as review evidence, not an automatic cheat verdict.",
                    $"{FormatPciId(device.Identity)}; watchlist={watch.Label}",
                    "RiskEngine",
                    device.InstanceId));
            }

            if (device.Resolved?.VendorName is null || device.Resolved.DeviceName is null)
            {
                findings.Add(Create(
                    "UNKNOWN_PCI_DEVICE",
                    FindingSeverity.Low,
                    FindingConfidence.Medium,
                    "Unknown PCI device",
                    "The device identity was not found in the local IronTrace reference database. Unknown does not prove malicious hardware.",
                    FormatPciId(device.Identity),
                    "LocalPciIdsProvider",
                    device.InstanceId));
            }
            else if (device.Identity.SubsystemVendorId is not null &&
                     device.Identity.SubsystemDeviceId is not null &&
                     device.Resolved.SubsystemName is null)
            {
                findings.Add(Create(
                    "SUBSYSTEM_NOT_IN_REFERENCE_DB",
                    FindingSeverity.Information,
                    FindingConfidence.ReferenceIdentity,
                    "Subsystem not in reference DB",
                    "The device identity is valid, but this subsystem combination is not present in the current IronTrace reference dataset. This does not prove malicious hardware.",
                    FormatPciId(device.Identity),
                    "LocalPciIdsProvider",
                    device.InstanceId));
            }

            var driverMissing = string.IsNullOrWhiteSpace(device.Driver?.Service) &&
                                string.IsNullOrWhiteSpace(device.Driver?.DriverName);

            if (driverMissing)
            {
                findings.Add(Create(
                    "DRIVER_MISSING",
                    FindingSeverity.Low,
                    FindingConfidence.Low,
                    "Driver metadata missing",
                    "IronTrace could not locate driver service/name metadata for this device. The device remains unverified rather than marked highly suspicious.",
                    device.InstanceId,
                    "PciInventory",
                    device.InstanceId));

                if (IsDonorClassWithoutDriver(device))
                {
                    findings.Add(Create(
                        DmaMasqueradeFindingCodes.DonorIdentityDriverMismatch,
                        FindingSeverity.Low,
                        FindingConfidence.Medium,
                        "Donor-class identity without driver",
                        "A network or storage-class PCI device has a resolved identity but no bound driver metadata. Partial DMA CFW dump-emu can look like this; many benign broken installs can too. Review evidence only.",
                        $"{FormatPciId(device.Identity)}; class={device.Identity.ClassCode:X2}:{device.Identity.Subclass:X2}",
                        "RiskEngine",
                        device.InstanceId));
                }
            }
            else if (device.Driver?.Signature?.Status == DriverSignatureStatus.Unsigned)
            {
                findings.Add(Create(
                    "DRIVER_UNSIGNED",
                    FindingSeverity.Low,
                    FindingConfidence.Medium,
                    "Driver unsigned",
                    device.Driver.Signature.AnalysisSummary,
                    device.Driver.ImagePath ?? device.Driver.InfPath ?? device.InstanceId,
                    "DriverSignatureAnalyzer",
                    device.InstanceId));
            }
            else if (device.Driver?.Signature?.Status is DriverSignatureStatus.Untrusted or DriverSignatureStatus.Expired)
            {
                findings.Add(Create(
                    "DRIVER_SIGNATURE_TRUST_ISSUE",
                    FindingSeverity.Low,
                    FindingConfidence.Medium,
                    "Driver signature trust issue",
                    device.Driver.Signature.AnalysisSummary,
                    $"{device.Driver.Signature.Status}: {device.Driver.Signature.SignerSubject ?? "unknown signer"}",
                    "DriverSignatureAnalyzer",
                    device.InstanceId));
            }
        }

        AssessDuplicatePciIdentities(devices, findings);
    }

    private static void AssessDuplicatePciIdentities(IReadOnlyList<PciDevice> devices, List<Finding> findings)
    {
        var groups = devices
            .Where(d => d.Kind != DeviceKind.VirtualOrSoftware)
            .GroupBy(d => IdentityKey(d.Identity))
            .Where(g => g.Count() >= 2);

        foreach (var group in groups)
        {
            var sample = group.First();
            findings.Add(Create(
                DmaMasqueradeFindingCodes.DuplicatePciIdentity,
                FindingSeverity.Medium,
                FindingConfidence.Medium,
                "Duplicate PCI identity on this machine",
                "Two or more physical PCI devices share the same vendor/device/subsystem identity. Custom DMA firmware guides warn against cloning an in-machine donor; duplicates can also be legitimate multi-function or multi-slot hardware. Review evidence only.",
                $"{FormatPciId(sample.Identity)}; count={group.Count()}; instances={string.Join(", ", group.Select(d => d.InstanceId))}",
                "RiskEngine",
                sample.InstanceId));
        }
    }

    private static void AssessUsb(IReadOnlyList<UsbDevice> devices, List<Finding> findings)
    {
        foreach (var device in devices)
        {
            if (device.Kind == DeviceKind.VirtualOrSoftware)
            {
                continue;
            }

            if (device.Resolved?.VendorName is null || device.Resolved.ProductName is null)
            {
                findings.Add(Create(
                    "UNKNOWN_USB_DEVICE",
                    FindingSeverity.Low,
                    FindingConfidence.Medium,
                    "Unknown USB device",
                    "The USB identity was not found in the local usb.ids reference database. Unknown does not prove malicious hardware.",
                    FormatUsbId(device.Identity),
                    "LocalUsbIdsProvider",
                    device.InstanceId));
            }

            if (string.IsNullOrWhiteSpace(device.Service) &&
                string.IsNullOrWhiteSpace(device.Driver?.Service) &&
                string.IsNullOrWhiteSpace(device.Driver?.DriverName))
            {
                findings.Add(Create(
                    "USB_DRIVER_MISSING",
                    FindingSeverity.Low,
                    FindingConfidence.Low,
                    "USB driver metadata missing",
                    "IronTrace could not locate driver metadata for this USB device. Informational / low confidence only.",
                    device.InstanceId,
                    "UsbInventory",
                    device.InstanceId));
            }
        }
    }

    private static void AssessVulnerableDrivers(ScanSession session, List<Finding> findings)
    {
        foreach (var match in session.VulnerableDriverMatches)
        {
            var isHash = string.Equals(match.MatchKind, "sha256", StringComparison.OrdinalIgnoreCase);
            findings.Add(Create(
                "VULNERABLE_DRIVER_MATCH",
                FindingSeverity.Medium,
                isHash ? FindingConfidence.High : FindingConfidence.Medium,
                "Known-vulnerable driver match",
                "A driver matched the local LOLDrivers snapshot. This is BYOVD risk evidence for administrator review — not proof of cheating.",
                match.Evidence ?? $"{match.DriverFileName}; {match.LolDriversId}",
                "LolDriversMatch",
                match.RelatedPath));

            var hvci = session.PlatformSecurity?.MemoryIntegrity.State;
            if (hvci is SecurityFeatureState.Disabled or SecurityFeatureState.Unknown or SecurityFeatureState.Unsupported
                or null)
            {
                findings.Add(Create(
                    "VULNERABLE_DRIVER_BLOCKLIST_GAP",
                    FindingSeverity.Low,
                    FindingConfidence.Low,
                    "Vulnerable driver with weak HVCI posture",
                    "A LOLDrivers match was observed while Memory Integrity (HVCI) is not clearly enabled. Suggests a possible blocklist/posture gap — review only.",
                    $"HVCI={hvci?.ToString() ?? "null"}; driver={match.DriverFileName}",
                    "LolDriversMatch",
                    match.RelatedPath));
            }
        }
    }

    private static void AssessCodeIntegrity(ScanSession session, List<Finding> findings)
    {
        var ci = session.CodeIntegrity;
        if (ci is null || !ci.Accessible)
        {
            return;
        }

        var unsigned = ci.Events.Where(e => e.EventId is 3004 or 3033).Take(5).ToList();
        foreach (var evt in unsigned)
        {
            findings.Add(Create(
                "CI_UNSIGNED_OR_INVALID_IMAGE",
                FindingSeverity.Low,
                FindingConfidence.Medium,
                "Code Integrity unsigned/invalid image event",
                "Code Integrity Operational log recorded an unsigned or integrity-failed image. Evidence for review; paths are truncated.",
                $"Event {evt.EventId}; {evt.FilePathTruncated ?? evt.StatusMessage ?? "no path"}",
                "CodeIntegrityLog",
                evt.FilePathTruncated));
        }

        var wdac = ci.Events.Where(e => e.EventId is 3076 or 3077).Take(5).ToList();
        foreach (var evt in wdac)
        {
            findings.Add(Create(
                "CI_WDAC_AUDIT_OR_BLOCK",
                FindingSeverity.Low,
                FindingConfidence.Medium,
                "Code Integrity App Control audit/block event",
                "Code Integrity logged an App Control audit (3076) or enforce (3077) event. Useful posture evidence; not an automatic cheat verdict.",
                $"Event {evt.EventId}; {evt.FilePathTruncated ?? evt.StatusMessage ?? "no path"}",
                "CodeIntegrityLog",
                evt.FilePathTruncated));
        }
    }

    private static void AssessIdentity(ScanSession session, List<Finding> findings)
    {
        var report = session.IdentityConsistency;
        if (report is null)
        {
            return;
        }

        foreach (var check in report.Checks.Where(c => c.IsAnomaly))
        {
            findings.Add(Create(
                "IDENTITY_PLACEHOLDER_OR_INCONSISTENT",
                FindingSeverity.Information,
                check.Confidence,
                check.Title,
                check.Explanation,
                check.Evidence,
                "IdentityConsistency"));
        }
    }

    private static void AssessKernelEvidence(ScanSession session, List<Finding> findings)
    {
        var kernel = session.KernelEvidence;
        if (kernel is null || kernel.Availability == KernelDriverAvailability.Unavailable)
        {
            findings.Add(Create(
                "KERNEL_EVIDENCE_UNAVAILABLE",
                FindingSeverity.Information,
                FindingConfidence.Low,
                "Kernel PCI evidence unavailable",
                "IronTrace.Driver was not available. User-mode inventory remains the baseline; absence of kernel evidence is not suspicious.",
                kernel?.Detail ?? "KernelEvidence null or unavailable",
                "KernelEvidence"));
            return;
        }

        if (kernel.Availability == KernelDriverAvailability.Unsupported)
        {
            findings.Add(Create(
                "KERNEL_DRIVER_PROTOCOL_UNSUPPORTED",
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "Kernel driver protocol unsupported",
                "IronTrace.Driver is present but the protocol version is incompatible. Update the driver or client.",
                kernel.Detail ?? "Unsupported protocol",
                "KernelEvidence"));
            return;
        }

        if (kernel.Availability == KernelDriverAvailability.Partial)
        {
            findings.Add(Create(
                "KERNEL_EVIDENCE_PARTIAL",
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "Kernel PCI evidence partial",
                "IronTrace.Driver opened but some PCI evidence operations were incomplete. Treat collected fields as best-effort evidence.",
                kernel.Detail ?? "Partial",
                "KernelEvidence"));
        }

        foreach (var device in kernel.Devices)
        {
            if (MatchesStockPcileechCapabilityLayout(device.Capabilities))
            {
                findings.Add(Create(
                    DmaMasqueradeFindingCodes.PcileechDefaultCapLayout,
                    FindingSeverity.Medium,
                    FindingConfidence.Medium,
                    "Stock PCILeech-like capability offsets",
                    "Kernel capability walk shows the publicly documented default pcileech-fpga standard chain (PM @ 0x40, MSI @ 0x50, PCIe @ 0x60). Custom firmware often relocates these; legitimate devices can still match. Review evidence only.",
                    $"BDF {device.Bus:X2}:{device.Device:X2}.{device.Function}; PM@0x{StockCapOffsetPm:X2} MSI@0x{StockCapOffsetMsi:X2} PCIe@0x{StockCapOffsetPcie:X2}",
                    "KernelEvidence",
                    device.InstanceId));
            }

            AssessBarShape(device, session, findings);
            AssessDsnWeakSignal(device, findings);

            if (device.ConfigVendorId is null || device.ConfigDeviceId is null)
                continue;

            var um = session.PciDevices.FirstOrDefault(p =>
                p.Bus == device.Bus &&
                p.DeviceNumber == device.Device &&
                p.Function == device.Function);

            if (um is null)
                continue;

            if (um.Identity.VendorId != device.ConfigVendorId ||
                um.Identity.DeviceId != device.ConfigDeviceId)
            {
                findings.Add(Create(
                    DmaMasqueradeFindingCodes.KernelPciIdentityMismatch,
                    FindingSeverity.Medium,
                    FindingConfidence.Medium,
                    "PCI identity mismatch (user-mode vs config space)",
                    "User-mode PnP identity does not match a bounded kernel config-space read for the same BDF. Evidence for review; not an automatic cheat verdict.",
                    $"BDF {device.Bus:X2}:{device.Device:X2}.{device.Function} UM=VEN_{um.Identity.VendorId:X4}&DEV_{um.Identity.DeviceId:X4} CFG=VEN_{device.ConfigVendorId:X4}&DEV_{device.ConfigDeviceId:X4}",
                    "KernelEvidence",
                    device.InstanceId));
            }
            else if (ClassesDisagree(um.Identity, device))
            {
                findings.Add(Create(
                    DmaMasqueradeFindingCodes.KernelPciClassMismatch,
                    FindingSeverity.Medium,
                    FindingConfidence.Medium,
                    "PCI class mismatch (user-mode vs config space)",
                    "Vendor/device IDs match for this BDF, but class or subclass differs between PnP and kernel config space. Possible shadow/spoof inconsistency; also possible race or filter driver. Review evidence only — not an automatic cheat verdict.",
                    $"BDF {device.Bus:X2}:{device.Device:X2}.{device.Function} UM={um.Identity.ClassCode:X2}.{um.Identity.Subclass:X2} CFG={device.ConfigClassCode:X2}.{device.ConfigSubclass:X2}",
                    "KernelEvidence",
                    device.InstanceId));
            }
        }

        AssessDuplicateDsn(kernel, findings);
    }

    private static bool ClassesDisagree(PciDeviceIdentity um, KernelPciDeviceEvidence cfg)
    {
        if (um.ClassCode is not byte umClass || cfg.ConfigClassCode is not byte cfgClass)
            return false;

        if (umClass != cfgClass)
            return true;

        if (um.Subclass is byte umSub && cfg.ConfigSubclass is byte cfgSub)
            return umSub != cfgSub;

        return false;
    }

    private static void AssessBarShape(
        KernelPciDeviceEvidence device,
        ScanSession session,
        List<Finding> findings)
    {
        var claimedClass = device.ConfigClassCode
            ?? session.PciDevices.FirstOrDefault(p =>
                p.Bus == device.Bus &&
                p.DeviceNumber == device.Device &&
                p.Function == device.Function)?.Identity.ClassCode;

        var populatedBars = device.Bars.Where(b =>
            !string.Equals(b.BarType, "Unknown", StringComparison.OrdinalIgnoreCase)).ToList();

        if (claimedClass == ClassNetwork && populatedBars.Count == 0 && device.Bars.Count == 0)
        {
            // Only when BAR query returned an empty list (not "unavailable" with notes only).
            // If bars collection is empty because query failed, Notes usually say so — skip.
            if (device.Notes.Any(n => n.Contains("BAR layout", StringComparison.OrdinalIgnoreCase)))
                return;

            findings.Add(Create(
                DmaMasqueradeFindingCodes.PciBarShapeAnomaly,
                FindingSeverity.Low,
                FindingConfidence.Low,
                "Network-class device with no BARs",
                "Kernel BAR layout reports no BARs for a network-class device. Partial CFW dump-emu can look like this; query gaps and unusual hardware can too. Review evidence only.",
                $"BDF {device.Bus:X2}:{device.Device:X2}.{device.Function}; class={claimedClass:X2}; bars=0",
                "KernelEvidence",
                device.InstanceId));
            return;
        }

        var isStock = device.ConfigVendorId == StockPcileechVendorId &&
                      device.ConfigDeviceId == StockPcileechDeviceId;
        if (!isStock)
            return;

        var memoryBars = populatedBars
            .Where(b => b.BarType.StartsWith("Memory", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (memoryBars.Count != 1)
            return;

        var size = memoryBars[0].Size;
        if (size is null || size > TinyBarSizeThreshold)
            return;

        findings.Add(Create(
            DmaMasqueradeFindingCodes.PciBarShapeAnomaly,
            FindingSeverity.Medium,
            FindingConfidence.Medium,
            "Stock PCILeech-class ID with tiny single BAR",
            "Stock Xilinx PCILeech-class identity combined with a single small memory BAR (when size is known). Lab FPGA boards can match; treat as supporting review evidence, not an automatic cheat verdict.",
            $"BDF {device.Bus:X2}:{device.Device:X2}.{device.Function}; BAR0 type={memoryBars[0].BarType}; size=0x{size.Value:X}",
            "KernelEvidence",
            device.InstanceId));
    }

    private static void AssessDsnWeakSignal(KernelPciDeviceEvidence device, List<Finding> findings)
    {
        if (string.IsNullOrEmpty(device.DeviceSerialNumberHex))
            return;

        var hex = device.DeviceSerialNumberHex;
        var allZero = hex.All(c => c is '0');
        var isStock = device.ConfigVendorId == StockPcileechVendorId &&
                      device.ConfigDeviceId == StockPcileechDeviceId;

        if (!allZero && !isStock)
            return;

        var reason = allZero
            ? "PCIe Device Serial Number (DSN) is all zeros."
            : "DSN is present on a stock PCILeech-class identity.";

        findings.Add(Create(
            DmaMasqueradeFindingCodes.PciDsnWeakSignal,
            FindingSeverity.Information,
            FindingConfidence.Low,
            "Weak PCIe DSN signal",
            $"{reason} Weak alone; correlate with other DMA/CFW review signals. Not an automatic cheat verdict.",
            $"BDF {device.Bus:X2}:{device.Device:X2}.{device.Function}; DSN={hex}",
            "KernelEvidence",
            device.InstanceId));
    }

    private static void AssessDuplicateDsn(KernelEvidenceSnapshot kernel, List<Finding> findings)
    {
        var groups = kernel.Devices
            .Where(d => !string.IsNullOrEmpty(d.DeviceSerialNumberHex))
            .Where(d => !d.DeviceSerialNumberHex!.All(c => c is '0'))
            .GroupBy(d => d.DeviceSerialNumberHex!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(x => (x.Bus, x.Device, x.Function)).Distinct().Count() >= 2);

        foreach (var group in groups)
        {
            var sample = group.First();
            findings.Add(Create(
                DmaMasqueradeFindingCodes.PciDsnWeakSignal,
                FindingSeverity.Medium,
                FindingConfidence.Medium,
                "Duplicate PCIe DSN across devices",
                "Two or more PCI functions report the same non-zero Device Serial Number. Unusual and worth review; can also be multi-function silicon. Not an automatic cheat verdict.",
                $"DSN={group.Key}; BDFs={string.Join(", ", group.Select(d => $"{d.Bus:X2}:{d.Device:X2}.{d.Function}"))}",
                "KernelEvidence",
                sample.InstanceId));
        }
    }

    private static void AssessChallengeEvidence(ScanSession session, List<Finding> findings)
    {
        var challenge = session.ChallengeEvidence;
        if (challenge is null)
            return;

        var critical = challenge.Decisions.Count(d => d.Decision == ChallengePolicyDecision.DenyCritical);
        var eligible = challenge.Decisions.Count(d => d.Decision == ChallengePolicyDecision.AllowListedEligible);

        findings.Add(Create(
            "SAFE_CHALLENGE_POLICY_APPLIED",
            FindingSeverity.Information,
            FindingConfidence.Medium,
            "Safe challenge policy applied",
            "Device challenge policy evaluated with default deny. No reset/FLR was executed. Critical deny and allow-list eligibility are evidence only — not a cheat verdict.",
            $"decisions={challenge.Decisions.Count}; denyCritical={critical}; allowListedEligible={eligible}; execution=notEnabled",
            "ChallengeEvidence"));
    }

    private static void AssessSpdmEvidence(ScanSession session, List<Finding> findings)
    {
        var spdm = session.SpdmEvidence;
        if (spdm is null)
            return;

        // Unsupported / Unknown / Partial — never escalate to suspicious.
        if (spdm.Availability is CapabilityStatus.Unsupported or CapabilityStatus.Unknown)
        {
            // No finding: Unsupported ≠ suspicious. Detail remains in the report section.
            return;
        }

        if (spdm.Availability == CapabilityStatus.Partial &&
            spdm.Devices.Any(d => d.DoePresent))
        {
            findings.Add(Create(
                "SPDM_DOE_CAPABILITY_DETECTED",
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "PCIe DOE capability detected",
                "One or more devices expose PCIe Data Object Exchange (DOE). SPDM stack is not integrated; this is detection-only evidence, not attestation.",
                spdm.Detail ?? "DOE present",
                "SpdmEvidence"));
        }
    }

    private static void AssessMeasuredBootEvidence(ScanSession session, List<Finding> findings)
    {
        var mb = session.MeasuredBootEvidence;
        if (mb is null)
            return;

        if (mb.Availability is CapabilityStatus.Unsupported or CapabilityStatus.Unknown)
            return;

        if (mb.Pcrs.Count > 0)
        {
            findings.Add(Create(
                "MEASURED_BOOT_PCR_SNAPSHOT",
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "Measured Boot PCR snapshot collected",
                "Best-effort TPM PCR digests were collected. This does not mean the JSON report is cryptographically attested.",
                $"bank={mb.PcrBank}; pcrs={mb.Pcrs.Count}; availability={mb.Availability}",
                "MeasuredBootEvidence"));
        }
    }

    private static void AssessPnPHistory(ScanSession session, List<Finding> findings)
    {
        var hist = session.PnPHistory;
        if (hist is null || !hist.OptInEnabled)
            return;

        foreach (var hit in hist.WatchlistHitsNotOnBus)
        {
            findings.Add(Create(
                DmaMasqueradeFindingCodes.PnpHistoryWatchlistHit,
                FindingSeverity.Medium,
                FindingConfidence.Medium,
                "Historical PnP watchlist identity not on bus",
                "A privacy-opt-in PnP Enum scan found a watchlisted PCI identity in device history that is not present on the current bus. Can indicate past stock DMA hardware or leftover Enum entries; not proof of cheating.",
                $"VEN_{hit.VendorId:X4}&DEV_{hit.DeviceId:X4}; {hit.InstanceId}; {hit.FriendlyName ?? "no name"}",
                "PnPHistory",
                hit.InstanceId));
        }
    }

    private static void AssessDmaSignalClusters(List<Finding> findings)
    {
        var groups = findings
            .Where(f => f.RelatedInstanceId is not null &&
                        DmaMasqueradeFindingCodes.ClusterSources.Contains(f.Code))
            .GroupBy(f => f.RelatedInstanceId!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(x => x.Code).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2);

        foreach (var group in groups)
        {
            var codes = string.Join(", ", group.Select(f => f.Code).Distinct(StringComparer.OrdinalIgnoreCase));
            findings.Add(Create(
                DmaMasqueradeFindingCodes.DmaSignalCluster,
                FindingSeverity.Information,
                FindingConfidence.Medium,
                "Multiple DMA/CFW signals on one device",
                "Two or more independent DMA/CFW review signals share the same device. Prioritize human triage; still not an automatic cheat verdict or ban.",
                $"instance={group.Key}; codes={codes}",
                "RiskEngine",
                group.Key));
        }
    }

    private bool NeedsReview(PciDevice device)
    {
        if (_watchlist.TryMatch(device.Identity, out _))
            return true;

        if (device.Resolved?.VendorName is null || device.Resolved.DeviceName is null)
            return true;

        if (string.IsNullOrWhiteSpace(device.Driver?.Service) &&
            string.IsNullOrWhiteSpace(device.Driver?.DriverName))
            return true;

        if (device.Driver?.Signature?.Status is DriverSignatureStatus.Unsigned
            or DriverSignatureStatus.Untrusted
            or DriverSignatureStatus.Expired)
            return true;

        return false;
    }

    private bool IsDonorClassWithoutDriver(PciDevice device)
    {
        if (device.Resolved?.VendorName is null || device.Resolved.DeviceName is null)
            return false;

        if (_watchlist.TryMatch(device.Identity, out _))
            return false;

        return device.Identity.ClassCode is 0x01 or 0x02;
    }

    private static bool MatchesStockPcileechCapabilityLayout(IReadOnlyList<KernelPciCapability> capabilities)
    {
        if (capabilities.Count == 0)
            return false;

        static bool Has(IReadOnlyList<KernelPciCapability> caps, ushort id, ushort offset)
            => caps.Any(c => !c.IsExtended && c.CapabilityId == id && c.Offset == offset);

        return Has(capabilities, CapIdPowerManagement, StockCapOffsetPm)
               && Has(capabilities, CapIdMsi, StockCapOffsetMsi)
               && Has(capabilities, CapIdPciExpress, StockCapOffsetPcie);
    }

    private static string IdentityKey(PciDeviceIdentity id)
        => $"{id.VendorId:X4}:{id.DeviceId:X4}:{id.SubsystemVendorId?.ToString("X4") ?? "-"}:{id.SubsystemDeviceId?.ToString("X4") ?? "-"}";

    private static IntegrityVerdict MapVerdict(
        int critical, int high, int medium, int low, int reviewDevices, int errorCount)
    {
        if (critical > 0)
            return IntegrityVerdict.HighRisk;

        if (high > 0)
            return IntegrityVerdict.Suspicious;

        if (errorCount > 0 && reviewDevices == 0 && medium == 0 && low == 0)
            return IntegrityVerdict.Unverified;

        if (medium > 0 || reviewDevices > 0)
            return IntegrityVerdict.ReviewRecommended;

        if (low > 0)
            return IntegrityVerdict.LowRisk;

        return IntegrityVerdict.Normal;
    }

    private static Finding Create(
        string code,
        FindingSeverity severity,
        FindingConfidence confidence,
        string title,
        string explanation,
        string evidence,
        string source,
        string? related = null)
        => new(
            code,
            severity,
            confidence,
            title,
            explanation,
            evidence,
            source,
            related,
            DmaMasqueradeFindingCodes.TriageHintFor(code));

    private static string FormatPciId(PciDeviceIdentity id)
    {
        var s = $"VEN_{id.VendorId:X4}&DEV_{id.DeviceId:X4}";
        if (id.SubsystemVendorId is ushort sv && id.SubsystemDeviceId is ushort sd)
            s += $"&SUBSYS_{sd:X4}{sv:X4}";

        if (id.Revision is byte rev)
            s += $"&REV_{rev:X2}";

        return s;
    }

    private static string FormatUsbId(UsbDeviceIdentity id)
        => $"VID_{id.VendorId:X4}&PID_{id.ProductId:X4}";
}

/// <summary>Minimal in-memory watchlist for tests / RiskEngine fallback ctor.</summary>
file sealed class BuiltInDmaWatchlistProvider : IDmaWatchlistProvider
{
    private static readonly DmaWatchlistEntry Stock = new(
        0x10EE, 0x0666, null, null,
        "Stock PCILeech / Squirrel-class FPGA",
        "stock",
        null);

    public IReadOnlyList<DmaWatchlistEntry> Entries { get; } = [Stock];

    public bool TryMatch(PciDeviceIdentity identity, out DmaWatchlistEntry match)
    {
        if (DmaWatchlistMatching.Matches(Stock, identity.VendorId, identity.DeviceId,
                identity.SubsystemVendorId, identity.SubsystemDeviceId))
        {
            match = Stock;
            return true;
        }

        match = null!;
        return false;
    }
}

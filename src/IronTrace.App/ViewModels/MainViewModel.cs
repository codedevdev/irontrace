using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IronTrace.App.Services;
using IronTrace.Contracts;
using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Findings;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Reference;
using IronTrace.Contracts.Reporting;
using System.IO;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Scanning;
using IronTrace.Core.Scanning;
using IronTrace.Reporting;
using IronTrace.Forensics;
using Microsoft.Win32;

namespace IronTrace.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IScanOrchestrator _orchestrator;
    private readonly IScanReportExporter _exporter;
    private readonly ISelfAuditHtmlExporter _htmlExporter;
    private readonly IReferenceUpdateService _referenceUpdates;
    private readonly IScanUploadService _uploadService;
    private readonly PrivacyScanOptions _privacy;
    private CancellationTokenSource? _cts;
    private readonly List<DeviceListItem> _allDevices = [];
    private readonly List<FindingListItem> _allFindings = [];

    public MainViewModel(
        IScanOrchestrator orchestrator,
        IScanReportExporter exporter,
        ISelfAuditHtmlExporter htmlExporter,
        IReferenceUpdateService referenceUpdates,
        IScanUploadService uploadService,
        PrivacyScanOptions privacy)
    {
        _orchestrator = orchestrator;
        _exporter = exporter;
        _htmlExporter = htmlExporter;
        _referenceUpdates = referenceUpdates;
        _uploadService = uploadService;
        _privacy = privacy;
        IncludePnpDeviceHistory = privacy.IncludePnpDeviceHistory;
        DevicesView = CollectionViewSource.GetDefaultView(Devices);
        DevicesView.Filter = FilterDevice;
        FindingsView = CollectionViewSource.GetDefaultView(Findings);
        FindingsView.Filter = FilterFinding;
        PlatformFeatures = new ObservableCollection<PlatformFeatureRow>();
        PreviewDevices = new ObservableCollection<DeviceListItem>();
        UsbDevices = new ObservableCollection<UsbListItem>();
        VulnerableMatches = new ObservableCollection<VulnerableMatchItem>();
        CodeIntegrityEvents = new ObservableCollection<CiEventItem>();
        KernelDevices = new ObservableCollection<KernelDeviceItem>();

        MemoryScanToolAvailable = MemoryScanToolLocator.IsAvailable;
        MemoryScanAvailabilityLine = MemoryScanToolAvailable
            ? ""
            : "Memory scan optional — hollows_hunter not installed. Hardware + forensic scans work without it.";
        if (!MemoryScanToolAvailable)
            IncludeMemoryScan = false;
    }

    public bool MemoryScanToolAvailable { get; }

    public ObservableCollection<DeviceListItem> Devices { get; } = [];
    public ObservableCollection<FindingListItem> Findings { get; } = [];
    public ObservableCollection<PlatformFeatureRow> PlatformFeatures { get; }
    public ObservableCollection<DeviceListItem> PreviewDevices { get; }
    public ObservableCollection<UsbListItem> UsbDevices { get; }
    public ObservableCollection<VulnerableMatchItem> VulnerableMatches { get; }
    public ObservableCollection<CiEventItem> CodeIntegrityEvents { get; }
    public ObservableCollection<KernelDeviceItem> KernelDevices { get; }
    public ICollectionView DevicesView { get; }
    public ICollectionView FindingsView { get; }

    [ObservableProperty] private string _viewState = "Home"; // Home | Scanning | Result | Advanced | Device
    [ObservableProperty] private string _advancedTab = "Devices"; // Devices | Usb | Drivers | Kernel | Ci | Findings
    [ObservableProperty] private string _progressMessage = "";
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _progressStage = "";
    [ObservableProperty] private string _verdictText = "";
    [ObservableProperty] private string _summaryText = "";
    [ObservableProperty] private string _dmaProtectionLine = "";
    [ObservableProperty] private string _deviceSummaryLine = "";
    [ObservableProperty] private string _ciSummaryLine = "";
    [ObservableProperty] private string _driverTrustLine = "";
    [ObservableProperty] private string _kernelSummaryLine = "";
    [ObservableProperty] private string _verificationSummaryLine = "";
    [ObservableProperty] private string _measuredBootSummaryLine = "";
    [ObservableProperty] private string _dmaReviewSummaryLine = "";
    [ObservableProperty] private string _elevationLine = "";
    [ObservableProperty] private string _referenceDbLine = "";
    [ObservableProperty] private string _motherboardSerialLine = "";
    [ObservableProperty] private bool _showRawSerialLocal;
    [ObservableProperty] private bool _exportIncludeSerialHash = true;
    [ObservableProperty] private bool _exportIncludeDriverPaths = true;
    [ObservableProperty] private bool _exportIncludeCiEvents = true;
    [ObservableProperty] private bool _exportIncludeInstanceIds = true;
    [ObservableProperty] private bool _exportIncludeRawSerial;
    [ObservableProperty] private bool _exportIncludePcrDigests = true;
    [ObservableProperty] private bool _includePnpDeviceHistory;
    [ObservableProperty] private bool _findingsDmaFilter;
    [ObservableProperty] private bool _includeProcessInventory;
    [ObservableProperty] private bool _includeMemoryScan;
    [ObservableProperty] private string _scanMode = "Admin"; // Admin | SelfAudit
    [ObservableProperty] private string _forensicBannerLine = "";
    [ObservableProperty] private string _memoryScanAvailabilityLine = "";
    [ObservableProperty] private string _memoryScanResultLine = "";
    [ObservableProperty] private ScanSession? _session;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _deviceSearch = "";
    [ObservableProperty] private string _findingSearch = "";
    [ObservableProperty] private string _deviceKindFilter = "All"; // All | Physical | Virtual | Review
    [ObservableProperty] private DeviceListItem? _selectedDevice;
    [ObservableProperty] private DeviceDetailModel? _deviceDetail;

    partial void OnDeviceSearchChanged(string value) => DevicesView.Refresh();
    partial void OnDeviceKindFilterChanged(string value) => DevicesView.Refresh();
    partial void OnIncludePnpDeviceHistoryChanged(bool value) => _privacy.IncludePnpDeviceHistory = value;
    partial void OnIncludeMemoryScanChanged(bool value)
    {
        if (value && !MemoryScanToolAvailable)
            IncludeMemoryScan = false;
    }
    partial void OnFindingSearchChanged(string value) => FindingsView.Refresh();
    partial void OnFindingsDmaFilterChanged(bool value) => FindingsView.Refresh();

    [RelayCommand]
    private Task StartAdminScanAsync()
    {
        ScanMode = "Admin";
        return StartScanAsync();
    }

    [RelayCommand]
    private Task StartSelfAuditScanAsync()
    {
        ScanMode = "SelfAudit";
        IncludeProcessInventory = true;
        return StartScanAsync();
    }

    [RelayCommand]
    private async Task StartScanAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        ViewState = "Scanning";
        ProgressMessage = "Starting...";
        ProgressStage = "os";
        ProgressPercent = 0;
        Findings.Clear();
        Devices.Clear();
        PreviewDevices.Clear();
        PlatformFeatures.Clear();
        UsbDevices.Clear();
        VulnerableMatches.Clear();
        CodeIntegrityEvents.Clear();
        KernelDevices.Clear();
        KernelSummaryLine = "";
        VerificationSummaryLine = "";
        MeasuredBootSummaryLine = "";
        DmaReviewSummaryLine = "";
        FindingsDmaFilter = false;
        SelectedDevice = null;
        DeviceDetail = null;
        _allDevices.Clear();
        _allFindings.Clear();
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                ProgressMessage = p.Message;
                ProgressStage = p.Stage;
                if (p.Percent is double pct)
                {
                    ProgressPercent = pct;
                }
            });

            var profile = ScanMode switch
            {
                "SelfAudit" => ScanProfile.SelfAudit,
                _ => IncludeProcessInventory || IncludeMemoryScan ? ScanProfile.FullForensic : ScanProfile.HardwareOnly
            };

            var consent = ScanConsentFlags.ForProfile(profile) with
            {
                IncludeProcessInventory = IncludeProcessInventory || profile != ScanProfile.HardwareOnly,
                IncludePersistence = IncludeProcessInventory || profile != ScanProfile.HardwareOnly,
                IncludeMemoryScan = IncludeMemoryScan
            };

            var options = new ScanOptions(profile, consent);
            Session = await _orchestrator.RunAsync(progress, _cts.Token, options);
            ApplyResult(Session);
            if (ScanMode == "SelfAudit" && Session is not null)
            {
                var htmlPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    $"IronTrace-SelfAudit-{DateTime.UtcNow:yyyyMMdd-HHmmss}.html");
                await _htmlExporter.ExportHtmlAsync(Session, htmlPath, CancellationToken.None);
                ProgressMessage = $"Self-audit HTML saved to Desktop.";
            }
            ViewState = "Result";
        }
        catch (OperationCanceledException)
        {
            ProgressMessage = "Scan cancelled.";
            ViewState = "Home";
        }
        catch (Exception)
        {
            MessageBox.Show(
                "IronTrace could not complete the hardware check.\n\nTechnical details are written to the local log.",
                "IronTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            ViewState = "Home";
        }
        finally
        {
            IsBusy = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    [RelayCommand]
    private void ShowAdvanced()
    {
        if (Session is null)
        {
            return;
        }

        AdvancedTab = "Devices";
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void ShowFindings()
    {
        if (Session is null)
        {
            return;
        }

        AdvancedTab = "Findings";
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void ShowUsb()
    {
        if (Session is null) return;
        AdvancedTab = "Usb";
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void ShowDrivers()
    {
        if (Session is null) return;
        AdvancedTab = "Drivers";
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void ShowKernel()
    {
        if (Session is null) return;
        AdvancedTab = "Kernel";
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void ShowCodeIntegrity()
    {
        if (Session is null) return;
        AdvancedTab = "Ci";
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void BackToResult()
    {
        SelectedDevice = null;
        DeviceDetail = null;
        ViewState = Session is null ? "Home" : "Result";
    }

    [RelayCommand]
    private void BackToAdvanced()
    {
        DeviceDetail = null;
        ViewState = "Advanced";
    }

    [RelayCommand]
    private void BackHome()
    {
        ViewState = "Home";
        SelectedDevice = null;
        DeviceDetail = null;
    }

    [RelayCommand]
    private void SelectDevice(DeviceListItem? item)
    {
        if (item is null)
        {
            return;
        }

        SelectedDevice = item;
        DeviceDetail = BuildDetail(item);
        ViewState = "Device";
    }

    [RelayCommand]
    private void OpenFindingDevice(FindingListItem? item)
    {
        if (item?.RelatedInstanceId is null)
        {
            return;
        }

        var device = _allDevices.FirstOrDefault(d =>
            string.Equals(d.InstanceId, item.RelatedInstanceId, StringComparison.OrdinalIgnoreCase));
        if (device is not null)
        {
            SelectDevice(device);
        }
    }

    [RelayCommand]
    private void SetDeviceFilter(string filter)
    {
        DeviceKindFilter = filter;
    }

    [RelayCommand]
    private async Task UploadToServerAsync()
    {
        if (Session is null || IsBusy)
        {
            return;
        }

        if (!_uploadService.IsConfigured)
        {
            MessageBox.Show(
                "Server upload is not configured.\n\nSet IronTrace:Server:BaseUrl in appsettings.json and provide an Upload API key (appsettings UploadApiKey or DPAPI store under %LocalAppData%\\IronTrace\\keys\\).",
                "IronTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var consent = MessageBox.Show(
            "Upload this scan to the configured IronTrace server for administrator review?\n\n" +
            "The report will include:\n" +
            "• Platform security posture and DMA-related signals\n" +
            "• PCI/USB inventory (no raw motherboard serial)\n" +
            "• Findings summary and risk verdict\n" +
            "• Driver / Code Integrity excerpts per export defaults\n\n" +
            "Raw serial numbers are never uploaded. Review does not auto-ban anyone.",
            "Consent to upload",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);

        if (consent != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var result = await _uploadService.UploadAsync(Session, CancellationToken.None);
            MessageBox.Show(
                result.Success
                    ? $"{result.Message}\nScan id: {result.ScanId}"
                    : result.Message,
                "IronTrace upload",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Upload failed: {ex.Message}",
                "IronTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ExportReportAsync()
    {
        if (Session is null)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "JSON report (*.json)|*.json",
            FileName = $"irontrace-scan-{Session.SessionId:N}.json"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var privacy = new ExportPrivacyOptions(
                ExportIncludeSerialHash,
                ExportIncludeDriverPaths,
                ExportIncludeCiEvents,
                ExportIncludeInstanceIds,
                ExportIncludeRawSerial,
                ExportIncludePcrDigests);
            await _exporter.ExportJsonAsync(Session, dialog.FileName, CancellationToken.None, privacy);
            MessageBox.Show("Report exported.", "IronTrace", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception)
        {
            MessageBox.Show(
                "IronTrace could not write the report file.",
                "IronTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    [RelayCommand]
    private async Task CheckReferenceUpdatesAsync()
    {
        try
        {
            IsBusy = true;
            var result = await _referenceUpdates.CheckAndApplyAsync(CancellationToken.None);
            MessageBox.Show(
                result.Message,
                "IronTrace reference updates",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Reference update failed: {ex.Message}",
                "IronTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ToggleShowRawSerial()
    {
        ShowRawSerialLocal = !ShowRawSerialLocal;
        UpdateMotherboardSerialLine();
    }

    private void UpdateMotherboardSerialLine()
    {
        var board = Session?.Motherboard;
        if (board is null)
        {
            MotherboardSerialLine = "Motherboard serial — unavailable";
            return;
        }

        if (ShowRawSerialLocal && !string.IsNullOrWhiteSpace(board.SerialRaw))
        {
            MotherboardSerialLine = $"Board serial (local only): {board.SerialRaw}";
        }
        else if (!string.IsNullOrWhiteSpace(board.SerialHash))
        {
            MotherboardSerialLine = $"Board serial hash: {board.SerialHash[..Math.Min(16, board.SerialHash.Length)]}… ({board.SerialHandling})";
        }
        else
        {
            MotherboardSerialLine = $"Board serial: {board.SerialHandling}";
        }
    }

    private bool FilterDevice(object obj)
    {
        if (obj is not DeviceListItem d)
        {
            return false;
        }

        if (DeviceKindFilter == "Physical" && d.Kind != DeviceKind.Physical)
        {
            return false;
        }

        if (DeviceKindFilter == "Virtual" && d.Kind != DeviceKind.VirtualOrSoftware)
        {
            return false;
        }

        if (DeviceKindFilter == "Review" && !d.NeedsReview)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(DeviceSearch))
        {
            return true;
        }

        var q = DeviceSearch.Trim();
        return Contains(d.Title, q) ||
               Contains(d.Ids, q) ||
               Contains(d.VendorName, q) ||
               Contains(d.DeviceName, q) ||
               Contains(d.DriverProvider, q) ||
               Contains(d.SignatureStatus, q) ||
               Contains(d.InstanceId, q);
    }

    private bool FilterFinding(object obj)
    {
        if (obj is not FindingListItem f)
        {
            return false;
        }

        if (FindingsDmaFilter && !DmaMasqueradeFindingCodes.IsDmaRelated(f.Code))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(FindingSearch))
        {
            return true;
        }

        var q = FindingSearch.Trim();
        return Contains(f.Code, q) || Contains(f.Title, q) || Contains(f.Explanation, q) ||
               Contains(f.Severity, q) || Contains(f.TriageHint, q);
    }

    private static bool Contains(string? hay, string needle) =>
        !string.IsNullOrEmpty(hay) && hay.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private void ApplyResult(ScanSession session)
    {
        var assessment = session.RiskAssessment;
        VerdictText = (assessment?.Verdict ?? IntegrityVerdict.Unverified) switch
        {
            IntegrityVerdict.Normal => "NORMAL",
            IntegrityVerdict.LowRisk => "LOW RISK",
            IntegrityVerdict.ReviewRecommended => "REVIEW RECOMMENDED",
            IntegrityVerdict.Suspicious => "SUSPICIOUS",
            IntegrityVerdict.HighRisk => "HIGH RISK",
            IntegrityVerdict.Verified => "VERIFIED",
            _ => "UNVERIFIED"
        };

        SummaryText = assessment?.Summary ?? "Assessment unavailable.";
        ForensicBannerLine = session.ForensicEvidence?.VerdictBanner switch
        {
            ForensicVerdictBanner.CheatsDetected => "Forensic banner: Cheats Detected",
            ForensicVerdictBanner.InputDevicesDetected => "Forensic banner: Input Devices Detected",
            ForensicVerdictBanner.ReviewRecommended => "Forensic banner: Review Recommended",
            ForensicVerdictBanner.Clean => "Forensic banner: Clean",
            _ => session.ScanProfile != ScanProfile.HardwareOnly ? "Forensic banner: —" : ""
        };
        DmaProtectionLine = FormatDma(session);
        DeviceSummaryLine = assessment is null
            ? $"{session.PciDevices.Count} PCI · {session.UsbDevices.Count} USB"
            : $"{assessment.ConsistentDeviceCount} consistent · {assessment.ReviewDeviceCount} review · {session.PciDevices.Count} PCI · {session.UsbDevices.Count} USB";
        CiSummaryLine = session.CodeIntegrity is null
            ? "Code Integrity log — not collected"
            : session.CodeIntegrity.Accessible
                ? $"Code Integrity — {session.CodeIntegrity.EventCount} events (last {session.CodeIntegrity.LookbackDays}d)"
                : $"Code Integrity — unavailable ({session.CodeIntegrity.AccessDetail})";
        DriverTrustLine = session.VulnerableDriverMatches.Count == 0
            ? $"Drivers inventoried: {session.Drivers.Count} · no LOLDrivers matches"
            : $"Drivers inventoried: {session.Drivers.Count} · {session.VulnerableDriverMatches.Count} LOLDrivers match(es)";

        KernelSummaryLine = FormatKernelSummary(session.KernelEvidence);
        VerificationSummaryLine = FormatVerificationSummary(session);
        MeasuredBootSummaryLine = FormatMeasuredBootSummary(session.MeasuredBootEvidence);
        DmaReviewSummaryLine = FormatDmaReviewSummary(assessment?.Findings);
        MemoryScanResultLine = FormatMemoryScanSummary(session);

        ElevationLine = session.PlatformSecurity?.RanElevated == true
            ? "✓ Running elevated — deeper security detail enabled when configured"
            : "○ Not elevated — restart as Administrator for deeper CI / DeviceGuard detail";

        var pciHash = session.Metadata.TryGetValue("referenceDbHash", out var h) ? h : "";
        ReferenceDbLine = string.IsNullOrWhiteSpace(pciHash)
            ? "Reference DB hash — unavailable"
            : $"pci.ids DB hash: {pciHash[..Math.Min(12, pciHash.Length)]}…";

        ShowRawSerialLocal = false;
        UpdateMotherboardSerialLine();

        PlatformFeatures.Clear();
        if (session.PlatformSecurity is { } s)
        {
            PlatformFeatures.Add(ToRow(s.SecureBoot));
            PlatformFeatures.Add(ToRow(s.Tpm));
            PlatformFeatures.Add(ToRow(s.VirtualizationBasedSecurity));
            PlatformFeatures.Add(ToRow(s.MemoryIntegrity));
            PlatformFeatures.Add(ToRow(s.Virtualization));
            PlatformFeatures.Add(ToRow(s.KernelDmaProtection));
            if (session.MeasuredBootEvidence is { } mb)
            {
                PlatformFeatures.Add(new PlatformFeatureRow(
                    "Measured Boot / PCR",
                    mb.Availability.ToString(),
                    mb.Availability is CapabilityStatus.Supported or CapabilityStatus.Partial ? "✓" : "○",
                    mb.Detail));
            }
        }

        var findingsByDevice = (assessment?.Findings ?? Array.Empty<Finding>())
            .Where(f => f.RelatedInstanceId is not null)
            .GroupBy(f => f.RelatedInstanceId!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        _allFindings.Clear();
        Findings.Clear();
        if (assessment is not null)
        {
            foreach (var f in assessment.Findings)
            {
                var item = new FindingListItem(
                    f.Code,
                    f.Severity.ToString(),
                    f.Severity,
                    f.Title,
                    f.Explanation,
                    f.Evidence,
                    f.Source,
                    f.RelatedInstanceId,
                    f.Confidence.ToString(),
                    f.TriageHint);
                _allFindings.Add(item);
                Findings.Add(item);
            }
        }

        _allDevices.Clear();
        Devices.Clear();
        foreach (var d in session.PciDevices.OrderBy(x => x.Identity.VendorId).ThenBy(x => x.Identity.DeviceId))
        {
            findingsByDevice.TryGetValue(d.InstanceId, out var linked);
            linked ??= [];
            var needsReview = linked.Any(f => f.Severity >= FindingSeverity.Low) ||
                              d.Resolved?.VendorName is null ||
                              d.Driver?.Signature?.Status is DriverSignatureStatus.Unsigned
                                  or DriverSignatureStatus.Untrusted
                                  or DriverSignatureStatus.Expired;

            var item = DeviceListItem.From(d, linked.Count, needsReview);
            _allDevices.Add(item);
            Devices.Add(item);
        }

        UsbDevices.Clear();
        foreach (var u in session.UsbDevices.OrderBy(x => x.Identity.VendorId).ThenBy(x => x.Identity.ProductId))
        {
            UsbDevices.Add(new UsbListItem(
                u.FriendlyName ?? u.Description ?? "USB Device",
                $"VID_{u.Identity.VendorId:X4} PID_{u.Identity.ProductId:X4}",
                u.Resolved?.VendorName,
                u.Resolved?.ProductName,
                u.InstanceId));
        }

        VulnerableMatches.Clear();
        foreach (var m in session.VulnerableDriverMatches)
        {
            VulnerableMatches.Add(new VulnerableMatchItem(
                m.DriverFileName ?? "(unknown)",
                m.MatchKind,
                m.Title ?? m.LolDriversId ?? "LOLDrivers",
                m.Evidence ?? "",
                m.RelatedPath));
        }

        CodeIntegrityEvents.Clear();
        if (session.CodeIntegrity?.Events is { } events)
        {
            foreach (var e in events.Take(50))
            {
                CodeIntegrityEvents.Add(new CiEventItem(
                    e.EventId.ToString(),
                    e.TimeCreated?.ToString("u") ?? "—",
                    e.FilePathTruncated ?? "—",
                    e.StatusMessage ?? ""));
            }
        }

        KernelDevices.Clear();
        if (session.KernelEvidence?.Devices is { } kernelDevices)
        {
            foreach (var k in kernelDevices.OrderBy(x => x.Bus).ThenBy(x => x.Device).ThenBy(x => x.Function))
            {
                KernelDevices.Add(KernelDeviceItem.From(k));
            }
        }

        PreviewDevices.Clear();
        foreach (var d in _allDevices.Where(x => x.NeedsReview).Take(5))
        {
            PreviewDevices.Add(d);
        }

        if (PreviewDevices.Count == 0)
        {
            foreach (var d in _allDevices.Take(5))
            {
                PreviewDevices.Add(d);
            }
        }

        DevicesView.Refresh();
        FindingsView.Refresh();
    }

    private DeviceDetailModel BuildDetail(DeviceListItem item)
    {
        var device = Session?.PciDevices.FirstOrDefault(d =>
            string.Equals(d.InstanceId, item.InstanceId, StringComparison.OrdinalIgnoreCase));
        if (device is null)
        {
            return new DeviceDetailModel(item, null, Array.Empty<FindingListItem>());
        }

        var related = _allFindings
            .Where(f => string.Equals(f.RelatedInstanceId, device.InstanceId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return new DeviceDetailModel(item, device, related);
    }

    private static PlatformFeatureRow ToRow(SecurityFeatureStatus feature)
    {
        var mark = feature.State switch
        {
            SecurityFeatureState.Enabled => "✓",
            SecurityFeatureState.Unsupported => "○",
            SecurityFeatureState.Disabled => "○",
            SecurityFeatureState.SupportedButDisabled => "○",
            _ => "?"
        };
        return new PlatformFeatureRow(feature.Name, feature.State.ToString(), mark, feature.Detail);
    }

    private static string FormatDma(ScanSession session)
    {
        var dma = session.PlatformSecurity?.KernelDmaProtection;
        if (dma is null)
        {
            return "○ DMA Protection — unknown";
        }

        return dma.State switch
        {
            SecurityFeatureState.Enabled => "✓ Kernel DMA Protection enabled",
            SecurityFeatureState.Disabled => "○ Kernel DMA Protection disabled (informational)",
            SecurityFeatureState.SupportedButDisabled => "○ Kernel DMA Protection supported but disabled (informational)",
            SecurityFeatureState.Unsupported => "○ Kernel DMA Protection unsupported (compatibility — not suspicious)",
            _ => "○ Kernel DMA Protection unknown"
        };
    }

    private static string FormatKernelSummary(KernelEvidenceSnapshot? kernel)
    {
        if (kernel is null)
        {
            return "Kernel evidence — not collected (unknown, not suspicious)";
        }

        var proto = kernel.ProtocolVersion is uint v ? $" · protocol {v}" : "";
        var detail = string.IsNullOrWhiteSpace(kernel.Detail) ? "" : $" — {kernel.Detail}";
        return kernel.Availability switch
        {
            KernelDriverAvailability.Available =>
                $"Kernel evidence — available{proto} · {kernel.Devices.Count} device(s){detail}",
            KernelDriverAvailability.Partial =>
                $"Kernel evidence — partial{proto} · {kernel.Devices.Count} device(s){detail}",
            KernelDriverAvailability.Unsupported =>
                $"Kernel evidence — unsupported protocol{detail} (unknown, not suspicious)",
            _ =>
                $"Kernel evidence — unavailable{detail} (unknown, not suspicious)"
        };
    }

    private static string FormatVerificationSummary(ScanSession session)
    {
        var challenge = session.ChallengeEvidence;
        var spdm = session.SpdmEvidence;
        var challengePart = challenge is null
            ? "Challenge policy — not collected"
            : $"Challenge policy — {challenge.Decisions.Count} device(s); execution not enabled";
        var spdmPart = spdm is null
            ? "SPDM/DOE — not collected"
            : spdm.Availability switch
            {
                CapabilityStatus.Partial => "SPDM/DOE — DOE detected (stack not integrated)",
                CapabilityStatus.Unsupported => "SPDM/DOE — unsupported on observed devices (not suspicious)",
                CapabilityStatus.Unknown => "SPDM/DOE — unknown (not suspicious)",
                _ => $"SPDM/DOE — {spdm.Availability}"
            };
        return $"{challengePart} · {spdmPart}";
    }

    private static string FormatMeasuredBootSummary(MeasuredBootEvidenceSnapshot? evidence)
    {
        if (evidence is null)
            return "Measured Boot / PCR — not collected (unknown, not suspicious)";

        return evidence.Availability switch
        {
            CapabilityStatus.Supported =>
                $"Measured Boot / PCR — {evidence.Pcrs.Count} digests ({evidence.PcrBank}); evidence only, not attested",
            CapabilityStatus.Partial =>
                $"Measured Boot / PCR — partial ({evidence.Pcrs.Count} digests); evidence only, not attested",
            CapabilityStatus.Unsupported =>
                "Measured Boot / PCR — unsupported (not suspicious)",
            _ =>
                "Measured Boot / PCR — unknown (not suspicious)"
        };
    }

    private static string FormatDmaReviewSummary(IReadOnlyList<Finding>? findings)
    {
        if (findings is null || findings.Count == 0)
            return "DMA / CFW review — no DMA-related findings";

        var dma = findings.Where(f => DmaMasqueradeFindingCodes.IsDmaRelated(f.Code)).ToList();
        if (dma.Count == 0)
            return "DMA / CFW review — no DMA-related findings";

        var codes = string.Join(", ", dma.Select(f => f.Code).Distinct());
        return $"DMA / CFW review — {dma.Count} finding(s) for admin review ({codes}). Not an auto-ban.";
    }

    private static string FormatMemoryScanSummary(ScanSession session)
    {
        var mem = session.ForensicEvidence?.Memory;
        if (mem is null)
            return session.ScanProfile == ScanProfile.HardwareOnly ? "" : "Memory scan — not requested";

        return mem.Availability switch
        {
            ForensicAvailability.Unavailable or ForensicAvailability.Skipped =>
                $"Memory scan — skipped ({mem.Detail ?? "hollows_hunter not installed"})",
            ForensicAvailability.Partial =>
                $"Memory scan — partial ({mem.Detail})",
            ForensicAvailability.Available when mem.Hits.Count == 0 =>
                "Memory scan — no hollow/injected modules detected",
            ForensicAvailability.Available =>
                $"Memory scan — {mem.Hits.Count} suspicious module(s) reported",
            _ => string.IsNullOrWhiteSpace(mem.Detail) ? "" : $"Memory scan — {mem.Detail}"
        };
    }
}

public sealed record PlatformFeatureRow(string Name, string State, string Mark, string? Detail);

public sealed record UsbListItem(
    string Title,
    string Ids,
    string? VendorName,
    string? ProductName,
    string InstanceId);

public sealed record VulnerableMatchItem(
    string FileName,
    string MatchKind,
    string Title,
    string Evidence,
    string? Path);

public sealed record CiEventItem(
    string EventId,
    string Time,
    string Path,
    string Message);

public sealed record KernelDeviceItem(
    string Bdf,
    string ConfigIds,
    string ClassLine,
    string CapsBarsLine,
    string ExpressLine,
    string Notes)
{
    public static KernelDeviceItem From(KernelPciDeviceEvidence d)
    {
        var bdf = $"{d.Bus:D2}:{d.Device:D2}.{d.Function}";
        var ids = d.ConfigVendorId is ushort v && d.ConfigDeviceId is ushort dev
            ? $"VEN_{v:X4} DEV_{dev:X4}"
            : "config IDs — unavailable";
        var cls = d.ConfigClassCode is byte c
            ? $"Class {c:X2}.{d.ConfigSubclass:X2}.{d.ConfigProgIf:X2}" +
              (d.ConfigRevision is byte r ? $" · Rev {r:X2}" : "")
            : "Class — unavailable";
        var capsBars = $"{d.Capabilities.Count} cap(s) · {d.Bars.Count} BAR(s)";
        if (d.Bars.Count > 0)
        {
            var barBits = d.Bars.Select(b =>
            {
                var type = string.IsNullOrWhiteSpace(b.BarType) ? "?" : b.BarType;
                var bas = b.BaseAddress is ulong a ? $"0x{a:X}" : "base—";
                var size = b.Size is ulong s ? $" size 0x{s:X}" : "";
                return $"[{b.Index}:{type} {bas}{size}]";
            });
            capsBars += " · " + string.Join(" ", barBits);
        }
        var express = FormatExpress(d.Express);
        var notes = d.Notes.Count == 0 ? "" : string.Join("; ", d.Notes);
        return new KernelDeviceItem(bdf, ids, cls, capsBars, express, notes);
    }

    private static string FormatExpress(KernelPciExpressCaps? e)
    {
        if (e is null)
            return "Express — unavailable";
        if (!e.HasPcie)
            return "Express — no PCIe cap";

        var flags = new List<string> { "PCIe" };
        if (e.HasAer) flags.Add("AER");
        if (e.HasAcs) flags.Add("ACS");
        if (e.HasAts) flags.Add("ATS");
        if (e.HasSriov) flags.Add("SR-IOV");
        if (e.SupportsFlr) flags.Add("FLR");
        return string.Join(" · ", flags);
    }
}

public sealed class DeviceListItem
{
    public required string Title { get; init; }
    public required string Ids { get; init; }
    public string? VendorName { get; init; }
    public string? DeviceName { get; init; }
    public string? SubsystemName { get; init; }
    public string? ClassName { get; init; }
    public string? DriverProvider { get; init; }
    public string? DriverVersion { get; init; }
    public required DeviceKind Kind { get; init; }
    public required string KindLabel { get; init; }
    public required string Source { get; init; }
    public required string InstanceId { get; init; }
    public string? Bdf { get; init; }
    public string SignatureStatus { get; init; } = "Unknown";
    public DriverSignatureStatus SignatureStatusEnum { get; init; }
    public string? SignerShort { get; init; }
    public bool NeedsReview { get; init; }
    public int LinkedFindingCount { get; init; }

    public static DeviceListItem From(PciDevice d, int linkedFindings, bool needsReview)
    {
        var sig = d.Driver?.Signature;
        var bdf = d.Bus is int b && d.DeviceNumber is int dn
            ? $"{b:D2}:{dn:D2}.{d.Function ?? 0}"
            : null;

        return new DeviceListItem
        {
            Title = d.FriendlyName ?? d.Description ?? "PCI Device",
            Ids = $"VEN_{d.Identity.VendorId:X4} DEV_{d.Identity.DeviceId:X4}" +
                  (d.Identity.SubsystemVendorId is ushort sv && d.Identity.SubsystemDeviceId is ushort sd
                      ? $" SUB_{sd:X4}{sv:X4}"
                      : ""),
            VendorName = d.Resolved?.VendorName,
            DeviceName = d.Resolved?.DeviceName,
            SubsystemName = d.Resolved?.SubsystemName,
            ClassName = d.Resolved?.ClassName,
            DriverProvider = d.Driver?.Provider,
            DriverVersion = d.Driver?.Version,
            Kind = d.Kind,
            KindLabel = d.Kind == DeviceKind.VirtualOrSoftware ? "Virtual" : "Physical",
            Source = d.Resolved?.Source ?? "—",
            InstanceId = d.InstanceId,
            Bdf = bdf,
            SignatureStatus = sig?.Status.ToString() ?? d.Driver?.SigningState ?? "Unknown",
            SignatureStatusEnum = sig?.Status ?? DriverSignatureStatus.Unknown,
            SignerShort = IronTrace.Hardware.Signing.DriverSignatureMapper.ShortSubject(sig?.SignerSubject),
            NeedsReview = needsReview,
            LinkedFindingCount = linkedFindings
        };
    }
}

public sealed record FindingListItem(
    string Code,
    string Severity,
    FindingSeverity SeverityEnum,
    string Title,
    string Explanation,
    string Evidence,
    string Source,
    string? RelatedInstanceId,
    string Confidence,
    string? TriageHint = null);

public sealed class DeviceDetailModel
{
    public DeviceDetailModel(DeviceListItem listItem, PciDevice? device, IReadOnlyList<FindingListItem> relatedFindings)
    {
        ListItem = listItem;
        Device = device;
        RelatedFindings = relatedFindings;

        if (device is null)
        {
            return;
        }

        IdentityLines =
        [
            new("Vendor ID", $"0x{device.Identity.VendorId:X4}"),
            new("Device ID", $"0x{device.Identity.DeviceId:X4}"),
            new("Subsystem", device.Identity.SubsystemVendorId is ushort sv && device.Identity.SubsystemDeviceId is ushort sd
                ? $"VEN 0x{sv:X4} / DEV 0x{sd:X4}"
                : "—"),
            new("Revision", device.Identity.Revision is byte r ? $"0x{r:X2}" : "—"),
            new("Class", device.Identity.ClassCode is byte c
                ? $"0x{c:X2}.{device.Identity.Subclass:X2}.{device.Identity.ProgrammingInterface:X2}"
                : "—"),
            new("Resolved vendor", device.Resolved?.VendorName ?? "—"),
            new("Resolved device", device.Resolved?.DeviceName ?? "—"),
            new("Resolved subsystem", device.Resolved?.SubsystemName ?? "—"),
            new("Class name", device.Resolved?.ClassName ?? "—"),
            new("Reference source", device.Resolved?.Source ?? "—")
        ];

        TopologyLines =
        [
            new("Instance ID", device.InstanceId),
            new("Location", device.LocationInformation ?? "—"),
            new("BDF", listItem.Bdf ?? "—"),
            new("Parent", device.ParentInstanceId ?? "—"),
            new("Manufacturer", device.Manufacturer ?? "—"),
            new("Kind", listItem.KindLabel)
        ];

        var drv = device.Driver;
        DriverLines =
        [
            new("Service", drv?.Service ?? "—"),
            new("Name", drv?.DriverName ?? "—"),
            new("Provider", drv?.Provider ?? "—"),
            new("Version", drv?.Version ?? "—"),
            new("Date", drv?.Date ?? "—"),
            new("Image", drv?.ImagePath ?? "—"),
            new("INF", drv?.InfPath ?? "—")
        ];

        var sig = drv?.Signature;
        SignatureStatus = sig?.Status.ToString() ?? "Unknown";
        SignatureStatusEnum = sig?.Status ?? DriverSignatureStatus.Unknown;
        SignatureAnalysis = sig?.AnalysisSummary ?? "No signature analysis available.";
        SignatureTechnical = sig?.TechnicalDetail;
        SignatureLines =
        [
            new("Status", SignatureStatus),
            new("Signer", sig?.SignerSubject ?? "—"),
            new("Issuer", sig?.SignerIssuer ?? "—"),
            new("Thumbprint", sig?.Thumbprint ?? "—"),
            new("Algorithm", sig?.SigningAlgorithm ?? "—"),
            new("Valid from", sig?.NotBefore?.ToString("u") ?? "—"),
            new("Valid to", sig?.NotAfter?.ToString("u") ?? "—"),
            new("File", sig?.CatalogOrFilePath ?? "—")
        ];

        HardwareIds = device.HardwareIds;
        CompatibleIds = device.CompatibleIds;
    }

    public DeviceListItem ListItem { get; }
    public PciDevice? Device { get; }
    public IReadOnlyList<FindingListItem> RelatedFindings { get; }
    public IReadOnlyList<DetailLine> IdentityLines { get; private set; } = [];
    public IReadOnlyList<DetailLine> TopologyLines { get; private set; } = [];
    public IReadOnlyList<DetailLine> DriverLines { get; private set; } = [];
    public IReadOnlyList<DetailLine> SignatureLines { get; private set; } = [];
    public IReadOnlyList<string> HardwareIds { get; private set; } = [];
    public IReadOnlyList<string> CompatibleIds { get; private set; } = [];
    public string SignatureStatus { get; private set; } = "Unknown";
    public DriverSignatureStatus SignatureStatusEnum { get; private set; }
    public string SignatureAnalysis { get; private set; } = "";
    public string? SignatureTechnical { get; private set; }
}

public sealed record DetailLine(string Label, string Value);

using System.Text.Json;
using System.Text.Json.Serialization;
using IronTrace.Contracts.Reporting;
using IronTrace.Contracts.Scanning;

namespace IronTrace.Reporting;

public interface IScanReportExporter
{
    Task ExportJsonAsync(
        ScanSession session,
        string path,
        CancellationToken cancellationToken,
        ExportPrivacyOptions? privacy = null);

    string ToJson(ScanSession session, ExportPrivacyOptions? privacy = null);
}

public sealed class JsonScanReportExporter : IScanReportExporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public string ToJson(ScanSession session, ExportPrivacyOptions? privacy = null)
    {
        var dto = ScanReportMapper.ToReport(session, privacy ?? ExportPrivacyOptions.Default);
        return JsonSerializer.Serialize(dto, Options);
    }

    public async Task ExportJsonAsync(
        ScanSession session,
        string path,
        CancellationToken cancellationToken,
        ExportPrivacyOptions? privacy = null)
    {
        var json = ToJson(session, privacy);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(path, json, cancellationToken).ConfigureAwait(false);
    }
}

public static class ScanReportMapper
{
    public static ScanReportDocument ToReport(ScanSession session, ExportPrivacyOptions? privacy = null)
    {
        privacy ??= ExportPrivacyOptions.Default;

        object? motherboard = null;
        if (session.Motherboard is not null)
        {
            motherboard = new
            {
                session.Motherboard.Manufacturer,
                session.Motherboard.Product,
                session.Motherboard.Version,
                SerialHash = privacy.IncludeSerialHash ? session.Motherboard.SerialHash : null,
                SerialHandling = session.Motherboard.SerialHandling,
                SerialRaw = privacy.IncludeRawSerial ? session.Motherboard.SerialRaw : null,
                session.Motherboard.BiosVendor,
                session.Motherboard.BiosVersion,
                session.Motherboard.BiosReleaseDate,
                session.Motherboard.FirmwareType
            };
        }

        object? codeIntegrity = null;
        if (privacy.IncludeCodeIntegrityEvents && session.CodeIntegrity is not null)
        {
            codeIntegrity = new
            {
                session.CodeIntegrity.Accessible,
                session.CodeIntegrity.AccessDetail,
                session.CodeIntegrity.WindowStartUtc,
                session.CodeIntegrity.WindowEndUtc,
                session.CodeIntegrity.LookbackDays,
                session.CodeIntegrity.EventCount,
                Events = session.CodeIntegrity.Events.Select(e => new
                {
                    e.EventId,
                    e.TimeCreated,
                    e.FilePathTruncated,
                    e.StatusMessage,
                    e.ActivityId
                }).ToList()
            };
        }

        return new ScanReportDocument
        {
            SchemaVersion = session.ReportSchemaVersion,
            IronTraceVersion = session.ApplicationVersion,
            ScanId = session.SessionId,
            ScanStartedAt = session.ScanStartedAt,
            ScanCompletedAt = session.ScanCompletedAt,
            System = session.OperatingSystem is null ? null : new
            {
                session.OperatingSystem.ProductName,
                session.OperatingSystem.Version,
                session.OperatingSystem.BuildNumber,
                session.OperatingSystem.DisplayVersion,
                session.OperatingSystem.Architecture,
                session.OperatingSystem.InstallationType,
                session.OperatingSystem.EditionId
            },
            PlatformSecurity = session.PlatformSecurity,
            Motherboard = motherboard,
            PciDevices = session.PciDevices.Select(d => new
            {
                InstanceId = privacy.IncludeInstanceIds ? d.InstanceId : null,
                Identity = new
                {
                    VendorId = d.Identity.VendorId.ToString("X4"),
                    DeviceId = d.Identity.DeviceId.ToString("X4"),
                    SubsystemVendorId = d.Identity.SubsystemVendorId?.ToString("X4"),
                    SubsystemDeviceId = d.Identity.SubsystemDeviceId?.ToString("X4"),
                    Revision = d.Identity.Revision?.ToString("X2"),
                    ClassCode = d.Identity.ClassCode?.ToString("X2"),
                    Subclass = d.Identity.Subclass?.ToString("X2"),
                    ProgrammingInterface = d.Identity.ProgrammingInterface?.ToString("X2")
                },
                d.FriendlyName,
                d.Description,
                d.Manufacturer,
                d.LocationInformation,
                d.Bus,
                Device = d.DeviceNumber,
                d.Function,
                ParentInstanceId = privacy.IncludeInstanceIds ? d.ParentInstanceId : null,
                Driver = d.Driver is null ? null : new
                {
                    d.Driver.Service,
                    d.Driver.DriverName,
                    d.Driver.Version,
                    d.Driver.Provider,
                    d.Driver.Date,
                    d.Driver.SigningState,
                    InfPath = privacy.IncludeDriverImagePaths ? d.Driver.InfPath : null,
                    ImagePath = privacy.IncludeDriverImagePaths ? d.Driver.ImagePath : null,
                    Signature = d.Driver.Signature is null ? null : new
                    {
                        Status = d.Driver.Signature.Status.ToString(),
                        d.Driver.Signature.SignerSubject,
                        d.Driver.Signature.SignerIssuer,
                        d.Driver.Signature.Thumbprint,
                        d.Driver.Signature.SigningAlgorithm,
                        d.Driver.Signature.NotBefore,
                        d.Driver.Signature.NotAfter,
                        CatalogOrFilePath = privacy.IncludeDriverImagePaths
                            ? d.Driver.Signature.CatalogOrFilePath
                            : null,
                        d.Driver.Signature.AnalysisSummary,
                        d.Driver.Signature.TechnicalDetail
                    }
                },
                d.Resolved,
                Kind = d.Kind.ToString()
            }).ToList<object>(),
            UsbDevices = session.UsbDevices.Select(d => new
            {
                InstanceId = privacy.IncludeInstanceIds ? d.InstanceId : null,
                Identity = new
                {
                    VendorId = d.Identity.VendorId.ToString("X4"),
                    ProductId = d.Identity.ProductId.ToString("X4"),
                    DeviceRelease = d.Identity.DeviceRelease?.ToString("X4")
                },
                d.FriendlyName,
                d.Description,
                d.Manufacturer,
                d.Service,
                d.Resolved,
                Kind = d.Kind.ToString(),
                d.KindReason
            }).ToList<object>(),
            Drivers = session.Drivers.Select(d => new
            {
                d.ServiceName,
                d.DisplayName,
                ImagePath = privacy.IncludeDriverImagePaths ? d.ImagePath : null,
                d.Sha256,
                d.FileName,
                SignatureStatus = d.Signature?.Status.ToString(),
                d.Source
            }).ToList<object>(),
            VulnerableDriverMatches = session.VulnerableDriverMatches,
            CodeIntegrity = codeIntegrity,
            IdentityConsistency = session.IdentityConsistency,
            KernelEvidence = session.KernelEvidence is null ? null : new
            {
                Availability = session.KernelEvidence.Availability.ToString(),
                RuntimeCapabilityStatus = session.KernelEvidence.RuntimeCapabilityStatus.ToString(),
                session.KernelEvidence.ProtocolVersion,
                session.KernelEvidence.CapabilityFlags,
                session.KernelEvidence.MaxConfigReadLength,
                session.KernelEvidence.Detail,
                Devices = session.KernelEvidence.Devices.Select(d => new
                {
                    InstanceId = privacy.IncludeInstanceIds ? d.InstanceId : null,
                    d.Bus,
                    Device = d.Device,
                    d.Function,
                    ConfigVendorId = d.ConfigVendorId?.ToString("X4"),
                    ConfigDeviceId = d.ConfigDeviceId?.ToString("X4"),
                    ConfigRevision = d.ConfigRevision?.ToString("X2"),
                    ConfigClassCode = d.ConfigClassCode?.ToString("X2"),
                    ConfigSubclass = d.ConfigSubclass?.ToString("X2"),
                    ConfigProgIf = d.ConfigProgIf?.ToString("X2"),
                    Capabilities = d.Capabilities.Select(c => new
                    {
                        CapabilityId = c.CapabilityId.ToString("X4"),
                        Offset = c.Offset.ToString("X4"),
                        c.IsExtended
                    }).ToList(),
                    Bars = d.Bars.Select(b => new
                    {
                        b.Index,
                        b.BarType,
                        BaseAddress = b.BaseAddress?.ToString("X"),
                        Size = b.Size?.ToString("X")
                    }).ToList(),
                    Express = d.Express is null ? null : new
                    {
                        d.Express.HasPcie,
                        d.Express.HasAer,
                        d.Express.HasAcs,
                        d.Express.HasAts,
                        d.Express.HasSriov,
                        d.Express.SupportsFlr,
                        DeviceControl = d.Express.DeviceControl?.ToString("X4"),
                        LinkStatus = d.Express.LinkStatus?.ToString("X4"),
                        d.Express.MaxPayloadSupported,
                        d.Express.MaxReadRequest
                    },
                    d.DeviceSerialNumberHex,
                    d.Notes
                }).ToList()
            },
            ChallengeEvidence = session.ChallengeEvidence is null ? null : new
            {
                Availability = session.ChallengeEvidence.Availability.ToString(),
                session.ChallengeEvidence.Detail,
                Decisions = session.ChallengeEvidence.Decisions.Select(d => new
                {
                    d.Bus,
                    Device = d.Device,
                    d.Function,
                    ClassCode = d.ClassCode?.ToString("X2"),
                    Subclass = d.Subclass?.ToString("X2"),
                    Decision = d.Decision.ToString(),
                    d.Reason,
                    d.SupportsFlr
                }).ToList()
            },
            SpdmEvidence = session.SpdmEvidence is null ? null : new
            {
                Availability = session.SpdmEvidence.Availability.ToString(),
                session.SpdmEvidence.Detail,
                Devices = session.SpdmEvidence.Devices.Select(d => new
                {
                    d.Bus,
                    Device = d.Device,
                    d.Function,
                    d.DoePresent,
                    SpdmStackStatus = d.SpdmStackStatus.ToString(),
                    d.Detail
                }).ToList()
            },
            MeasuredBootEvidence = MapMeasuredBoot(session.MeasuredBootEvidence, privacy),
            PnpHistory = MapPnPHistory(session.PnPHistory, privacy),
            ScanProfile = session.ScanProfile.ToString(),
            ScanConsent = session.ScanConsent,
            ForensicEvidence = session.ForensicEvidence,
            ForensicVerdictBanner = session.ForensicEvidence?.VerdictBanner?.ToString(),
            Findings = session.RiskAssessment?.Findings ?? Array.Empty<Contracts.Findings.Finding>(),
            Assessment = session.RiskAssessment is null ? null : new
            {
                Verdict = session.RiskAssessment.Verdict.ToString(),
                session.RiskAssessment.Summary,
                session.RiskAssessment.InformationalCount,
                session.RiskAssessment.LowCount,
                session.RiskAssessment.MediumCount,
                session.RiskAssessment.HighCount,
                session.RiskAssessment.CriticalCount,
                session.RiskAssessment.ConsistentDeviceCount,
                session.RiskAssessment.ReviewDeviceCount
            },
            Errors = session.Errors,
            Metadata = session.Metadata,
            ExportPrivacy = new
            {
                privacy.IncludeSerialHash,
                privacy.IncludeDriverImagePaths,
                privacy.IncludeCodeIntegrityEvents,
                privacy.IncludeInstanceIds,
                privacy.IncludeRawSerial,
                privacy.IncludePcrDigests
            }
        };
    }

    private static object? MapMeasuredBoot(
        Contracts.Challenge.MeasuredBootEvidenceSnapshot? evidence,
        ExportPrivacyOptions privacy)
    {
        if (evidence is null)
            return null;

        return new
        {
            Availability = evidence.Availability.ToString(),
            evidence.TpmPresent,
            evidence.TpmSpecVersion,
            evidence.PcrBank,
            Pcrs = privacy.IncludePcrDigests
                ? evidence.Pcrs.Select(p => (object)new { p.Index, p.DigestHex }).ToList()
                : new List<object>(),
            evidence.Detail
        };
    }

    private static object? MapPnPHistory(
        Contracts.Hardware.PnPHistorySnapshot? evidence,
        ExportPrivacyOptions privacy)
    {
        if (evidence is null)
            return null;

        return new
        {
            Availability = evidence.Availability.ToString(),
            evidence.OptInEnabled,
            evidence.Detail,
            WatchlistHitsNotOnBus = evidence.WatchlistHitsNotOnBus.Select(h => new
            {
                InstanceId = privacy.IncludeInstanceIds ? h.InstanceId : null,
                VendorId = h.VendorId.ToString("X4"),
                DeviceId = h.DeviceId.ToString("X4"),
                h.FriendlyName,
                h.PresentOnBus
            }).ToList()
        };
    }
}

public sealed class ScanReportDocument
{
    public string SchemaVersion { get; init; } = "1.6";
    public string IronTraceVersion { get; init; } = "0.7.0";
    public Guid ScanId { get; init; }
    public DateTimeOffset ScanStartedAt { get; init; }
    public DateTimeOffset? ScanCompletedAt { get; init; }
    public object? System { get; init; }
    public object? PlatformSecurity { get; init; }
    public object? Motherboard { get; init; }
    public IReadOnlyList<object> PciDevices { get; init; } = Array.Empty<object>();
    public IReadOnlyList<object> UsbDevices { get; init; } = Array.Empty<object>();
    public IReadOnlyList<object> Drivers { get; init; } = Array.Empty<object>();
    public object? VulnerableDriverMatches { get; init; }
    public object? CodeIntegrity { get; init; }
    public object? IdentityConsistency { get; init; }
    public object? KernelEvidence { get; init; }
    public object? ChallengeEvidence { get; init; }
    public object? SpdmEvidence { get; init; }
    public object? MeasuredBootEvidence { get; init; }
    public object? PnpHistory { get; init; }
    public string? ScanProfile { get; init; }
    public object? ScanConsent { get; init; }
    public object? ForensicEvidence { get; init; }
    public string? ForensicVerdictBanner { get; init; }
    public object Findings { get; init; } = Array.Empty<object>();
    public object? Assessment { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> Metadata { get; init; } =
        new Dictionary<string, string>();
    public object? ExportPrivacy { get; init; }
}

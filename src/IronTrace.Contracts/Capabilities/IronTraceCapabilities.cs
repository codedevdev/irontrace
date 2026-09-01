using IronTrace.Contracts.Enums;

namespace IronTrace.Contracts.Capabilities;

public static class IronTraceCapabilities
{
    public static IReadOnlyDictionary<string, CapabilityStatus> Phase1 { get; } =
        new Dictionary<string, CapabilityStatus>(StringComparer.OrdinalIgnoreCase)
        {
            ["UserModePciInventory"] = CapabilityStatus.Supported,
            ["LocalPciIdsLookup"] = CapabilityStatus.Supported,
            ["PlatformSecuritySnapshot"] = CapabilityStatus.Supported,
            ["JsonReportExport"] = CapabilityStatus.Supported,
            ["UsbReferenceDb"] = CapabilityStatus.Supported,
            ["UsbInventory"] = CapabilityStatus.Supported,
            ["CodeIntegrityLogSnapshot"] = CapabilityStatus.Supported,
            ["LolDriversMatch"] = CapabilityStatus.Supported,
            ["DriverInventory"] = CapabilityStatus.Supported,
            ["IdentityConsistencyChecks"] = CapabilityStatus.Supported,
            ["ReferenceDbSignedUpdates"] = CapabilityStatus.Supported,
            ["DeviceKindClassifier"] = CapabilityStatus.Supported,
            ["ExportPrivacyOptions"] = CapabilityStatus.Supported,
            ["ElevatedSecurityDetails"] = CapabilityStatus.Supported,
            ["KernelDriver"] = CapabilityStatus.Supported,
            ["DeviceResetChallenge"] = CapabilityStatus.Partial,
            ["SpdmAttestation"] = CapabilityStatus.Partial,
            ["MeasuredBootEvidence"] = CapabilityStatus.Partial,
            ["ServerUpload"] = CapabilityStatus.Supported
        };
}

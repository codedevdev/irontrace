namespace IronTrace.Contracts.Enums;

public enum SecurityFeatureState
{
    Unknown = 0,
    Enabled = 1,
    Disabled = 2,
    SupportedButDisabled = 3,
    Unsupported = 4
}

public enum IntegrityVerdict
{
    Unverified = 0,
    Normal = 1,
    LowRisk = 2,
    ReviewRecommended = 3,
    Suspicious = 4,
    HighRisk = 5,
    Verified = 6
}

public enum FindingSeverity
{
    Information = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum FindingConfidence
{
    Low = 0,
    Medium = 1,
    High = 2,
    ReferenceIdentity = 3
}

public enum CapabilityStatus
{
    Supported = 0,
    Unsupported = 1,
    Planned = 2,
    NotImplemented = 3,
    Partial = 4,
    Unknown = 5
}

public enum SerialHandling
{
    NotCollected = 0,
    Hashed = 1,
    Raw = 2
}

public enum DeviceKind
{
    Unknown = 0,
    Physical = 1,
    VirtualOrSoftware = 2
}

public enum DriverSignatureStatus
{
    Unknown = 0,
    Unsigned = 1,
    AuthenticodeSigned = 2,
    CatalogSigned = 3,
    MicrosoftSigned = 4,
    Expired = 5,
    Untrusted = 6,
    Error = 7
}

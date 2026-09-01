using System.Runtime.InteropServices;

namespace IronTrace.Contracts.Driver;

/// <summary>Versioned IOCTL protocol shared with IronTrace.Driver (see IronTraceDriverProtocol.h).</summary>
public static class DriverProtocol
{
    public const uint Version = 2;
    public const uint MinVersion = 1;

    public const uint DeviceType = 0x8000;
    public const uint MethodBuffered = 0;
    public const uint FileAnyAccess = 0;

    public static readonly Guid DeviceInterfaceGuid =
        new("B8E4D1A0-2F3C-4A5B-9C8D-1E2F3A4B5C6D");

    public const uint CapReadPciConfig = 1u << 0;
    public const uint CapEnumerateCapabilities = 1u << 1;
    public const uint CapQueryBarLayout = 1u << 2;
    public const uint CapQueryExpressCaps = 1u << 3;
    public const uint CapSafeDeviceReset = 1u << 4; // remains unset — never execute FLR
    public const uint CapQueryBarSizeProbe = 1u << 5; // protocol 2 — gated write-probe for BAR size

    public const uint MaxConfigReadStandard = 256;
    public const uint MaxConfigReadExtended = 4096;
    public const int MaxCapabilityEntries = 64;
    public const int MaxBars = 6;

    public const uint ExpressHasPcie = 1u << 0;
    public const uint ExpressHasAer = 1u << 1;
    public const uint ExpressHasAcs = 1u << 2;
    public const uint ExpressHasAts = 1u << 3;
    public const uint ExpressHasSriov = 1u << 4;
    public const uint ExpressSupportsFlr = 1u << 5;

    public static readonly uint IoctlGetProtocolInfo = CtlCode(DeviceType, 0x800, MethodBuffered, FileAnyAccess);
    public static readonly uint IoctlReadPciConfig = CtlCode(DeviceType, 0x801, MethodBuffered, FileAnyAccess);
    public static readonly uint IoctlEnumerateCapabilities = CtlCode(DeviceType, 0x802, MethodBuffered, FileAnyAccess);
    public static readonly uint IoctlQueryBarLayout = CtlCode(DeviceType, 0x803, MethodBuffered, FileAnyAccess);
    public static readonly uint IoctlQueryExpressCaps = CtlCode(DeviceType, 0x804, MethodBuffered, FileAnyAccess);
    public static readonly uint IoctlSafeDeviceReset = CtlCode(DeviceType, 0x805, MethodBuffered, FileAnyAccess);

    /// <summary>Phase 4 base capabilities (reset and size-probe excluded).</summary>
    public const uint MvpCapabilityFlags =
        CapReadPciConfig | CapEnumerateCapabilities | CapQueryBarLayout | CapQueryExpressCaps;

    /// <summary>Protocol 2 advertised set (SafeDeviceReset still excluded).</summary>
    public const uint Protocol2CapabilityFlags = MvpCapabilityFlags | CapQueryBarSizeProbe;

    public static uint CtlCode(uint deviceType, uint function, uint method, uint access)
        => (deviceType << 16) | (access << 14) | (function << 2) | method;

    public static bool IsCompatible(uint driverProtocolVersion)
        => driverProtocolVersion >= MinVersion && driverProtocolVersion <= Version;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceBdf
{
    public byte Bus;
    public byte Device;
    public byte Function;
    public byte Reserved;

    public IronTraceBdf(byte bus, byte device, byte function)
    {
        Bus = bus;
        Device = device;
        Function = function;
        Reserved = 0;
    }

    public bool IsValid()
        => Device <= 31 && Function <= 7;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceProtocolInfo
{
    public uint ProtocolVersion;
    public uint MinProtocolVersion;
    public uint CapabilityFlags;
    public uint MaxConfigReadLength;
    public uint DriverBuild;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceReadPciConfigRequest
{
    public IronTraceBdf Bdf;
    public ushort Offset;
    public ushort Length;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceReadPciConfigResponseHeader
{
    public ushort BytesReturned;
    public ushort Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceEnumCapsRequest
{
    public IronTraceBdf Bdf;
    public ushort MaxEntries;
    public ushort Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceCapabilityEntry
{
    public ushort CapabilityId;
    public ushort Offset;
    public byte IsExtended;
    public byte Reserved0;
    public byte Reserved1;
    public byte Reserved2;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceEnumCapsResponseHeader
{
    public ushort Count;
    public ushort Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceQueryBarRequest
{
    public IronTraceBdf Bdf;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceBarInfo
{
    public byte Index;
    public byte BarType;
    public byte Reserved0;
    public byte Reserved1;
    public ulong BaseAddress;
    public ulong Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceQueryBarResponse
{
    public byte BarCount;
    public byte Reserved0;
    public byte Reserved1;
    public byte Reserved2;
    public IronTraceBarInfo Bar0;
    public IronTraceBarInfo Bar1;
    public IronTraceBarInfo Bar2;
    public IronTraceBarInfo Bar3;
    public IronTraceBarInfo Bar4;
    public IronTraceBarInfo Bar5;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceQueryExpressRequest
{
    public IronTraceBdf Bdf;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceQueryExpressResponse
{
    public uint Flags;
    public ushort DeviceControl;
    public ushort LinkStatus;
    public byte MaxPayloadSupported;
    public byte MaxReadRequest;
    public byte Reserved0;
    public byte Reserved1;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct IronTraceSafeResetRequest
{
    public IronTraceBdf Bdf;
    public uint Reserved;
}

using System.Runtime.InteropServices;
using IronTrace.Contracts.Driver;
using IronTrace.Contracts.Hardware;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace IronTrace.Windows.Driver;

public sealed class IronTraceDriverClient : IIronTraceDriverClient
{
    private readonly ILogger<IronTraceDriverClient> _logger;
    private SafeFileHandle? _handle;
    private IronTraceProtocolInfo? _info;
    private KernelDriverAvailability _availability = KernelDriverAvailability.Unavailable;
    private bool _disposed;

    public IronTraceDriverClient(ILogger<IronTraceDriverClient> logger)
        => _logger = logger;

    public KernelDriverAvailability Availability => _availability;

    public KernelDriverAvailability TryOpen()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_handle is { IsInvalid: false })
            return _availability;

        try
        {
            var path = ResolveDevicePath();
            if (path is null)
            {
                _availability = KernelDriverAvailability.Unavailable;
                _logger.LogDebug("IronTrace.Driver device interface not present");
                return _availability;
            }

            _handle = CreateFile(
                path,
                NativeMethods.GenericRead | NativeMethods.GenericWrite,
                NativeMethods.FileShareRead | NativeMethods.FileShareWrite,
                IntPtr.Zero,
                NativeMethods.OpenExisting,
                0,
                IntPtr.Zero);

            if (_handle.IsInvalid)
            {
                var err = Marshal.GetLastWin32Error();
                _handle.Dispose();
                _handle = null;
                _availability = KernelDriverAvailability.Unavailable;
                _logger.LogDebug("CreateFile for IronTrace.Driver failed: {Error}", err);
                return _availability;
            }

            _info = QueryProtocolInfoCore();
            if (_info is null)
            {
                CloseHandleOnly();
                _availability = KernelDriverAvailability.Unavailable;
                return _availability;
            }

            if (!DriverProtocol.IsCompatible(_info.Value.ProtocolVersion))
            {
                _logger.LogWarning(
                    "IronTrace.Driver protocol {Version} incompatible with client {Client}",
                    _info.Value.ProtocolVersion,
                    DriverProtocol.Version);
                CloseHandleOnly();
                _availability = KernelDriverAvailability.Unsupported;
                return _availability;
            }

            var caps = _info.Value.CapabilityFlags;
            // CapSafeDeviceReset must never be required or treated as a success signal.
            var expected = _info.Value.ProtocolVersion >= 2
                ? DriverProtocol.Protocol2CapabilityFlags
                : DriverProtocol.MvpCapabilityFlags;
            _availability = (caps & expected) == expected
                ? KernelDriverAvailability.Available
                : KernelDriverAvailability.Partial;

            return _availability;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to open IronTrace.Driver");
            CloseHandleOnly();
            _availability = KernelDriverAvailability.Unavailable;
            return _availability;
        }
    }

    public IronTraceProtocolInfo? GetProtocolInfo()
    {
        if (_availability is KernelDriverAvailability.Unavailable or KernelDriverAvailability.Unsupported)
            return null;
        return _info ?? QueryProtocolInfoCore();
    }

    public byte[]? ReadPciConfig(IronTraceBdf bdf, ushort offset, ushort length)
    {
        if (!EnsureOpen() || !bdf.IsValid() || length == 0)
            return null;

        var max = _info?.MaxConfigReadLength ?? DriverProtocol.MaxConfigReadStandard;
        if (offset + length > max || length > max)
            return null;

        var request = new IronTraceReadPciConfigRequest
        {
            Bdf = bdf,
            Offset = offset,
            Length = length
        };

        var outSize = Marshal.SizeOf<IronTraceReadPciConfigResponseHeader>() + length;
        var output = new byte[outSize];
        if (!DeviceIoControl(DriverProtocol.IoctlReadPciConfig, request, output, out var returned) ||
            returned < Marshal.SizeOf<IronTraceReadPciConfigResponseHeader>())
        {
            return null;
        }

        var header = MemoryMarshal.Read<IronTraceReadPciConfigResponseHeader>(output);
        var dataLen = Math.Min(header.BytesReturned, length);
        var data = new byte[dataLen];
        Buffer.BlockCopy(output, Marshal.SizeOf<IronTraceReadPciConfigResponseHeader>(), data, 0, dataLen);
        return data;
    }

    public IReadOnlyList<IronTraceCapabilityEntry> EnumerateCapabilities(
        IronTraceBdf bdf,
        ushort maxEntries = DriverProtocol.MaxCapabilityEntries)
    {
        if (!EnsureOpen() || !bdf.IsValid())
            return Array.Empty<IronTraceCapabilityEntry>();

        maxEntries = (ushort)Math.Clamp(maxEntries, (ushort)1, (ushort)DriverProtocol.MaxCapabilityEntries);
        var request = new IronTraceEnumCapsRequest
        {
            Bdf = bdf,
            MaxEntries = maxEntries,
            Reserved = 0
        };

        var entrySize = Marshal.SizeOf<IronTraceCapabilityEntry>();
        var outSize = Marshal.SizeOf<IronTraceEnumCapsResponseHeader>() + entrySize * maxEntries;
        var output = new byte[outSize];
        if (!DeviceIoControl(DriverProtocol.IoctlEnumerateCapabilities, request, output, out var returned) ||
            returned < Marshal.SizeOf<IronTraceEnumCapsResponseHeader>())
        {
            return Array.Empty<IronTraceCapabilityEntry>();
        }

        var header = MemoryMarshal.Read<IronTraceEnumCapsResponseHeader>(output);
        var count = Math.Min(header.Count, maxEntries);
        var list = new List<IronTraceCapabilityEntry>(count);
        var offset = Marshal.SizeOf<IronTraceEnumCapsResponseHeader>();
        for (var i = 0; i < count; i++)
        {
            list.Add(MemoryMarshal.Read<IronTraceCapabilityEntry>(output.AsSpan(offset)));
            offset += entrySize;
        }

        return list;
    }

    public IronTraceQueryBarResponse? QueryBarLayout(IronTraceBdf bdf)
    {
        if (!EnsureOpen() || !bdf.IsValid())
            return null;

        var request = new IronTraceQueryBarRequest { Bdf = bdf };
        var output = new byte[Marshal.SizeOf<IronTraceQueryBarResponse>()];
        if (!DeviceIoControl(DriverProtocol.IoctlQueryBarLayout, request, output, out var returned) ||
            returned < Marshal.SizeOf<IronTraceQueryBarResponse>())
        {
            return null;
        }

        return MemoryMarshal.Read<IronTraceQueryBarResponse>(output);
    }

    public IronTraceQueryExpressResponse? QueryExpressCaps(IronTraceBdf bdf)
    {
        if (!EnsureOpen() || !bdf.IsValid())
            return null;

        var request = new IronTraceQueryExpressRequest { Bdf = bdf };
        var output = new byte[Marshal.SizeOf<IronTraceQueryExpressResponse>()];
        if (!DeviceIoControl(DriverProtocol.IoctlQueryExpressCaps, request, output, out var returned) ||
            returned < Marshal.SizeOf<IronTraceQueryExpressResponse>())
        {
            return null;
        }

        return MemoryMarshal.Read<IronTraceQueryExpressResponse>(output);
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        CloseHandleOnly();
    }

    private bool EnsureOpen()
    {
        if (_handle is { IsInvalid: false } &&
            _availability is KernelDriverAvailability.Available or KernelDriverAvailability.Partial)
        {
            return true;
        }

        var status = TryOpen();
        return status is KernelDriverAvailability.Available or KernelDriverAvailability.Partial;
    }

    private IronTraceProtocolInfo? QueryProtocolInfoCore()
    {
        var output = new byte[Marshal.SizeOf<IronTraceProtocolInfo>()];
        if (!DeviceIoControl(DriverProtocol.IoctlGetProtocolInfo, ReadOnlySpan<byte>.Empty, output, out var returned) ||
            returned < Marshal.SizeOf<IronTraceProtocolInfo>())
        {
            return null;
        }

        return MemoryMarshal.Read<IronTraceProtocolInfo>(output);
    }

    private bool DeviceIoControl<TRequest>(uint ioctl, TRequest request, byte[] output, out int bytesReturned)
        where TRequest : struct
    {
        var size = Marshal.SizeOf<TRequest>();
        var input = new byte[size];
        MemoryMarshal.Write(input, in request);
        return DeviceIoControl(ioctl, input, output, out bytesReturned);
    }

    private bool DeviceIoControl(uint ioctl, ReadOnlySpan<byte> input, byte[] output, out int bytesReturned)
    {
        bytesReturned = 0;
        if (_handle is null || _handle.IsInvalid)
            return false;

        var inBuf = input.IsEmpty ? null : input.ToArray();
        return NativeMethods.DeviceIoControl(
            _handle,
            ioctl,
            inBuf,
            inBuf?.Length ?? 0,
            output,
            output.Length,
            out bytesReturned,
            IntPtr.Zero);
    }

    private void CloseHandleOnly()
    {
        _handle?.Dispose();
        _handle = null;
        _info = null;
    }

    private static string? ResolveDevicePath()
    {
        var list = NativeMethods.SetupDiGetClassDevs(
            DriverProtocol.DeviceInterfaceGuid,
            IntPtr.Zero,
            IntPtr.Zero,
            NativeMethods.DigcfDeviceInterface | NativeMethods.DigcfPresent);

        if (list == NativeMethods.InvalidHandleValue)
            return null;

        try
        {
            var data = new NativeMethods.SpDeviceInterfaceData
            {
                CbSize = Marshal.SizeOf<NativeMethods.SpDeviceInterfaceData>()
            };

            if (!NativeMethods.SetupDiEnumDeviceInterfaces(list, IntPtr.Zero, DriverProtocol.DeviceInterfaceGuid, 0, ref data))
                return null;

            NativeMethods.SetupDiGetDeviceInterfaceDetail(
                list,
                ref data,
                IntPtr.Zero,
                0,
                out var required,
                IntPtr.Zero);

            if (required == 0)
                return null;

            var detailPtr = Marshal.AllocHGlobal((int)required);
            try
            {
                Marshal.WriteInt32(detailPtr, IntPtr.Size == 8 ? 8 : 6);
                if (!NativeMethods.SetupDiGetDeviceInterfaceDetail(
                        list,
                        ref data,
                        detailPtr,
                        required,
                        out _,
                        IntPtr.Zero))
                {
                    return null;
                }

                var pathOffset = IntPtr.Size == 8 ? 8 : 4;
                return Marshal.PtrToStringUni(detailPtr + pathOffset);
            }
            finally
            {
                Marshal.FreeHGlobal(detailPtr);
            }
        }
        finally
        {
            NativeMethods.SetupDiDestroyDeviceInfoList(list);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    private static class NativeMethods
    {
        public const uint GenericRead = 0x80000000;
        public const uint GenericWrite = 0x40000000;
        public const uint FileShareRead = 0x00000001;
        public const uint FileShareWrite = 0x00000002;
        public const uint OpenExisting = 3;
        public const uint DigcfPresent = 0x00000002;
        public const uint DigcfDeviceInterface = 0x00000010;
        public static readonly IntPtr InvalidHandleValue = new(-1);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            byte[]? lpInBuffer,
            int nInBufferSize,
            byte[] lpOutBuffer,
            int nOutBufferSize,
            out int lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern IntPtr SetupDiGetClassDevs(
            Guid classGuid,
            IntPtr enumerator,
            IntPtr hwndParent,
            uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInterfaces(
            IntPtr deviceInfoSet,
            IntPtr deviceInfoData,
            Guid interfaceClassGuid,
            uint memberIndex,
            ref SpDeviceInterfaceData deviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool SetupDiGetDeviceInterfaceDetail(
            IntPtr deviceInfoSet,
            ref SpDeviceInterfaceData deviceInterfaceData,
            IntPtr deviceInterfaceDetailData,
            uint deviceInterfaceDetailDataSize,
            out uint requiredSize,
            IntPtr deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [StructLayout(LayoutKind.Sequential)]
        public struct SpDeviceInterfaceData
        {
            public int CbSize;
            public Guid InterfaceClassGuid;
            public uint Flags;
            public IntPtr Reserved;
        }
    }
}

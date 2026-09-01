using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Core.Paths;
using IronTrace.Core.Scanning;
using IronTrace.Hardware.Classification;
using IronTrace.Hardware.Parsing;
using IronTrace.Hardware.Signing;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Hardware.Collectors;

public sealed class MotherboardCollector : IMotherboardCollector
{
    private readonly ILogger<MotherboardCollector> _logger;
    private readonly ISerialPrivacyService _serialPrivacy;

    public MotherboardCollector(ILogger<MotherboardCollector> logger, ISerialPrivacyService serialPrivacy)
    {
        _logger = logger;
        _serialPrivacy = serialPrivacy;
    }

    public Task<MotherboardInfo> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? manufacturer = null, product = null, version = null, serial = null;
        string? biosVendor = null, biosVersion = null, biosDate = null;

        try
        {
            using (var boardSearcher = new ManagementObjectSearcher("SELECT Manufacturer, Product, Version, SerialNumber FROM Win32_BaseBoard"))
            using (var boards = boardSearcher.Get())
            {
                foreach (ManagementObject obj in boards)
                {
                    using (obj)
                    {
                        manufacturer = obj["Manufacturer"]?.ToString();
                        product = obj["Product"]?.ToString();
                        version = obj["Version"]?.ToString();
                        serial = obj["SerialNumber"]?.ToString();
                        break;
                    }
                }
            }

            using var biosSearcher = new ManagementObjectSearcher("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
            using var bioses = biosSearcher.Get();
            foreach (ManagementObject obj in bioses)
            {
                using (obj)
                {
                    biosVendor = obj["Manufacturer"]?.ToString();
                    biosVersion = obj["SMBIOSBIOSVersion"]?.ToString();
                    biosDate = FormatBiosDate(obj["ReleaseDate"]?.ToString());
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Motherboard/BIOS WMI query failed");
        }

        var (raw, hash, handling) = _serialPrivacy.ProcessSerial(serial, includeRaw: true);
        var firmware = DetectFirmwareType();

        return Task.FromResult(new MotherboardInfo(
            manufacturer,
            product,
            version,
            raw,
            hash,
            handling,
            biosVendor,
            biosVersion,
            biosDate,
            firmware));
    }

    private static string? FormatBiosDate(string? cimDate)
    {
        if (string.IsNullOrWhiteSpace(cimDate) || cimDate.Length < 8)
        {
            return cimDate;
        }

        // yyyyMMddHHmmss.xxxxxx±UUU
        return $"{cimDate[..4]}-{cimDate.Substring(4, 2)}-{cimDate.Substring(6, 2)}";
    }

    private string DetectFirmwareType()
    {
        try
        {
            if (NativeMethods.GetFirmwareType(out var type))
            {
                return type switch
                {
                    NativeMethods.FirmwareType.FirmwareTypeBios => "BIOS",
                    NativeMethods.FirmwareType.FirmwareTypeUefi => "UEFI",
                    _ => "Unknown"
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "GetFirmwareType failed");
        }

        return "Unknown";
    }
}

public interface ISerialPrivacyService
{
    (string? Raw, string? Hash, SerialHandling Handling) ProcessSerial(string? serial, bool includeRaw = false);
}

public sealed class DpapiSerialPrivacyService : ISerialPrivacyService
{
    private readonly byte[] _key;

    public DpapiSerialPrivacyService()
    {
        IronTracePaths.EnsureCreated();
        var keyPath = Path.Combine(IronTracePaths.Keys, "serial-hmac.key");
        if (File.Exists(keyPath))
        {
            var protectedBytes = File.ReadAllBytes(keyPath);
            _key = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }
        else
        {
            _key = RandomNumberGenerator.GetBytes(32);
            var protectedBytes = ProtectedData.Protect(_key, optionalEntropy: null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(keyPath, protectedBytes);
        }
    }

    public (string? Raw, string? Hash, SerialHandling Handling) ProcessSerial(string? serial, bool includeRaw = false)
    {
        if (string.IsNullOrWhiteSpace(serial) ||
            serial.Equals("None", StringComparison.OrdinalIgnoreCase) ||
            serial.Equals("To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase) ||
            serial.Equals("Default string", StringComparison.OrdinalIgnoreCase))
        {
            return (null, null, SerialHandling.NotCollected);
        }

        var hash = Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(serial.Trim())))
            .ToLowerInvariant();
        return includeRaw
            ? (serial.Trim(), hash, SerialHandling.Raw)
            : (null, hash, SerialHandling.Hashed);
    }
}

public sealed class PciInventoryCollector : IPciInventoryCollector
{
    private readonly ILogger<PciInventoryCollector> _logger;
    private readonly IDriverSignatureAnalyzer _signatureAnalyzer;

    public PciInventoryCollector(
        ILogger<PciInventoryCollector> logger,
        IDriverSignatureAnalyzer signatureAnalyzer)
    {
        _logger = logger;
        _signatureAnalyzer = signatureAnalyzer;
    }

    public Task<IReadOnlyList<PciDevice>> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var devices = new List<PciDevice>();

        try
        {
            // Enumerate present devices; filter to PCI instance IDs.
            var ids = EnumeratePciInstanceIds();
            foreach (var instanceId in ids)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var device = ReadDevice(instanceId);
                    if (device is not null)
                    {
                        devices.Add(device);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed reading PCI device {InstanceId}", instanceId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PCI enumeration failed");
            throw;
        }

        return Task.FromResult<IReadOnlyList<PciDevice>>(devices);
    }

    private static IEnumerable<string> EnumeratePciInstanceIds()
    {
        // Prefer CM API list filtered by PCI\
        var list = new List<string>();
        var size = 0;
        var cr = NativeMethods.CM_Get_Device_ID_List_Size(ref size, null, NativeMethods.CM_GETIDLIST_FILTER_NONE);
        if (cr != 0 || size <= 0)
        {
            // Fallback via SetupDi PCI class enum
            return EnumerateViaSetupDi();
        }

        var buffer = new char[size];
        cr = NativeMethods.CM_Get_Device_ID_List(null, buffer, size, NativeMethods.CM_GETIDLIST_FILTER_NONE);
        if (cr != 0)
        {
            return EnumerateViaSetupDi();
        }

        var start = 0;
        for (var i = 0; i < buffer.Length; i++)
        {
            if (buffer[i] != '\0')
            {
                continue;
            }

            if (i > start)
            {
                var id = new string(buffer, start, i - start);
                if (id.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase))
                {
                    list.Add(id);
                }
            }

            start = i + 1;
            if (start < buffer.Length && buffer[start] == '\0')
            {
                break;
            }
        }

        return list.Count > 0 ? list : EnumerateViaSetupDi();
    }

    private static IEnumerable<string> EnumerateViaSetupDi()
    {
        var list = new List<string>();
        var guid = NativeMethods.GUID_DEVCLASS_PCI;
        var info = NativeMethods.SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero,
            NativeMethods.DIGCF_PRESENT);
        if (info == NativeMethods.InvalidHandle)
        {
            return list;
        }

        try
        {
            var data = new NativeMethods.SP_DEVINFO_DATA
            {
                cbSize = Marshal.SizeOf<NativeMethods.SP_DEVINFO_DATA>()
            };
            for (uint i = 0; NativeMethods.SetupDiEnumDeviceInfo(info, i, ref data); i++)
            {
                if (TryGetDeviceInstanceId(info, data, out var id) &&
                    id.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase))
                {
                    list.Add(id);
                }
            }
        }
        finally
        {
            NativeMethods.SetupDiDestroyDeviceInfoList(info);
        }

        return list;
    }

    private PciDevice? ReadDevice(string instanceId)
    {
        var hardwareIds = ReadMultiSzProperty(instanceId, "HardwareID");
        var compatibleIds = ReadMultiSzProperty(instanceId, "CompatibleIDs");
        var identity = PciHardwareIdParser.ParseFirst(hardwareIds.Concat(new[] { instanceId }));
        if (identity is null)
        {
            return null;
        }

        byte? cc = identity.ClassCode, sc = identity.Subclass, pi = identity.ProgrammingInterface;
        foreach (var c in compatibleIds.Concat(hardwareIds))
        {
            if (PciHardwareIdParser.TryParseClassCode(c, out var cCode, out var sCode, out var pCode))
            {
                cc = cCode;
                sc = sCode;
                pi = pCode;
                break;
            }
        }

        identity = PciHardwareIdParser.WithClass(identity, cc, sc, pi);

        var friendly = ReadRegistryProperty(instanceId, "FriendlyName");
        var description = ReadRegistryProperty(instanceId, "DeviceDesc") ?? friendly;
        var manufacturer = ReadRegistryProperty(instanceId, "Mfg");
        var location = ReadRegistryProperty(instanceId, "LocationInformation");
        var service = ReadRegistryProperty(instanceId, "Service");
        var (bus, deviceNumber, function) = ParseLocation(location, instanceId);
        var parent = TryGetParent(instanceId);
        var driver = ReadDriverInfo(instanceId, service);
        var classification = DeviceKindClassifier.Classify(
            instanceId, service, description, friendly, manufacturer, hardwareIds);
        var kind = classification.Kind;

        return new PciDevice(
            instanceId,
            identity,
            friendly,
            description,
            manufacturer,
            location,
            bus,
            deviceNumber,
            function,
            parent,
            driver,
            Resolved: null,
            kind,
            hardwareIds,
            compatibleIds);
    }

    private DriverInfo? ReadDriverInfo(string instanceId, string? service)
    {
        try
        {
            var driverKey = ReadRegistryProperty(instanceId, "Driver");
            string? version = null, provider = null, date = null, name = null, infPath = null;
            if (!string.IsNullOrWhiteSpace(driverKey))
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\" + driverKey);
                version = key?.GetValue("DriverVersion") as string;
                provider = key?.GetValue("ProviderName") as string;
                date = key?.GetValue("DriverDate") as string;
                name = key?.GetValue("DriverDesc") as string ?? key?.GetValue("InfPath") as string;
                infPath = key?.GetValue("InfPath") as string;
            }

            var imagePath = DriverPathResolver.ResolveServiceImagePath(service);
            var infFull = DriverPathResolver.ResolveInfFullPath(infPath);
            var signature = _signatureAnalyzer.Analyze(imagePath, infFull ?? infPath);
            var signingState = signature.Status.ToString();

            if (service is null && version is null && provider is null && name is null &&
                imagePath is null && signature.Status == DriverSignatureStatus.Unknown)
            {
                return null;
            }

            return new DriverInfo(
                service,
                name,
                version,
                provider,
                date,
                signingState,
                InfPath: infFull ?? infPath,
                ImagePath: imagePath,
                Signature: signature);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Driver info read failed for {InstanceId}", instanceId);
            return new DriverInfo(service, null, null, null, null, "Unknown",
                Signature: DriverSignatureMapper.Create(
                    DriverSignatureStatus.Error,
                    "Driver metadata read failed.",
                    ex.Message,
                    null));
        }
    }

    private static (int? Bus, int? Device, int? Function) ParseLocation(string? location, string instanceId)
    {
        // LocationInformation often like: PCI bus 0, device 31, function 2
        if (!string.IsNullOrWhiteSpace(location))
        {
            var bus = MatchInt(location, @"bus\s+(\d+)");
            var device = MatchInt(location, @"device\s+(\d+)");
            var function = MatchInt(location, @"function\s+(\d+)");
            if (bus is not null || device is not null || function is not null)
            {
                return (bus, device, function);
            }
        }

        // Instance ID sometimes: PCI\VEN_...&DEV_...\3&xxx&0&58 -> not reliable for BDF
        return (null, null, null);
    }

    private static int? MatchInt(string input, string pattern)
    {
        var m = System.Text.RegularExpressions.Regex.Match(input, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success && int.TryParse(m.Groups[1].Value, out var v) ? v : null;
    }

    private static string? TryGetParent(string instanceId)
    {
        try
        {
            if (NativeMethods.CM_Locate_DevNode(out var devInst, instanceId, 0) != 0)
            {
                return null;
            }

            if (NativeMethods.CM_Get_Parent(out var parent, devInst, 0) != 0)
            {
                return null;
            }

            var buffer = new char[NativeMethods.MAX_DEVICE_ID_LEN];
            if (NativeMethods.CM_Get_Device_ID(parent, buffer, buffer.Length, 0) != 0)
            {
                return null;
            }

            return new string(buffer).TrimEnd('\0');
        }
        catch
        {
            return null;
        }
    }

    private static bool TryGetDeviceInstanceId(IntPtr info, NativeMethods.SP_DEVINFO_DATA data, out string id)
    {
        id = "";
        var buffer = new char[NativeMethods.MAX_DEVICE_ID_LEN];
        if (!NativeMethods.SetupDiGetDeviceInstanceId(info, ref data, buffer, buffer.Length, out _))
        {
            return false;
        }

        id = new string(buffer).TrimEnd('\0');
        return !string.IsNullOrWhiteSpace(id);
    }

    private static IReadOnlyList<string> ReadMultiSzProperty(string instanceId, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + instanceId);
            if (key?.GetValue(valueName) is string[] arr)
            {
                return arr.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
            }

            if (key?.GetValue(valueName) is string s && !string.IsNullOrWhiteSpace(s))
            {
                return [s];
            }
        }
        catch
        {
            // ignored
        }

        return Array.Empty<string>();
    }

    private static string? ReadRegistryProperty(string instanceId, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + instanceId);
            var value = key?.GetValue(valueName)?.ToString();
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            // DeviceDesc often "Device Name;file.inf" style from REG_SZ with ; — keep as-is if simple
            return value;
        }
        catch
        {
            return null;
        }
    }
}

internal static class NativeMethods
{
    public static readonly IntPtr InvalidHandle = new(-1);

    public static readonly Guid GUID_DEVCLASS_PCI = new("4d36e97d-e325-11ce-bfc1-08002be10318");

    public const int DIGCF_PRESENT = 0x00000002;
    public const int CM_GETIDLIST_FILTER_NONE = 0x00000000;
    public const int MAX_DEVICE_ID_LEN = 200;

    public enum FirmwareType
    {
        FirmwareTypeUnknown = 0,
        FirmwareTypeBios = 1,
        FirmwareTypeUefi = 2,
        FirmwareTypeMax = 3
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFirmwareType(out FirmwareType firmwareType);

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, int flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetupDiGetDeviceInstanceId(
        IntPtr deviceInfoSet,
        ref SP_DEVINFO_DATA deviceInfoData,
        char[] deviceInstanceId,
        int deviceInstanceIdSize,
        out int requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Get_Device_ID_List_Size(ref int length, string? filter, int flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Get_Device_ID_List(string? filter, [Out] char[] buffer, int bufferLength, int flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Locate_DevNode(out int devInst, string deviceId, int flags);

    [DllImport("cfgmgr32.dll")]
    public static extern int CM_Get_Parent(out int parentDevInst, int devInst, int flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Get_Device_ID(int devInst, [Out] char[] buffer, int bufferLen, int flags);
}

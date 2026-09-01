using System.Globalization;
using System.Management;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Core.Scanning;
using IronTrace.Hardware.Classification;
using IronTrace.Hardware.Parsing;
using IronTrace.Hardware.Signing;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Hardware.Collectors;

public sealed class UsbInventoryCollector : IUsbInventoryCollector
{
    private readonly ILogger<UsbInventoryCollector> _logger;
    private readonly IDriverSignatureAnalyzer _signatureAnalyzer;

    public UsbInventoryCollector(
        ILogger<UsbInventoryCollector> logger,
        IDriverSignatureAnalyzer signatureAnalyzer)
    {
        _logger = logger;
        _signatureAnalyzer = signatureAnalyzer;
    }

    public Task<IReadOnlyList<UsbDevice>> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var devices = new List<UsbDevice>();

        try
        {
            foreach (var instanceId in EnumerateUsbInstanceIds())
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
                    _logger.LogDebug(ex, "Failed reading USB device {InstanceId}", instanceId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "USB enumeration failed");
            throw;
        }

        return Task.FromResult<IReadOnlyList<UsbDevice>>(devices);
    }

    private static IEnumerable<string> EnumerateUsbInstanceIds()
    {
        var list = new List<string>();
        var size = 0;
        var cr = NativeMethods.CM_Get_Device_ID_List_Size(ref size, null, NativeMethods.CM_GETIDLIST_FILTER_NONE);
        if (cr != 0 || size <= 0)
        {
            return list;
        }

        var buffer = new char[size];
        cr = NativeMethods.CM_Get_Device_ID_List(null, buffer, size, NativeMethods.CM_GETIDLIST_FILTER_NONE);
        if (cr != 0)
        {
            return list;
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
                if (id.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) &&
                    id.Contains("VID_", StringComparison.OrdinalIgnoreCase))
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

        return list;
    }

    private UsbDevice? ReadDevice(string instanceId)
    {
        var hardwareIds = ReadMultiSzProperty(instanceId, "HardwareID");
        var identity = UsbHardwareIdParser.ParseFirst(hardwareIds.Concat([instanceId]));
        if (identity is null)
        {
            return null;
        }

        var friendly = ReadRegistryProperty(instanceId, "FriendlyName");
        var description = ReadRegistryProperty(instanceId, "DeviceDesc") ?? friendly;
        var manufacturer = ReadRegistryProperty(instanceId, "Mfg");
        var service = ReadRegistryProperty(instanceId, "Service");
        var driver = ReadDriverInfo(instanceId, service);
        var classification = DeviceKindClassifier.Classify(
            instanceId, service, description, friendly, manufacturer, hardwareIds);

        return new UsbDevice(
            instanceId,
            identity,
            friendly,
            description,
            manufacturer,
            service,
            driver,
            Resolved: null,
            hardwareIds,
            classification.Kind,
            classification.Reason);
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
            return new DriverInfo(
                service,
                name,
                version,
                provider,
                date,
                signature.Status.ToString(),
                InfPath: infFull ?? infPath,
                ImagePath: imagePath,
                Signature: signature);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "USB driver info failed for {InstanceId}", instanceId);
            return null;
        }
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
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
        catch
        {
            return null;
        }
    }
}

public sealed class DriverInventoryCollector : IDriverInventoryCollector
{
    private readonly ILogger<DriverInventoryCollector> _logger;
    private readonly IDriverSignatureAnalyzer _signatureAnalyzer;
    private readonly ILolDriversMatchService _lolDrivers;

    public DriverInventoryCollector(
        ILogger<DriverInventoryCollector> logger,
        IDriverSignatureAnalyzer signatureAnalyzer,
        ILolDriversMatchService lolDrivers)
    {
        _logger = logger;
        _signatureAnalyzer = signatureAnalyzer;
        _lolDrivers = lolDrivers;
    }

    public async Task<(IReadOnlyList<InventoriedDriver> Drivers, IReadOnlyList<VulnerableDriverMatch> Matches)> CollectAsync(
        IReadOnlyList<PciDevice> pciDevices,
        CancellationToken cancellationToken)
    {
        var byPath = new Dictionary<string, InventoriedDriver>(StringComparer.OrdinalIgnoreCase);
        var matches = new List<VulnerableDriverMatch>();

        foreach (var pci in pciDevices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = pci.Driver?.ImagePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            await AddDriverAsync(byPath, matches, pci.Driver?.Service, pci.Driver?.DriverName, path, "PciInventory", cancellationToken)
                .ConfigureAwait(false);
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (key is not null)
            {
                foreach (var name in key.GetSubKeyNames())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var svc = key.OpenSubKey(name);
                    if (svc is null)
                    {
                        continue;
                    }

                    // Type 1 = kernel driver, 2 = file system driver
                    if (svc.GetValue("Type") is not int type || (type != 1 && type != 2))
                    {
                        continue;
                    }

                    var image = DriverPathResolver.ResolveServiceImagePath(name);
                    if (string.IsNullOrWhiteSpace(image))
                    {
                        continue;
                    }

                    var display = svc.GetValue("DisplayName") as string ?? name;
                    await AddDriverAsync(byPath, matches, name, display, image, "Services", cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Kernel driver service enumeration failed");
        }

        return (byPath.Values.ToList(), matches);
    }

    private async Task AddDriverAsync(
        Dictionary<string, InventoriedDriver> byPath,
        List<VulnerableDriverMatch> matches,
        string? service,
        string? display,
        string path,
        string source,
        CancellationToken cancellationToken)
    {
        if (byPath.ContainsKey(path))
        {
            return;
        }

        string? sha = null;
        try
        {
            if (File.Exists(path))
            {
                await using var stream = File.OpenRead(path);
                sha = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
                    .ToLowerInvariant();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not hash driver {Path}", path);
        }

        var signature = _signatureAnalyzer.Analyze(path, null);
        var fileName = Path.GetFileName(path);
        byPath[path] = new InventoriedDriver(service, display, path, sha, fileName, signature, source);

        VulnerableDriverMatch? match = null;
        if (!string.IsNullOrWhiteSpace(sha))
        {
            match = await _lolDrivers.MatchBySha256Async(sha, cancellationToken).ConfigureAwait(false);
        }

        match ??= await _lolDrivers.MatchByFileNameAsync(fileName, cancellationToken).ConfigureAwait(false);
        if (match is not null)
        {
            matches.Add(match with { RelatedPath = path, DriverFileName = fileName, DriverSha256 = sha ?? match.DriverSha256 });
        }
    }
}

public sealed class LolDriversMatchService : ILolDriversMatchService
{
    private readonly Contracts.Reference.ILolDriversProvider _provider;

    public LolDriversMatchService(Contracts.Reference.ILolDriversProvider provider)
        => _provider = provider;

    public Task<VulnerableDriverMatch?> MatchBySha256Async(string sha256Hex, CancellationToken cancellationToken)
        => _provider.MatchBySha256Async(sha256Hex, cancellationToken);

    public Task<VulnerableDriverMatch?> MatchByFileNameAsync(string fileName, CancellationToken cancellationToken)
        => _provider.MatchByFileNameAsync(fileName, cancellationToken);
}

public sealed class IdentityConsistencyCollector : IIdentityConsistencyCollector
{
    private readonly ILogger<IdentityConsistencyCollector> _logger;

    private static readonly string[] PlaceholderSerials =
    [
        "none", "to be filled by o.e.m.", "default string", "system serial number",
        "0123456789", "o.e.m.", "oem", "n/a", "na", "unknown"
    ];

    public IdentityConsistencyCollector(ILogger<IdentityConsistencyCollector> logger)
        => _logger = logger;

    public Task<IdentityConsistencyReport> CollectAsync(MotherboardInfo? board, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var checks = new List<IdentityCheckResult>();
        string? uuid = null;
        var uuidPlaceholder = false;
        var serialPlaceholder = false;

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    uuid = obj["UUID"]?.ToString();
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Win32_ComputerSystemProduct UUID query failed");
        }

        var normalized = NormalizeUuid(uuid);
        uuidPlaceholder = IsPlaceholderUuid(normalized);
        if (uuidPlaceholder)
        {
            checks.Add(new IdentityCheckResult(
                "SYSTEM_UUID_PLACEHOLDER",
                IsAnomaly: true,
                FindingConfidence.Low,
                "System UUID looks like a placeholder",
                "The SMBIOS/system product UUID is empty, all zeros, or a known placeholder. This can be OEM default or spoofing — low confidence only.",
                normalized ?? "(null)"));
        }

        var rawSerial = board?.SerialRaw;
        // Serial may be hashed-only in board info; placeholder detection uses hash absence + product heuristics via notes.
        // Prefer detecting via manufacturer/product empty patterns when raw is unavailable.
        if (board?.SerialHandling == SerialHandling.NotCollected)
        {
            serialPlaceholder = true;
            checks.Add(new IdentityCheckResult(
                "BOARD_SERIAL_PLACEHOLDER",
                IsAnomaly: true,
                FindingConfidence.Low,
                "Board serial not collectable / placeholder",
                "Motherboard serial was absent or matched known OEM placeholder patterns. Informational only.",
                board.SerialHandling.ToString()));
        }
        else if (!string.IsNullOrWhiteSpace(rawSerial) && IsPlaceholderText(rawSerial))
        {
            serialPlaceholder = true;
            checks.Add(new IdentityCheckResult(
                "BOARD_SERIAL_PLACEHOLDER",
                IsAnomaly: true,
                FindingConfidence.Low,
                "Board serial looks like a placeholder",
                "Motherboard serial matches common OEM placeholder strings. Informational only.",
                rawSerial));
        }

        return Task.FromResult(new IdentityConsistencyReport(
            normalized,
            uuidPlaceholder,
            serialPlaceholder,
            checks));
    }

    private static string? NormalizeUuid(string? uuid)
    {
        if (string.IsNullOrWhiteSpace(uuid))
        {
            return null;
        }

        return uuid.Trim().ToLowerInvariant();
    }

    private static bool IsPlaceholderUuid(string? uuid)
    {
        if (string.IsNullOrWhiteSpace(uuid))
        {
            return true;
        }

        var compact = Regex.Replace(uuid, "[^0-9a-f]", "", RegexOptions.IgnoreCase);
        if (compact.Length == 0)
        {
            return true;
        }

        if (compact.All(c => c == '0') || compact.All(c => c == 'f'))
        {
            return true;
        }

        // Common OEM placeholders
        return uuid.Contains("03000200-0400-0500-0006-000700080009", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPlaceholderText(string value)
        => PlaceholderSerials.Any(p => value.Trim().Equals(p, StringComparison.OrdinalIgnoreCase));
}

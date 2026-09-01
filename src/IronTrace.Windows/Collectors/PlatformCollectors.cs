using System.Management;
using System.Runtime.InteropServices;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Platform;
using IronTrace.Contracts.Reference;
using IronTrace.Core.Scanning;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Windows.Collectors;

public sealed class OperatingSystemCollector : IOperatingSystemCollector
{
    private readonly ILogger<OperatingSystemCollector> _logger;

    public OperatingSystemCollector(ILogger<OperatingSystemCollector> logger) => _logger = logger;

    public Task<OperatingSystemInfo> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var productName = key?.GetValue("ProductName") as string ?? "Windows";
            var buildNumber = key?.GetValue("CurrentBuildNumber") as string
                              ?? key?.GetValue("CurrentBuild") as string
                              ?? "Unknown";
            var displayVersion = key?.GetValue("DisplayVersion") as string
                                 ?? key?.GetValue("ReleaseId") as string
                                 ?? "Unknown";
            var editionId = key?.GetValue("EditionID") as string;
            var installationType = key?.GetValue("InstallationType") as string;
            var ubr = key?.GetValue("UBR");
            var version = key?.GetValue("CurrentMajorVersionNumber") is int major &&
                          key.GetValue("CurrentMinorVersionNumber") is int minor
                ? $"{major}.{minor}.{buildNumber}" + (ubr is int u ? $".{u}" : "")
                : (key?.GetValue("CurrentVersion") as string ?? "Unknown");

            var arch = RuntimeInformation.OSArchitecture.ToString();
            return Task.FromResult(new OperatingSystemInfo(
                productName,
                version,
                buildNumber,
                displayVersion,
                arch,
                installationType,
                editionId));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read OS version information");
            return Task.FromResult(new OperatingSystemInfo(
                "Windows",
                "Unknown",
                "Unknown",
                "Unknown",
                RuntimeInformation.OSArchitecture.ToString(),
                null,
                null));
        }
    }
}

public sealed class PlatformSecurityCollector : IPlatformSecurityCollector
{
    private readonly ILogger<PlatformSecurityCollector> _logger;
    private readonly ElevatedSecurityOptions _elevatedOptions;

    public PlatformSecurityCollector(
        ILogger<PlatformSecurityCollector> logger,
        ElevatedSecurityOptions? elevatedOptions = null)
    {
        _logger = logger;
        _elevatedOptions = elevatedOptions ?? new ElevatedSecurityOptions();
    }

    public Task<PlatformSecurityState> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<string>();
        var elevated = IsElevated();
        var deep = elevated &&
                   string.Equals(_elevatedOptions.Mode, "WhenElevated", StringComparison.OrdinalIgnoreCase);

        if (!elevated)
        {
            notes.Add("Not running elevated. Restart IronTrace as Administrator for deeper security log access.");
        }
        else if (deep)
        {
            notes.Add("Elevated security detail collection is active.");
        }

        var secureBoot = ReadSecureBoot(notes);
        var tpm = ReadTpm(notes);
        var vbs = ReadDeviceGuardFeature("VirtualizationBasedSecurityStatus", "VBS", notes, deep);
        var hvci = ReadMemoryIntegrity(notes, deep);
        var dma = ReadKernelDmaProtection(notes, deep);
        var virt = ReadVirtualization(notes);

        if (deep)
        {
            AppendDeviceGuardElevatedNotes(notes);
        }

        return Task.FromResult(new PlatformSecurityState(
            secureBoot,
            tpm,
            vbs,
            hvci,
            dma,
            virt,
            elevated,
            notes));
    }

    private SecurityFeatureStatus ReadSecureBoot(List<string> notes)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            var value = key?.GetValue("UEFISecureBootEnabled");
            if (value is int i)
            {
                return new SecurityFeatureStatus(
                    "Secure Boot",
                    i == 1 ? SecurityFeatureState.Enabled : SecurityFeatureState.Disabled,
                    i == 1 ? "UEFI Secure Boot is enabled." : "UEFI Secure Boot is disabled.");
            }

            // Firmware type without Secure Boot state
            var firmware = GetFirmwareType();
            if (firmware == FirmwareType.Bios)
            {
                return new SecurityFeatureStatus(
                    "Secure Boot",
                    SecurityFeatureState.Unsupported,
                    "Legacy BIOS firmware does not support Secure Boot.");
            }

            notes.Add("Secure Boot state could not be read; result is Unknown.");
            return new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Unknown, "State unavailable.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Secure Boot query failed");
            notes.Add("Secure Boot query failed.");
            return new SecurityFeatureStatus("Secure Boot", SecurityFeatureState.Unknown, ex.Message);
        }
    }

    private SecurityFeatureStatus ReadTpm(List<string> notes)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    var isPresent = ToBool(obj["IsPresent"]) ?? true;
                    var isEnabled = ToBool(obj["IsEnabled_InitialValue"]);
                    var isActivated = ToBool(obj["IsActivated_InitialValue"]);
                    var spec = obj["SpecVersion"]?.ToString();
                    if (!isPresent)
                    {
                        return new SecurityFeatureStatus("TPM", SecurityFeatureState.Unsupported, "TPM not present.");
                    }

                    var enabled = isEnabled == true && isActivated != false;
                    return new SecurityFeatureStatus(
                        "TPM",
                        enabled ? SecurityFeatureState.Enabled : SecurityFeatureState.SupportedButDisabled,
                        string.IsNullOrWhiteSpace(spec) ? "TPM present." : $"TPM present ({spec}).");
                }
            }

            // Fallback: presence via TBS-less registry/WMI absence
            notes.Add("TPM WMI class returned no instances.");
            return new SecurityFeatureStatus("TPM", SecurityFeatureState.Unknown, "TPM state unavailable.");
        }
        catch (ManagementException mex) when (mex.ErrorCode == ManagementStatus.InvalidNamespace || mex.ErrorCode == ManagementStatus.NotFound)
        {
            notes.Add("TPM WMI namespace unavailable.");
            return new SecurityFeatureStatus("TPM", SecurityFeatureState.Unknown, "TPM WMI namespace unavailable.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "TPM query failed");
            notes.Add("TPM query failed.");
            return new SecurityFeatureStatus("TPM", SecurityFeatureState.Unknown, "TPM query failed.");
        }
    }

    private SecurityFeatureStatus ReadDeviceGuardFeature(string property, string label, List<string> notes, bool deep)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    var status = Convert.ToInt32(obj[property] ?? 0);
                    var state = status switch
                    {
                        0 => SecurityFeatureState.Disabled,
                        1 => SecurityFeatureState.Enabled,
                        2 => SecurityFeatureState.Unsupported,
                        _ => SecurityFeatureState.Unknown
                    };
                    var detail = $"{label} status code: {status}.";
                    if (deep)
                    {
                        var available = obj["AvailableSecurityProperties"]?.ToString();
                        var required = obj["RequiredSecurityProperties"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(available))
                        {
                            detail += $" AvailableSecurityProperties={available}.";
                        }

                        if (!string.IsNullOrWhiteSpace(required))
                        {
                            detail += $" RequiredSecurityProperties={required}.";
                        }
                    }

                    return new SecurityFeatureStatus(label, state, detail);
                }
            }

            notes.Add($"{label} WMI returned no instances.");
            return new SecurityFeatureStatus(label, SecurityFeatureState.Unknown, "Unavailable.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "{Label} query failed", label);
            notes.Add($"{label} query failed.");
            return new SecurityFeatureStatus(label, SecurityFeatureState.Unknown, "Query failed.");
        }
    }

    private SecurityFeatureStatus ReadMemoryIntegrity(List<string> notes, bool deep)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    var status = Convert.ToInt32(obj["CodeIntegrityPolicyEnforcementStatus"] ?? -1);
                    var state = status switch
                    {
                        0 => SecurityFeatureState.Disabled,
                        1 => SecurityFeatureState.SupportedButDisabled,
                        2 => SecurityFeatureState.Enabled,
                        _ => SecurityFeatureState.Unknown
                    };
                    var detail = $"Code integrity enforcement status: {status}.";
                    if (deep)
                    {
                        var usermode = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(usermode))
                        {
                            detail += $" Usermode CI enforcement: {usermode}.";
                        }
                    }

                    return new SecurityFeatureStatus("Memory Integrity (HVCI)", state, detail);
                }
            }

            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            var enabled = key?.GetValue("Enabled");
            if (enabled is int i)
            {
                var detail = "Read from DeviceGuard HVCI registry scenario.";
                if (deep)
                {
                    var locked = key?.GetValue("Locked");
                    if (locked is not null)
                    {
                        detail += $" Locked={locked}.";
                    }
                }

                return new SecurityFeatureStatus(
                    "Memory Integrity (HVCI)",
                    i == 1 ? SecurityFeatureState.Enabled : SecurityFeatureState.Disabled,
                    detail);
            }

            notes.Add("Memory Integrity state unavailable.");
            return new SecurityFeatureStatus("Memory Integrity (HVCI)", SecurityFeatureState.Unknown, "Unavailable.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Memory Integrity query failed");
            notes.Add("Memory Integrity query failed.");
            return new SecurityFeatureStatus("Memory Integrity (HVCI)", SecurityFeatureState.Unknown, "Query failed.");
        }
    }

    private SecurityFeatureStatus ReadKernelDmaProtection(List<string> notes, bool deep)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DmaSecurity");
            if (key is null)
            {
                return new SecurityFeatureStatus(
                    "Kernel DMA Protection",
                    SecurityFeatureState.Unsupported,
                    "DmaSecurity policy key not present. This is informational — Unsupported does not mean suspicious.");
            }

            var names = key.GetValueNames();
            var anything = names.Length > 0 || key.SubKeyCount > 0;
            if (!anything)
            {
                return new SecurityFeatureStatus(
                    "Kernel DMA Protection",
                    SecurityFeatureState.Unknown,
                    "DmaSecurity key present but no readable values.");
            }

            if (deep)
            {
                var bits = new List<string>();
                foreach (var name in names.Take(8))
                {
                    bits.Add($"{name}={key.GetValue(name)}");
                }

                notes.Add("DmaSecurity values (elevated): " + string.Join("; ", bits));
                // Still conservative: values present ≠ confirmed ON without MSINFO-equivalent API.
                return new SecurityFeatureStatus(
                    "Kernel DMA Protection",
                    SecurityFeatureState.Unknown,
                    "Elevated DmaSecurity values enumerated; treat as evidence, not a cheat verdict.");
            }

            notes.Add("Kernel DMA Protection detail is limited in user-mode; state may be Unknown.");
            return new SecurityFeatureStatus(
                "Kernel DMA Protection",
                SecurityFeatureState.Unknown,
                "Policy surfaces detected; exact runtime state not confirmed without additional APIs.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Kernel DMA Protection query failed");
            notes.Add("Kernel DMA Protection query failed.");
            return new SecurityFeatureStatus("Kernel DMA Protection", SecurityFeatureState.Unknown, "Query failed.");
        }
    }

    private void AppendDeviceGuardElevatedNotes(List<string> notes)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    var securityServicesRunning = obj["SecurityServicesRunning"]?.ToString();
                    var securityServicesConfigured = obj["SecurityServicesConfigured"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(securityServicesRunning))
                    {
                        notes.Add($"DeviceGuard SecurityServicesRunning={securityServicesRunning}");
                    }

                    if (!string.IsNullOrWhiteSpace(securityServicesConfigured))
                    {
                        notes.Add($"DeviceGuard SecurityServicesConfigured={securityServicesConfigured}");
                    }

                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Elevated DeviceGuard notes failed");
            notes.Add("Elevated DeviceGuard detail partially unavailable.");
        }
    }

    private SecurityFeatureStatus ReadVirtualization(List<string> notes)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT HypervisorPresent FROM Win32_ComputerSystem");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    var present = ToBool(obj["HypervisorPresent"]) == true;
                    return new SecurityFeatureStatus(
                        "Virtualization / Hypervisor",
                        present ? SecurityFeatureState.Enabled : SecurityFeatureState.Disabled,
                        present ? "Hypervisor present." : "Hypervisor not present.");
                }
            }

            notes.Add("Virtualization state unavailable.");
            return new SecurityFeatureStatus("Virtualization / Hypervisor", SecurityFeatureState.Unknown, "Unavailable.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Virtualization query failed");
            return new SecurityFeatureStatus("Virtualization / Hypervisor", SecurityFeatureState.Unknown, "Query failed.");
        }
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static bool? ToBool(object? value) => value switch
    {
        bool b => b,
        int i => i != 0,
        string s when bool.TryParse(s, out var b) => b,
        _ => null
    };

    private enum FirmwareType
    {
        Unknown = 0,
        Bios = 1,
        Uefi = 2,
        Max = 3
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFirmwareType")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool NativeGetFirmwareType(out FirmwareType firmwareType);

    private FirmwareType GetFirmwareType()
    {
        try
        {
            return NativeGetFirmwareType(out var type) ? type : FirmwareType.Unknown;
        }
        catch
        {
            return FirmwareType.Unknown;
        }
    }
}

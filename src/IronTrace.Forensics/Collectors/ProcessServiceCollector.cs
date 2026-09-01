using System.Diagnostics;
using System.Runtime.InteropServices;
using IronTrace.Contracts.Forensics;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Forensics.Collectors;

public interface IProcessServiceCollector
{
    Task<ProcessServiceSnapshot> CollectAsync(bool consentGranted, CancellationToken cancellationToken);
}

public sealed class ProcessServiceCollector : IProcessServiceCollector
{
    private readonly ISignatureMatcher _matcher;
    private readonly ICheatSignatureProvider _signatures;
    private readonly ILogger<ProcessServiceCollector> _logger;

    private static readonly HashSet<string> UserWritableRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Documents",
        Path.GetTempPath()
    };

    public ProcessServiceCollector(
        ISignatureMatcher matcher,
        ICheatSignatureProvider signatures,
        ILogger<ProcessServiceCollector> logger)
    {
        _matcher = matcher;
        _signatures = signatures;
        _logger = logger;
    }

    public Task<ProcessServiceSnapshot> CollectAsync(bool consentGranted, CancellationToken cancellationToken)
    {
        if (!consentGranted)
        {
            return Task.FromResult(new ProcessServiceSnapshot(
                ForensicAvailability.Skipped,
                "Process inventory skipped — consent not granted.",
                false,
                [],
                [],
                []));
        }

        var processes = new List<ProcessEntry>();
        var processHits = new List<SignatureMatchHit>();
        var services = new List<ServiceEntry>();

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var name = proc.ProcessName;
                    string? path = null;
                    try { path = proc.MainModule?.FileName; } catch { /* access denied */ }

                    var pathHash = ForensicHashHelper.HashText(path);
                    var hits = _matcher.Match(name, "Process");
                    if (path is not null)
                        hits = hits.Concat(_matcher.Match(path, "Process")).ToList();
                    processHits.AddRange(hits);

                    var modules = EnumerateSuspiciousModules(proc, cancellationToken);
                    processes.Add(new ProcessEntry(
                        name,
                        pathHash.Length > 0 ? pathHash : null,
                        null,
                        proc.Id,
                        null,
                        modules));
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Process enumeration failed for pid {Pid}", proc.Id);
                }
                finally
                {
                    proc.Dispose();
                }
            }

            CollectServices(services, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Process/service collection failed");
            return Task.FromResult(new ProcessServiceSnapshot(
                ForensicAvailability.Partial,
                ex.Message,
                true,
                processes,
                services,
                processHits));
        }

        return Task.FromResult(new ProcessServiceSnapshot(
            ForensicAvailability.Available,
            $"Processes={processes.Count}, Services={services.Count}",
            true,
            processes,
            services,
            processHits));
    }

    private IReadOnlyList<ProcessModuleEntry> EnumerateSuspiciousModules(Process proc, CancellationToken ct)
    {
        var list = new List<ProcessModuleEntry>();
        try
        {
            foreach (ProcessModule module in proc.Modules)
            {
                ct.ThrowIfCancellationRequested();
                var path = module.FileName;
                if (string.IsNullOrEmpty(path))
                    continue;

                var userWritable = UserWritableRoots.Any(root =>
                    path.StartsWith(root, StringComparison.OrdinalIgnoreCase));
                if (!userWritable)
                    continue;

                var onAllowlist = _matcher.IsOnVendorAllowlist(path);
                list.Add(new ProcessModuleEntry(
                    ForensicHashHelper.HashText(proc.ProcessName),
                    module.ModuleName,
                    ForensicHashHelper.HashText(path),
                    true,
                    onAllowlist));
            }
        }
        catch
        {
            // elevation required for some processes
        }

        return list;
    }

    private void CollectServices(List<ServiceEntry> services, CancellationToken ct)
    {
        var scm = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == IntPtr.Zero)
            return;

        try
        {
            var bytesNeeded = 0u;
            var servicesReturned = 0u;
            uint resumeHandle = 0;
            NativeMethods.EnumServicesStatusEx(scm, NativeMethods.SC_ENUM_PROCESS_INFO,
                NativeMethods.SERVICE_WIN32, NativeMethods.SERVICE_STATE_ALL,
                IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, ref resumeHandle, null);

            if (bytesNeeded == 0)
                return;

            var buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                resumeHandle = 0;
                if (!NativeMethods.EnumServicesStatusEx(scm, NativeMethods.SC_ENUM_PROCESS_INFO,
                        NativeMethods.SERVICE_WIN32, NativeMethods.SERVICE_STATE_ALL,
                        buffer, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle, null))
                    return;

                var structSize = Marshal.SizeOf<NativeMethods.ENUM_SERVICE_STATUS_PROCESS>();
                for (var i = 0; i < servicesReturned; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var ptr = buffer + i * structSize;
                    var entry = Marshal.PtrToStructure<NativeMethods.ENUM_SERVICE_STATUS_PROCESS>(ptr);
                    var name = entry.lpServiceName ?? "";
                    var display = entry.lpDisplayName ?? "";
                    var hits = _matcher.Match(name, "Service").Concat(_matcher.Match(display, "Service")).ToList();
                    services.Add(new ServiceEntry(
                        name,
                        display,
                        ForensicHashHelper.HashText(name),
                        hits));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            NativeMethods.CloseServiceHandle(scm);
        }
    }

    private static class NativeMethods
    {
        public const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        public const uint SC_ENUM_PROCESS_INFO = 0;
        public const uint SERVICE_WIN32 = 0x00000030;
        public const uint SERVICE_STATE_ALL = 0x00000003;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwAccess);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ENUM_SERVICE_STATUS_PROCESS
        {
            public string? lpServiceName;
            public string? lpDisplayName;
            public SERVICE_STATUS_PROCESS ServiceStatusProcess;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS_PROCESS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
            public uint dwProcessId;
            public uint dwServiceFlags;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool EnumServicesStatusEx(
            IntPtr hSCManager,
            uint InfoLevel,
            uint dwServiceType,
            uint dwServiceState,
            IntPtr lpServices,
            uint cbBufSize,
            out uint pcbBytesNeeded,
            out uint lpServicesReturned,
            ref uint lpResumeHandle,
            string? pszGroupName);
    }
}

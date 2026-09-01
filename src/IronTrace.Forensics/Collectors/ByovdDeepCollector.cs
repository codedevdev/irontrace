using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Hardware;
using Microsoft.Extensions.Logging;

namespace IronTrace.Forensics.Collectors;

public interface IByovdDeepCollector
{
    Task<ByovdDeepSnapshot> CollectAsync(
        IReadOnlyList<InventoriedDriver> drivers,
        CancellationToken cancellationToken);
}

public sealed class ByovdDeepCollector : IByovdDeepCollector
{
    private readonly ILogger<ByovdDeepCollector> _logger;
    private readonly HashSet<string> _msBlocklist;

    public ByovdDeepCollector(ILogger<ByovdDeepCollector> logger)
    {
        _logger = logger;
        _msBlocklist = LoadMsBlocklist();
    }

    public Task<ByovdDeepSnapshot> CollectAsync(
        IReadOnlyList<InventoriedDriver> drivers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var (testSigning, noIntegrity) = ReadBcdFlags();
        var msMatches = new List<string>();
        var fingerprints = new List<DriverCapabilityFingerprint>();
        var stalePackages = new List<string>();

        foreach (var driver in drivers)
        {
            var fileName = driver.FileName ?? Path.GetFileName(driver.ImagePath ?? "");
            if (_msBlocklist.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                msMatches.Add(fileName);

            if (!string.IsNullOrEmpty(driver.ImagePath) && File.Exists(driver.ImagePath))
            {
                TryFingerprint(driver, fingerprints);
            }
        }

        TryDriverStoreStale(stalePackages);
        var kernelInstalls = CollectKernelServiceInstalls(cancellationToken);

        return Task.FromResult(new ByovdDeepSnapshot(
            ForensicAvailability.Available,
            $"Drivers={drivers.Count}, MS matches={msMatches.Count}",
            testSigning,
            noIntegrity,
            msMatches,
            stalePackages,
            kernelInstalls,
            fingerprints));
    }

    private static (bool TestSigning, bool NoIntegrityChecks) ReadBcdFlags()
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum {current}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (proc is null)
                return (false, false);

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            var outputLower = output.ToLowerInvariant();
            return (
                outputLower.Contains("testsigning") && outputLower.Contains("yes"),
                outputLower.Contains("nointegritychecks") && outputLower.Contains("yes"));
        }
        catch
        {
            return (false, false);
        }
    }

    private void TryFingerprint(InventoriedDriver driver, List<DriverCapabilityFingerprint> list)
    {
        try
        {
            var path = driver.ImagePath!;
            var info = new FileInfo(path);
            if (info.Length > 200 * 1024)
                return;

            var imports = PeImportScanner.GetImportedFunctions(path);
            var hasCopy = imports.Any(i => i.Contains("MmCopyVirtualMemory", StringComparison.OrdinalIgnoreCase));
            var hasPhys = imports.Any(i =>
                i.Contains("MmMapIoSpaceEx", StringComparison.OrdinalIgnoreCase) ||
                i.Contains("MmGetPhysicalMemoryRanges", StringComparison.OrdinalIgnoreCase));

            if (!hasCopy || !hasPhys)
                return;

            list.Add(new DriverCapabilityFingerprint(
                driver.FileName ?? Path.GetFileName(path),
                driver.Sha256,
                info.Length,
                imports.Where(i => i.Contains("Mm", StringComparison.OrdinalIgnoreCase)).Take(8).ToList(),
                "Small driver with cross-process and physical memory imports (capability fingerprint)."));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "PE import scan failed for {Path}", driver.ImagePath);
        }
    }

    private static void TryDriverStoreStale(List<string> stale)
    {
        var store = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "DriverStore", "FileRepository");
        if (!Directory.Exists(store))
            return;

        foreach (var dir in Directory.EnumerateDirectories(store))
        {
            var inf = Directory.EnumerateFiles(dir, "*.inf").FirstOrDefault();
            if (inf is null)
                stale.Add(Path.GetFileName(dir));
        }
    }

    private List<KernelServiceInstallEvent> CollectKernelServiceInstalls(CancellationToken ct)
    {
        var events = new List<KernelServiceInstallEvent>();
        try
        {
            var query = new EventLogQuery("System", PathType.LogName,
                "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]")
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
            {
                ct.ThrowIfCancellationRequested();
                if (events.Count >= 50)
                    break;

                var name = record.Properties.Count > 0 ? record.Properties[0]?.ToString() ?? "" : "";
                var imagePath = record.Properties.Count > 1 ? record.Properties[1]?.ToString() : null;
                events.Add(new KernelServiceInstallEvent(
                    record.TimeCreated ?? DateTimeOffset.UtcNow,
                    name,
                    ForensicHashHelper.TruncatePath(imagePath)));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Event ID 7045 collection unavailable");
        }

        return events;
    }

    private HashSet<string> LoadMsBlocklist()
    {
        var path = FindBlocklistPath();
        if (!File.Exists(path))
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (doc.RootElement.TryGetProperty("entries", out var entries))
            {
                foreach (var e in entries.EnumerateArray())
                {
                    if (e.TryGetProperty("fileName", out var fn))
                        set.Add(fn.GetString() ?? "");
                }
            }

            return set;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load MS blocklist from {Path}", path);
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static string FindBlocklistPath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "reference", "ms-vulnerable-driver-blocklist.json"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "data", "reference", "ms-vulnerable-driver-blocklist.json"))
        };
        return candidates.FirstOrDefault(File.Exists) ?? candidates[^1];
    }
}

internal static class PeImportScanner
{
    public static IReadOnlyList<string> GetImportedFunctions(string path)
    {
        var list = new List<string>();
        try
        {
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);
            if (br.ReadUInt16() != 0x5A4D)
                return list;

            fs.Seek(0x3C, SeekOrigin.Begin);
            var peOffset = br.ReadInt32();
            fs.Seek(peOffset + 4, SeekOrigin.Begin);
            var machine = br.ReadUInt16();
            if (machine != 0x8664 && machine != 0x014C)
                return list;

            fs.Seek(peOffset + 24, SeekOrigin.Begin);
            var optionalHeaderSize = br.ReadUInt16();
            fs.Seek(peOffset + 24 + optionalHeaderSize, SeekOrigin.Begin);

            while (fs.Position < fs.Length - 8)
            {
                var nameRva = br.ReadUInt32();
                if (nameRva == 0)
                    break;
                br.ReadUInt32();
                br.ReadUInt32();
                br.ReadUInt32();
                var nameOffset = RvaToOffset(fs, peOffset, nameRva);
                if (nameOffset <= 0)
                    continue;

                var pos = fs.Position;
                fs.Seek(nameOffset, SeekOrigin.Begin);
                var dllName = ReadAscii(br);
                list.Add(dllName);
                fs.Seek(pos, SeekOrigin.Begin);
            }
        }
        catch
        {
            // best effort
        }

        return list;
    }

    private static int RvaToOffset(FileStream fs, int peOffset, uint rva) => (int)rva;

    private static string ReadAscii(BinaryReader br)
    {
        var bytes = new List<byte>();
        while (br.BaseStream.Position < br.BaseStream.Length)
        {
            var b = br.ReadByte();
            if (b == 0)
                break;
            bytes.Add(b);
        }

        return System.Text.Encoding.ASCII.GetString(bytes.ToArray());
    }
}

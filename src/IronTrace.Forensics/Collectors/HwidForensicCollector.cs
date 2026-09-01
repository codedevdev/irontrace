using System.Management;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Platform;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Forensics.Collectors;

public interface IHwidForensicCollector
{
    Task<HwidForensicSnapshot> CollectAsync(
        MotherboardInfo? board,
        CancellationToken cancellationToken);
}

public sealed class HwidForensicCollector : IHwidForensicCollector
{
    private readonly ISignatureMatcher _matcher;
    private readonly ILogger<HwidForensicCollector> _logger;

    private static readonly string[] DmaArtifactPatterns =
        ["pcileech", "leechcore", "_top.bin", "ft601", "ft2232"];

    public HwidForensicCollector(ISignatureMatcher matcher, ILogger<HwidForensicCollector> logger)
    {
        _matcher = matcher;
        _logger = logger;
    }

    public Task<HwidForensicSnapshot> CollectAsync(
        MotherboardInfo? board,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fields = CollectCrossSourceFields(board);
        var spooferHits = CollectSpooferRegistryHits();
        var dmaArtifacts = ScanDmaDevArtifacts(cancellationToken);

        return Task.FromResult(new HwidForensicSnapshot(
            ForensicAvailability.Available,
            $"CrossSource={fields.Count}, DmaArtifacts={dmaArtifacts.Count}",
            fields,
            spooferHits,
            dmaArtifacts));
    }

    private IReadOnlyList<HwidCrossSourceField> CollectCrossSourceFields(MotherboardInfo? board)
    {
        var fields = new List<HwidCrossSourceField>();
        try
        {
            var machineGuid = ReadMachineGuid();
            var wmiUuid = QueryWmi("Win32_ComputerSystemProduct", "UUID");
            var boardSerial = board?.SerialRaw ?? QueryWmi("Win32_BaseBoard", "SerialNumber");
            var diskSerial = QueryWmi("Win32_DiskDrive", "SerialNumber");

            if (!string.IsNullOrWhiteSpace(wmiUuid) && !string.IsNullOrWhiteSpace(machineGuid))
            {
                fields.Add(MakeField("SystemUuid", "WMI", "Registry", wmiUuid, machineGuid));
            }

            if (!string.IsNullOrWhiteSpace(boardSerial) && !string.IsNullOrWhiteSpace(diskSerial))
            {
                fields.Add(MakeField("BoardVsDiskSerial", "SMBIOS", "DiskWMI", boardSerial, diskSerial));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "HWID cross-source collection partial failure");
        }

        return fields;
    }

    private static HwidCrossSourceField MakeField(
        string name, string srcA, string srcB, string valA, string valB)
    {
        var hashA = ForensicHashHelper.HashText(valA.Trim());
        var hashB = ForensicHashHelper.HashText(valB.Trim());
        var consistent = hashA.Equals(hashB, StringComparison.OrdinalIgnoreCase)
                         || IsPlaceholder(valA) || IsPlaceholder(valB);
        return new HwidCrossSourceField(name, srcA, srcB, hashA, hashB, consistent);
    }

    private static bool IsPlaceholder(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return true;
        var v = value.Trim().ToLowerInvariant();
        return v is "0" or "00000000-0000-0000-0000-000000000000"
            or "to be filled by o.e.m." or "default string" or "none" or "unknown"
            || v.All(c => c == '0' || c == ' ');
    }

    private static string? ReadMachineGuid()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        return key?.GetValue("MachineGuid") as string;
    }

    private static string? QueryWmi(string wmiClass, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                return obj[property]?.ToString();
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private IReadOnlyList<SignatureMatchHit> CollectSpooferRegistryHits()
    {
        var hits = new List<SignatureMatchHit>();
        var paths = new[]
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            @"SYSTEM\CurrentControlSet\Control\IDConfigDB"
        };

        foreach (var path in paths)
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key is null)
                continue;

            foreach (var name in key.GetValueNames())
            {
                hits.AddRange(_matcher.Match(name, "SpooferRegistry"));
                if (key.GetValue(name)?.ToString() is { } val)
                    hits.AddRange(_matcher.Match(val, "SpooferRegistry"));
            }
        }

        return hits;
    }

    private IReadOnlyList<DmaDevArtifact> ScanDmaDevArtifacts(CancellationToken ct)
    {
        var artifacts = new List<DmaDevArtifact>();
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        };

        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root))
                continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    if (artifacts.Count >= 100)
                        break;

                    var name = Path.GetFileName(file).ToLowerInvariant();
                    if (!DmaArtifactPatterns.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var info = new FileInfo(file);
                    if (info.Length > 50 * 1024 * 1024)
                        continue;

                    artifacts.Add(new DmaDevArtifact(
                        Path.GetRelativePath(root, file),
                        info.Name,
                        info.Length,
                        "DMA development artifact filename pattern."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "DMA artifact scan failed under {Root}", root);
            }
        }

        return artifacts;
    }
}

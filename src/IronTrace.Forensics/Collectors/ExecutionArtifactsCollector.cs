using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Scanning;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Forensics.Collectors;

public interface IExecutionArtifactsCollector
{
    Task<ExecutionArtifactsSnapshot> CollectAsync(CancellationToken cancellationToken);
}

public sealed class ExecutionArtifactsCollector : IExecutionArtifactsCollector
{
    private readonly ISignatureMatcher _matcher;
    private readonly ILogger<ExecutionArtifactsCollector> _logger;

    public ExecutionArtifactsCollector(ISignatureMatcher matcher, ILogger<ExecutionArtifactsCollector> logger)
    {
        _matcher = matcher;
        _logger = logger;
    }

    public Task<ExecutionArtifactsSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hits = new List<SignatureMatchHit>();
        var prefetchCount = 0;
        var bamCount = 0;
        var shimCount = 0;
        var userAssistCount = 0;

        try
        {
            CollectPrefetch(hits, ref prefetchCount, cancellationToken);
            CollectBam(hits, ref bamCount, cancellationToken);
            CollectShimCache(hits, ref shimCount);
            CollectUserAssist(hits, ref userAssistCount);
            CollectMuiCache(hits);
            CollectRecentFiles(hits);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Execution artifacts collection partial failure");
        }

        var availability = hits.Count > 0 || prefetchCount + bamCount > 0
            ? ForensicAvailability.Available
            : ForensicAvailability.Partial;

        return Task.FromResult(new ExecutionArtifactsSnapshot(
            availability,
            $"Prefetch={prefetchCount}, BAM={bamCount}, ShimCache={shimCount}, UserAssist={userAssistCount}",
            hits,
            prefetchCount,
            bamCount,
            shimCount,
            userAssistCount));
    }

    private void CollectPrefetch(List<SignatureMatchHit> hits, ref int count, CancellationToken ct)
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(dir))
            return;

        foreach (var file in Directory.EnumerateFiles(dir, "*.pf"))
        {
            ct.ThrowIfCancellationRequested();
            count++;
            var name = Path.GetFileNameWithoutExtension(file);
            var exeName = name.Contains('-') ? name[..name.LastIndexOf('-')] : name;
            hits.AddRange(_matcher.MatchFileName(exeName, "Prefetch", File.GetLastWriteTimeUtc(file)));
        }
    }

    private void CollectBam(List<SignatureMatchHit> hits, ref int count, CancellationToken ct)
    {
        const string basePath = @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
        using var usersKey = Registry.LocalMachine.OpenSubKey(basePath);
        if (usersKey is null)
            return;

        foreach (var sid in usersKey.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            using var userKey = usersKey.OpenSubKey(sid);
            if (userKey is null)
                continue;

            foreach (var valueName in userKey.GetValueNames())
            {
                if (string.IsNullOrEmpty(valueName) || valueName.StartsWith("Version", StringComparison.OrdinalIgnoreCase))
                    continue;

                count++;
                var lastWrite = userKey.GetValue(valueName) is byte[] bytes && bytes.Length >= 8
                    ? DateTimeOffset.FromFileTime(BitConverter.ToInt64(bytes, 0))
                    : (DateTimeOffset?)null;
                hits.AddRange(_matcher.Match(valueName, "BAM", lastWrite));
            }
        }
    }

    private void CollectShimCache(List<SignatureMatchHit> hits, ref int count)
    {
        const string path = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
        using var key = Registry.LocalMachine.OpenSubKey(path);
        var data = key?.GetValue("AppCompatCache") as byte[];
        if (data is null || data.Length == 0)
            return;

        count = 1;
        // ShimCache is opaque binary; presence recorded for metadata only.
    }

    private void CollectUserAssist(List<SignatureMatchHit> hits, ref int count)
    {
        var users = Registry.Users.GetSubKeyNames()
            .Where(s => s.StartsWith("S-1-5-21", StringComparison.OrdinalIgnoreCase));

        foreach (var sid in users)
        {
            using var key = Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (key is null)
                continue;

            foreach (var guid in key.GetSubKeyNames())
            {
                using var countKey = key.OpenSubKey(guid + "\\Count");
                if (countKey is null)
                    continue;

                foreach (var name in countKey.GetValueNames())
                {
                    var decoded = DecodeRot13(name);
                    count++;
                    hits.AddRange(_matcher.Match(decoded, "UserAssist"));
                }
            }
        }
    }

    private void CollectMuiCache(List<SignatureMatchHit> hits)
    {
        using var key = Registry.CurrentUser.OpenSubKey(
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
        if (key is null)
            return;

        foreach (var name in key.GetValueNames())
        {
            hits.AddRange(_matcher.Match(name, "MUICache"));
            if (key.GetValue(name) is string val)
                hits.AddRange(_matcher.Match(val, "MUICache"));
        }
    }

    private void CollectRecentFiles(List<SignatureMatchHit> hits)
    {
        var recent = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
        if (!Directory.Exists(recent))
            return;

        foreach (var lnk in Directory.EnumerateFiles(recent, "*.lnk"))
        {
            hits.AddRange(_matcher.MatchFileName(Path.GetFileNameWithoutExtension(lnk), "RecentFiles",
                File.GetLastWriteTimeUtc(lnk)));
        }
    }

    private static string DecodeRot13(string input)
    {
        var chars = input.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (c is >= 'a' and <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c is >= 'A' and <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
        }

        return new string(chars);
    }
}

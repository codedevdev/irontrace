namespace IronTrace.Forensics;

public static class MemoryScanToolLocator
{
    public const string ToolFileName = "hollows_hunter64.exe";
    public const string InstallHint =
        "Place hollows_hunter64.exe (+ pe-sieve64.dll) under artifacts/tools/ or publish/tools/. BSD-2-Clause; optional for all other scans.";

    public static bool IsAvailable => ResolvePath() is not null;

    public static string? ResolvePath()
    {
        foreach (var candidate in CandidatePaths())
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    public static IEnumerable<string> CandidatePaths()
    {
        yield return Path.Combine(AppContext.BaseDirectory, "tools", ToolFileName);
        yield return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "artifacts", "tools", ToolFileName));
    }
}

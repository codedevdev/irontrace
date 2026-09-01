using IronTrace.Contracts.Scanning;
using IronTrace.Core.Scanning;
using IronTrace.Reporting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IronTrace.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        if (!string.Equals(args[0], "scan", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Unknown command. Use: irontrace scan --profile <hardware-only|full-forensic|self-audit> --output <path.json>");
            return 2;
        }

        var profile = ParseProfile(GetArg(args, "--profile") ?? "hardware-only");
        var output = GetArg(args, "--output") ?? $"irontrace-scan-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json";
        var html = GetArg(args, "--html");
        var includeMemory = HasFlag(args, "--memory");

        var consent = ScanConsentFlags.ForProfile(profile);
        if (profile == ScanProfile.FullForensic && includeMemory)
            consent = consent with { IncludeMemoryScan = true };

        var options = new ScanOptions(profile, consent);
        using var host = ScanHostBuilder.Build(args);
        var orchestrator = host.Services.GetRequiredService<IScanOrchestrator>();
        var exporter = host.Services.GetRequiredService<IScanReportExporter>();
        var htmlExporter = host.Services.GetRequiredService<ISelfAuditHtmlExporter>();

        var progress = new Progress<ScanProgress>(p =>
            Console.WriteLine($"[{p.Stage}] {p.Message} ({p.Percent:0}%)"));

        Console.WriteLine($"IronTrace CLI scan · profile={profile}");
        var session = await orchestrator.RunAsync(progress, CancellationToken.None, options).ConfigureAwait(false);
        await exporter.ExportJsonAsync(session, output, CancellationToken.None).ConfigureAwait(false);
        Console.WriteLine($"JSON report: {Path.GetFullPath(output)}");

        if (!string.IsNullOrWhiteSpace(html))
        {
            await htmlExporter.ExportHtmlAsync(session, html, CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"HTML report: {Path.GetFullPath(html)}");
        }
        else if (profile is ScanProfile.SelfAudit or ScanProfile.SelfAuditConsoleRig)
        {
            var autoHtml = Path.ChangeExtension(output, ".html");
            await htmlExporter.ExportHtmlAsync(session, autoHtml, CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"HTML report: {Path.GetFullPath(autoHtml)}");
        }

        var verdict = session.RiskAssessment?.Verdict.ToString() ?? "Unverified";
        Console.WriteLine($"Verdict: {verdict}");
        if (session.ForensicEvidence?.VerdictBanner is { } banner)
            Console.WriteLine($"Forensic banner: {banner}");

        return 0;
    }

    private static ScanProfile ParseProfile(string value) => value.ToLowerInvariant().Replace('_', '-') switch
    {
        "hardware-only" or "hardware" => ScanProfile.HardwareOnly,
        "full-forensic" or "full" => ScanProfile.FullForensic,
        "self-audit" => ScanProfile.SelfAudit,
        "self-audit-console-rig" or "console-rig" => ScanProfile.SelfAuditConsoleRig,
        _ => ScanProfile.HardwareOnly
    };

    private static string? GetArg(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return null;
    }

    private static bool HasFlag(string[] args, string name)
        => args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

    private static void PrintHelp()
    {
        Console.WriteLine("""
            irontrace scan --profile <hardware-only|full-forensic|self-audit|console-rig> [--output report.json] [--html report.html] [--memory]

            Profiles:
              hardware-only   Phases 1-5 hardware scan (default)
              full-forensic   Hardware + forensic collectors (+ --memory for PE-sieve)
              self-audit      Player self-audit with local HTML companion
              console-rig     Self-audit for capture-card / console-rig PC
            """);
    }
}

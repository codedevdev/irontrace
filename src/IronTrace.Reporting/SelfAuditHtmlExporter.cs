using System.Net;
using System.Text;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Scanning;

namespace IronTrace.Reporting;

public interface ISelfAuditHtmlExporter
{
    Task ExportHtmlAsync(ScanSession session, string path, CancellationToken cancellationToken);
}

public sealed class SelfAuditHtmlExporter : ISelfAuditHtmlExporter
{
    public async Task ExportHtmlAsync(ScanSession session, string path, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var html = BuildHtml(session);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(path, html, cancellationToken).ConfigureAwait(false);
    }

    public static string BuildHtml(ScanSession session)
    {
        var banner = session.ForensicEvidence?.VerdictBanner ?? ForensicVerdictBanner.Clean;
        var bannerText = ForensicVerdictMapperDisplay(banner);
        var bannerClass = banner switch
        {
            ForensicVerdictBanner.CheatsDetected => "bad",
            ForensicVerdictBanner.InputDevicesDetected => "warn",
            ForensicVerdictBanner.ReviewRecommended => "warn",
            _ => "ok"
        };

        var findings = session.RiskAssessment?.Findings ?? [];
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>");
        sb.Append("<title>IronTrace Self-Audit</title>");
        sb.Append("<style>body{font-family:Segoe UI,sans-serif;background:#0b1016;color:#e8eef4;margin:0;padding:32px}");
        sb.Append(".card{max-width:900px;margin:0 auto;background:#121a22;border-radius:12px;padding:28px;border:1px solid #243040}");
        sb.Append(".banner{font-size:28px;font-weight:600;margin-bottom:8px}.ok{color:#2f9e8a}.warn{color:#d4a017}.bad{color:#e05a5a}");
        sb.Append(".muted{color:#8aa0b4;font-size:14px}table{width:100%;border-collapse:collapse;margin-top:16px}");
        sb.Append("td,th{padding:8px;border-bottom:1px solid #243040;text-align:left;font-size:13px}</style></head><body><div class=\"card\">");
        sb.Append($"<div class=\"banner {bannerClass}\">{WebUtility.HtmlEncode(bannerText)}</div>");
        sb.Append($"<div class=\"muted\">IronTrace {WebUtility.HtmlEncode(session.ApplicationVersion)} · Schema {WebUtility.HtmlEncode(session.ReportSchemaVersion)} · Profile {WebUtility.HtmlEncode(session.ScanProfile.ToString())}</div>");
        sb.Append($"<p>{WebUtility.HtmlEncode(session.RiskAssessment?.Summary ?? "Scan completed.")}</p>");
        sb.Append("<h3>Findings</h3><table><tr><th>Severity</th><th>Code</th><th>Title</th></tr>");
        foreach (var f in findings.Take(100))
        {
            sb.Append("<tr><td>").Append(WebUtility.HtmlEncode(f.Severity.ToString()));
            sb.Append("</td><td>").Append(WebUtility.HtmlEncode(f.Code));
            sb.Append("</td><td>").Append(WebUtility.HtmlEncode(f.Title)).Append("</td></tr>");
        }
        sb.Append("</table><p class=\"muted\">Evidence-based review only — not an automatic ban. Generated locally; nothing uploaded unless you choose to.</p>");
        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    private static string ForensicVerdictMapperDisplay(ForensicVerdictBanner banner) => banner switch
    {
        ForensicVerdictBanner.CheatsDetected => "Cheats Detected",
        ForensicVerdictBanner.InputDevicesDetected => "Input Devices Detected",
        ForensicVerdictBanner.ReviewRecommended => "Review Recommended",
        _ => "Clean"
    };
}

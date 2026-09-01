using System.Security.Claims;
using System.Text.Json;
using IronTrace.Contracts.Api;
using IronTrace.Server.Auth;
using IronTrace.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IronTrace.Server.Pages.Admin.Scans;

[Authorize(Roles = nameof(ApiKeyScope.Admin))]
public class DetailModel : PageModel
{
    private readonly IronTraceDbContext _db;

    public DetailModel(IronTraceDbContext db) => _db = db;

    public ScanSubmissionEntity? Scan { get; private set; }
    public string FindingsPreview { get; private set; } = "";
    public string? ForensicBanner { get; private set; }
    public string ForensicPreview { get; private set; } = "";

    [BindProperty]
    public ScanReviewStatus ReviewStatus { get; set; }

    [BindProperty]
    public string? ReviewNotes { get; set; }

    public async Task<IActionResult> OnGetAsync(Guid id)
    {
        Scan = await _db.Scans.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id);
        if (Scan is null)
        {
            return NotFound();
        }

        ReviewStatus = Scan.ReviewStatus;
        ReviewNotes = Scan.ReviewNotes;
        FindingsPreview = BuildFindingsPreview(Scan.PayloadJson);
        (ForensicBanner, ForensicPreview) = BuildForensicPreview(Scan.PayloadJson);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(Guid id)
    {
        var scan = await _db.Scans.FirstOrDefaultAsync(s => s.Id == id);
        if (scan is null)
        {
            return NotFound();
        }

        scan.ReviewStatus = ReviewStatus;
        scan.ReviewNotes = ReviewNotes;
        var keyClaim = User.FindFirstValue(ApiKeyAuthDefaults.KeyIdClaim);
        if (Guid.TryParse(keyClaim, out var keyId))
        {
            scan.ReviewerKeyId = keyId;
        }

        await _db.SaveChangesAsync();
        return RedirectToPage(new { id });
    }

    private static (string? Banner, string Preview) BuildForensicPreview(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            string? banner = doc.RootElement.TryGetProperty("forensicVerdictBanner", out var b)
                ? b.GetString()
                : null;

            if (!doc.RootElement.TryGetProperty("forensicEvidence", out var fe) ||
                fe.ValueKind == JsonValueKind.Null)
            {
                return (banner, "No forensic evidence section.");
            }

            var profile = fe.TryGetProperty("profile", out var p) ? p.GetString() : null;
            var exec = fe.TryGetProperty("execution", out var ex) && ex.TryGetProperty("hits", out var hits)
                ? hits.GetArrayLength()
                : 0;
            return (banner, $"Profile: {profile ?? "—"} · Execution hits: {exec}");
        }
        catch
        {
            return (null, "Could not parse forensic evidence.");
        }
    }

    private static string BuildFindingsPreview(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("findings", out var findings) ||
                findings.ValueKind != JsonValueKind.Array)
            {
                return "No findings array.";
            }

            var lines = new List<string>();
            foreach (var f in findings.EnumerateArray().Take(20))
            {
                var code = f.TryGetProperty("code", out var c) ? c.GetString() : "?";
                var title = f.TryGetProperty("title", out var t) ? t.GetString() : "";
                var sev = f.TryGetProperty("severity", out var s) ? s.GetString() : "";
                lines.Add($"{sev}: {code} — {title}");
            }

            return lines.Count == 0 ? "No findings." : string.Join("\n", lines);
        }
        catch
        {
            return "Could not parse findings.";
        }
    }
}

using IronTrace.Contracts.Api;
using IronTrace.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IronTrace.Server.Pages.Admin.Scans;

[Authorize(Roles = nameof(ApiKeyScope.Admin))]
public class IndexModel : PageModel
{
    private readonly IronTraceDbContext _db;

    public IndexModel(IronTraceDbContext db) => _db = db;

    public IReadOnlyList<ScanSubmissionEntity> Scans { get; private set; } = [];

    [BindProperty(SupportsGet = true)]
    public ScanReviewStatus? Status { get; set; }

    public async Task OnGetAsync()
    {
        var q = _db.Scans.AsNoTracking().AsQueryable();
        if (Status is not null)
        {
            q = q.Where(s => s.ReviewStatus == Status);
        }

        Scans = await q.OrderByDescending(s => s.ReceivedAt).Take(200).ToListAsync();
    }
}

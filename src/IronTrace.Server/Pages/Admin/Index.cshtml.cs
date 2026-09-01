using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IronTrace.Server.Pages.Admin;

public class IndexModel : PageModel
{
    public IActionResult OnGet() => RedirectToPage("/Admin/Scans/Index");
}

using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using IronTrace.Contracts.Api;
using IronTrace.Server.Auth;
using IronTrace.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IronTrace.Server.Pages.Admin;

[AllowAnonymous]
public class LoginModel : PageModel
{
    private readonly IronTraceDbContext _db;

    public LoginModel(IronTraceDbContext db) => _db = db;

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? Error { get; set; }

    public class InputModel
    {
        [Required]
        public string ApiKey { get; set; } = "";
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var hash = ApiKeyHasher.Hash(Input.ApiKey.Trim());
        var key = await _db.ApiKeys.AsNoTracking()
            .FirstOrDefaultAsync(k => k.KeyHash == hash && k.RevokedAt == null && k.Scope == ApiKeyScope.Admin);
        if (key is null)
        {
            Error = "Invalid admin API key.";
            return Page();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, key.Name),
            new(ClaimTypes.Role, nameof(ApiKeyScope.Admin)),
            new(ApiKeyAuthDefaults.KeyIdClaim, key.Id.ToString("D")),
            new(ApiKeyAuthDefaults.ScopeClaim, nameof(ApiKeyScope.Admin))
        };
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));

        return RedirectToPage("/Admin/Scans/Index");
    }
}

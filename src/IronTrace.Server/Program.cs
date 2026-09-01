using System.Security.Claims;
using IronTrace.Server.Auth;
using IronTrace.Server.Data;
using IronTrace.Server.Endpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var useInMemory = builder.Configuration.GetValue("IronTrace:UseInMemoryDatabase", false);
var conn = builder.Configuration.GetConnectionString("IronTrace")
           ?? "Host=localhost;Port=5432;Database=irontrace;Username=irontrace;Password=irontrace";

builder.Services.AddDbContext<IronTraceDbContext>(options =>
{
    if (useInMemory)
    {
        options.UseInMemoryDatabase("IronTrace");
    }
    else if (conn.StartsWith("Data Source=", StringComparison.OrdinalIgnoreCase) ||
             conn.Contains(".db", StringComparison.OrdinalIgnoreCase))
    {
        options.UseSqlite(conn);
    }
    else
    {
        options.UseNpgsql(conn);
    }
});

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/admin/login";
        options.AccessDeniedPath = "/admin/login";
        options.Cookie.Name = "IronTrace.Admin";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    })
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthDefaults.Scheme, _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Upload", p =>
        p.AddAuthenticationSchemes(ApiKeyAuthDefaults.Scheme)
            .RequireRole(nameof(IronTrace.Contracts.Api.ApiKeyScope.Upload)));
    options.AddPolicy("Admin", p =>
        p.AddAuthenticationSchemes(ApiKeyAuthDefaults.Scheme, CookieAuthenticationDefaults.AuthenticationScheme)
            .RequireRole(nameof(IronTrace.Contracts.Api.ApiKeyScope.Admin)));
});

builder.Services.AddRazorPages();
builder.Services.AddOpenApi();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(
        new System.Text.Json.Serialization.JsonStringEnumConverter(System.Text.Json.JsonNamingPolicy.CamelCase));
});

var app = builder.Build();

await ApiKeyBootstrap.EnsureBootstrapKeysAsync(app.Services, app.Configuration, app.Logger);

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapIronTraceApi();
app.MapRazorPages();
app.MapGet("/", () => Results.Redirect("/admin"));

app.Run();

public partial class Program;

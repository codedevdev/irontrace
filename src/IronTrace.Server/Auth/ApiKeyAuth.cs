using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using IronTrace.Contracts.Api;
using IronTrace.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IronTrace.Server.Auth;

public static class ApiKeyAuthDefaults
{
    public const string Scheme = "IronTraceApiKey";
    public const string UploadPrefix = "it_upload_";
    public const string AdminPrefix = "it_admin_";
    public const string ScopeClaim = "irontrace_scope";
    public const string KeyIdClaim = "irontrace_key_id";
}

public static class ApiKeyHasher
{
    public static string Hash(string secret)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();

    public static string GenerateSecret(ApiKeyScope scope)
    {
        var prefix = scope == ApiKeyScope.Admin
            ? ApiKeyAuthDefaults.AdminPrefix
            : ApiKeyAuthDefaults.UploadPrefix;
        return prefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
    }
}

public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IronTraceDbContext _db;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IronTraceDbContext db)
        : base(options, logger, encoder)
    {
        _db = db;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var header))
        {
            return AuthenticateResult.NoResult();
        }

        var value = header.ToString();
        if (!value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.Fail("Expected Bearer API key.");
        }

        var secret = value["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(secret))
        {
            return AuthenticateResult.Fail("Empty API key.");
        }

        var hash = ApiKeyHasher.Hash(secret);
        var entity = await _db.ApiKeys.AsNoTracking()
            .FirstOrDefaultAsync(k => k.KeyHash == hash && k.RevokedAt == null);

        if (entity is null)
        {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        // Stash raw secret for HMAC verification on upload (HttpContext.Items)
        Context.Items["IronTraceApiKeySecret"] = secret;
        Context.Items["IronTraceApiKeyId"] = entity.Id;

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, entity.Name),
            new(ApiKeyAuthDefaults.ScopeClaim, entity.Scope.ToString()),
            new(ApiKeyAuthDefaults.KeyIdClaim, entity.Id.ToString("D")),
            new(ClaimTypes.Role, entity.Scope.ToString())
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }
}

public static class ApiKeyBootstrap
{
    public static async Task EnsureBootstrapKeysAsync(IServiceProvider services, IConfiguration config, ILogger logger)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IronTraceDbContext>();
        if (db.Database.IsRelational())
        {
            await db.Database.MigrateAsync();
        }
        else
        {
            await db.Database.EnsureCreatedAsync();
        }

        await EnsureKeyAsync(db, config["IRONTRACE_BOOTSTRAP_ADMIN_KEY"] ?? config["IronTrace:Bootstrap:AdminKey"],
            ApiKeyScope.Admin, "Bootstrap Admin", logger);
        await EnsureKeyAsync(db, config["IRONTRACE_BOOTSTRAP_UPLOAD_KEY"] ?? config["IronTrace:Bootstrap:UploadKey"],
            ApiKeyScope.Upload, "Bootstrap Upload", logger);
    }

    private static async Task EnsureKeyAsync(
        IronTraceDbContext db,
        string? secret,
        ApiKeyScope scope,
        string name,
        ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            return;
        }

        var hash = ApiKeyHasher.Hash(secret);
        if (await db.ApiKeys.AnyAsync(k => k.KeyHash == hash))
        {
            return;
        }

        if (await db.ApiKeys.AnyAsync(k => k.Scope == scope && k.RevokedAt == null && k.Name == name))
        {
            return;
        }

        var prefix = secret.Length >= 12 ? secret[..12] : secret;
        db.ApiKeys.Add(new ApiKeyEntity
        {
            Id = Guid.NewGuid(),
            Name = name,
            KeyPrefix = prefix,
            KeyHash = hash,
            Scope = scope,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync();
        logger.LogInformation("Bootstrapped {Scope} API key (prefix {Prefix}…).", scope, prefix);
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IronTrace.Contracts;
using IronTrace.Contracts.Api;
using IronTrace.Server.Auth;
using IronTrace.Server.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IronTrace.Server.Endpoints;

public static class ApiV1Endpoints
{
    public static RouteGroupBuilder MapIronTraceApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1").WithTags("IronTrace");

        group.MapPost("/challenges", CreateChallenge)
            .RequireAuthorization("Upload")
            .WithName("CreateChallenge");

        group.MapPost("/scans", UploadScan)
            .RequireAuthorization("Upload")
            .WithName("UploadScan")
            .DisableAntiforgery();

        group.MapGet("/scans", ListScans)
            .RequireAuthorization("Admin")
            .WithName("ListScans");

        group.MapGet("/scans/{id:guid}", GetScan)
            .RequireAuthorization("Admin")
            .WithName("GetScan");

        group.MapPatch("/scans/{id:guid}/review", ReviewScan)
            .RequireAuthorization("Admin")
            .WithName("ReviewScan");

        return group;
    }

    private static async Task<IResult> CreateChallenge(
        HttpContext http,
        IronTraceDbContext db,
        CancellationToken ct)
    {
        var keyId = (Guid)http.Items["IronTraceApiKeyId"]!;
        var sessionId = Guid.NewGuid();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var expires = DateTimeOffset.UtcNow.AddMinutes(10);

        db.Challenges.Add(new ChallengeEntity
        {
            SessionId = sessionId,
            Nonce = nonce,
            ApiKeyId = keyId,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expires
        });
        await db.SaveChangesAsync(ct);

        return Results.Ok(new ChallengeResponse(sessionId, nonce, expires));
    }

    private static async Task<IResult> UploadScan(
        HttpContext http,
        IronTraceDbContext db,
        CancellationToken ct)
    {
        if (!http.Request.Headers.TryGetValue(UploadHmac.SessionHeader, out var sessionHeader) ||
            !Guid.TryParse(sessionHeader.ToString(), out var sessionId))
        {
            return Results.BadRequest(new { error = "Missing or invalid session id header." });
        }

        if (!http.Request.Headers.TryGetValue(UploadHmac.NonceHeader, out var nonceHeader) ||
            string.IsNullOrWhiteSpace(nonceHeader))
        {
            return Results.BadRequest(new { error = "Missing nonce header." });
        }

        if (!http.Request.Headers.TryGetValue(UploadHmac.SignatureHeader, out var sigHeader) ||
            string.IsNullOrWhiteSpace(sigHeader))
        {
            return Results.BadRequest(new { error = "Missing signature header." });
        }

        http.Request.EnableBuffering();
        using var ms = new MemoryStream();
        await http.Request.Body.CopyToAsync(ms, ct);
        var body = ms.ToArray();
        if (body.Length == 0)
        {
            return Results.BadRequest(new { error = "Empty body." });
        }

        if (body.Length > 8 * 1024 * 1024)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        var secret = http.Items["IronTraceApiKeySecret"] as string;
        if (string.IsNullOrEmpty(secret))
        {
            return Results.Unauthorized();
        }

        var expected = UploadHmac.ComputeSignature(secret, sessionId, nonceHeader.ToString(), body);
        if (!UploadHmac.FixedTimeEqualsHex(expected, sigHeader.ToString().Trim().ToLowerInvariant()))
        {
            return Results.Unauthorized();
        }

        var challenge = await db.Challenges.FirstOrDefaultAsync(c => c.SessionId == sessionId, ct);
        if (challenge is null)
        {
            return Results.BadRequest(new { error = "Unknown challenge session." });
        }

        if (challenge.ConsumedAt is not null)
        {
            return Results.Conflict(new { error = "Challenge nonce already used." });
        }

        if (challenge.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return Results.BadRequest(new { error = "Challenge expired." });
        }

        if (!string.Equals(challenge.Nonce, nonceHeader.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { error = "Nonce mismatch." });
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        var schema = root.TryGetProperty("schemaVersion", out var sv) ? sv.GetString() ?? "" : "";
        var appVer = root.TryGetProperty("ironTraceVersion", out var av) ? av.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(schema))
        {
            return Results.BadRequest(new { error = "schemaVersion required." });
        }

        // Accept current and recent schemas
        if (schema is not ("1.6" or "1.5" or "1.4" or "1.3" or "1.2" or "1.1" or "1.0"))
        {
            return Results.BadRequest(new { error = $"Unsupported report schemaVersion: {schema}" });
        }

        string? verdict = null;
        string? summary = null;
        if (root.TryGetProperty("assessment", out var assessment) && assessment.ValueKind == JsonValueKind.Object)
        {
            verdict = assessment.TryGetProperty("verdict", out var v) ? v.GetString() : null;
            summary = assessment.TryGetProperty("summary", out var s) ? s.GetString() : null;
        }

        string? hostHash = null;
        if (root.TryGetProperty("metadata", out var meta) && meta.ValueKind == JsonValueKind.Object &&
            meta.TryGetProperty("hostMachineNameHash", out var hh))
        {
            hostHash = hh.GetString();
        }

        // Strip raw serial if present
        var sanitized = SanitizePayload(root);

        var keyId = (Guid)http.Items["IronTraceApiKeyId"]!;
        var scanId = Guid.NewGuid();
        db.Scans.Add(new ScanSubmissionEntity
        {
            Id = scanId,
            SessionId = sessionId,
            ReceivedAt = DateTimeOffset.UtcNow,
            ReportSchemaVersion = schema,
            ApplicationVersion = string.IsNullOrWhiteSpace(appVer) ? IronTraceVersions.Application : appVer,
            Verdict = verdict,
            Summary = summary,
            HostMachineNameHash = hostHash,
            PayloadJson = sanitized,
            ReviewStatus = ScanReviewStatus.Pending,
            UploadApiKeyId = keyId
        });

        challenge.ConsumedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        return Results.Ok(new ScanUploadResponse(scanId, ScanReviewStatus.Pending, "Scan accepted for administrator review."));
    }

    private static string SanitizePayload(JsonElement root)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteSanitized(writer, root);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteSanitized(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var prop in element.EnumerateObject())
                {
                    if (prop.NameEquals("serialRaw") || prop.NameEquals("SerialRaw"))
                    {
                        continue;
                    }

                    writer.WritePropertyName(prop.Name);
                    WriteSanitized(writer, prop.Value);
                }

                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteSanitized(writer, item);
                }

                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static async Task<IResult> ListScans(
        IronTraceDbContext db,
        [FromQuery] ScanReviewStatus? status,
        CancellationToken ct)
    {
        var q = db.Scans.AsNoTracking().AsQueryable();
        if (status is not null)
        {
            q = q.Where(s => s.ReviewStatus == status);
        }

        var items = await q.OrderByDescending(s => s.ReceivedAt)
            .Take(200)
            .Select(s => new ScanListItemDto(
                s.Id,
                s.SessionId,
                s.ReceivedAt,
                s.Verdict,
                s.Summary,
                s.ReportSchemaVersion,
                s.ApplicationVersion,
                s.ReviewStatus))
            .ToListAsync(ct);

        return Results.Ok(items);
    }

    private static async Task<IResult> GetScan(Guid id, IronTraceDbContext db, CancellationToken ct)
    {
        var s = await db.Scans.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (s is null)
        {
            return Results.NotFound();
        }

        return Results.Ok(new ScanDetailDto(
            s.Id,
            s.SessionId,
            s.ReceivedAt,
            s.Verdict,
            s.Summary,
            s.ReportSchemaVersion,
            s.ApplicationVersion,
            s.HostMachineNameHash,
            s.ReviewStatus,
            s.ReviewNotes,
            s.PayloadJson));
    }

    private static async Task<IResult> ReviewScan(
        Guid id,
        ReviewScanRequest body,
        HttpContext http,
        IronTraceDbContext db,
        CancellationToken ct)
    {
        var s = await db.Scans.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (s is null)
        {
            return Results.NotFound();
        }

        s.ReviewStatus = body.Status;
        s.ReviewNotes = body.Notes;
        s.ReviewerKeyId = (Guid)http.Items["IronTraceApiKeyId"]!;
        await db.SaveChangesAsync(ct);
        return Results.Ok(new { s.Id, s.ReviewStatus, s.ReviewNotes });
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using IronTrace.Contracts.Api;
using IronTrace.Server.Auth;
using IronTrace.Server.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IronTrace.Server.Tests;

file static class JsonTest
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };
}

public sealed class UploadHmacTests
{
    [Fact]
    public void Canonical_string_is_stable()
    {
        var session = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var body = Encoding.UTF8.GetBytes("""{"schemaVersion":"1.2"}""");
        var sig = UploadHmac.ComputeSignature("it_upload_test", session, "abc", body);
        var sig2 = UploadHmac.ComputeSignature("it_upload_test", session, "abc", body);
        sig.Should().Be(sig2);
        sig.Should().HaveLength(64);
    }

    [Fact]
    public void FixedTimeEqualsHex_rejects_mismatch()
    {
        UploadHmac.FixedTimeEqualsHex("aa", "bb").Should().BeFalse();
        UploadHmac.FixedTimeEqualsHex("aabb", "aabb").Should().BeTrue();
    }
}

public sealed class ApiIntegrationTests : IClassFixture<IronTraceWebApplicationFactory>
{
    private readonly IronTraceWebApplicationFactory _factory;

    public ApiIntegrationTests(IronTraceWebApplicationFactory factory) => _factory = factory;

    [Fact]
    public async Task Happy_path_upload_and_admin_list()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", IronTraceWebApplicationFactory.UploadKey);

        var challenge = await client.PostAsync("/v1/challenges", null);
        challenge.StatusCode.Should().Be(HttpStatusCode.OK);
        var ch = await challenge.Content.ReadFromJsonAsync<ChallengeResponse>(JsonTest.Options);
        ch.Should().NotBeNull();

        var bodyText = """{"schemaVersion":"1.4","ironTraceVersion":"0.5.1","assessment":{"verdict":"Low","summary":"ok"},"findings":[]}""";
        var body = Encoding.UTF8.GetBytes(bodyText);
        var sig = UploadHmac.ComputeSignature(IronTraceWebApplicationFactory.UploadKey, ch!.SessionId, ch.Nonce, body);

        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/scans") { Content = content };
        req.Headers.TryAddWithoutValidation(UploadHmac.SessionHeader, ch.SessionId.ToString("D"));
        req.Headers.TryAddWithoutValidation(UploadHmac.NonceHeader, ch.Nonce);
        req.Headers.TryAddWithoutValidation(UploadHmac.SignatureHeader, sig);

        var upload = await client.SendAsync(req);
        upload.StatusCode.Should().Be(HttpStatusCode.OK);
        var uploaded = await upload.Content.ReadFromJsonAsync<ScanUploadResponse>(JsonTest.Options);
        uploaded!.Status.Should().Be(ScanReviewStatus.Pending);

        // reuse nonce
        using var content2 = new ByteArrayContent(body);
        content2.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var req2 = new HttpRequestMessage(HttpMethod.Post, "/v1/scans") { Content = content2 };
        req2.Headers.TryAddWithoutValidation(UploadHmac.SessionHeader, ch.SessionId.ToString("D"));
        req2.Headers.TryAddWithoutValidation(UploadHmac.NonceHeader, ch.Nonce);
        req2.Headers.TryAddWithoutValidation(UploadHmac.SignatureHeader, sig);
        var reuse = await client.SendAsync(req2);
        reuse.StatusCode.Should().Be(HttpStatusCode.Conflict);

        var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", IronTraceWebApplicationFactory.AdminKey);
        var list = await admin.GetAsync("/v1/scans");
        list.StatusCode.Should().Be(HttpStatusCode.OK);
        var items = await list.Content.ReadFromJsonAsync<List<ScanListItemDto>>(JsonTest.Options);
        items.Should().Contain(i => i.Id == uploaded.ScanId);
    }

    [Fact]
    public async Task Bad_signature_is_rejected()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", IronTraceWebApplicationFactory.UploadKey);

        var challenge = await client.PostAsync("/v1/challenges", null);
        var ch = await challenge.Content.ReadFromJsonAsync<ChallengeResponse>(JsonTest.Options);

        var body = Encoding.UTF8.GetBytes("""{"schemaVersion":"1.2"}""");
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/scans") { Content = content };
        req.Headers.TryAddWithoutValidation(UploadHmac.SessionHeader, ch!.SessionId.ToString("D"));
        req.Headers.TryAddWithoutValidation(UploadHmac.NonceHeader, ch.Nonce);
        req.Headers.TryAddWithoutValidation(UploadHmac.SignatureHeader, new string('0', 64));

        var upload = await client.SendAsync(req);
        upload.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Expired_challenge_is_rejected()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IronTraceDbContext>();
        var sessionId = Guid.NewGuid();
        var nonce = "deadbeef";
        db.Challenges.Add(new ChallengeEntity
        {
            SessionId = sessionId,
            Nonce = nonce,
            ApiKeyId = Guid.NewGuid(),
            CreatedAt = DateTimeOffset.UtcNow.AddHours(-1),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        await db.SaveChangesAsync();

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", IronTraceWebApplicationFactory.UploadKey);

        var body = Encoding.UTF8.GetBytes("""{"schemaVersion":"1.2"}""");
        var sig = UploadHmac.ComputeSignature(IronTraceWebApplicationFactory.UploadKey, sessionId, nonce, body);
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/scans") { Content = content };
        req.Headers.TryAddWithoutValidation(UploadHmac.SessionHeader, sessionId.ToString("D"));
        req.Headers.TryAddWithoutValidation(UploadHmac.NonceHeader, nonce);
        req.Headers.TryAddWithoutValidation(UploadHmac.SignatureHeader, sig);

        var upload = await client.SendAsync(req);
        upload.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}

public sealed class IronTraceWebApplicationFactory : WebApplicationFactory<Program>
{
    public const string UploadKey = "it_upload_test_integration_key_001";
    public const string AdminKey = "it_admin_test_integration_key_001";
    private readonly string _dbName = "IronTraceTests_" + Guid.NewGuid().ToString("N");

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.UseSetting("IronTrace:UseInMemoryDatabase", "true");
        builder.UseSetting("IronTrace:Bootstrap:UploadKey", UploadKey);
        builder.UseSetting("IronTrace:Bootstrap:AdminKey", AdminKey);
        builder.UseSetting("ConnectionStrings:IronTrace", "unused");

        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<IronTraceDbContext>));
            if (descriptor is not null)
            {
                services.Remove(descriptor);
            }

            services.AddDbContext<IronTraceDbContext>(options => options.UseInMemoryDatabase(_dbName));
        });
    }
}

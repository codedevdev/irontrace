using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using IronTrace.Contracts.Api;
using IronTrace.Contracts.Reporting;
using IronTrace.Contracts.Scanning;
using IronTrace.Core.Paths;
using IronTrace.Reporting;
using Microsoft.Extensions.Logging;

namespace IronTrace.App.Services;

public interface IScanUploadService
{
    bool IsConfigured { get; }
    Task<ScanUploadResult> UploadAsync(ScanSession session, CancellationToken cancellationToken);
}

public sealed record ScanUploadResult(bool Success, string Message, Guid? ScanId = null);

public sealed class ServerUploadOptions
{
    public const string SectionName = "IronTrace:Server";
    public string BaseUrl { get; set; } = "";
    /// <summary>Optional plaintext for local/dev; prefer DPAPI store under Keys.</summary>
    public string? UploadApiKey { get; set; }
}

public sealed class DpapiUploadApiKeyStore
{
    private readonly string _path;

    public DpapiUploadApiKeyStore(string? path = null)
    {
        _path = path ?? Path.Combine(IronTracePaths.Keys, "upload-api-key.bin");
    }

    public string? TryRead()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            var protectedBytes = File.ReadAllBytes(_path);
            var bytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    public void Save(string apiKey)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var bytes = Encoding.UTF8.GetBytes(apiKey);
        var protectedBytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_path, protectedBytes);
    }
}

public sealed class ScanUploadService : IScanUploadService
{
    private readonly ServerUploadOptions _options;
    private readonly IScanReportExporter _exporter;
    private readonly DpapiUploadApiKeyStore _keyStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ScanUploadService> _logger;

    public ScanUploadService(
        ServerUploadOptions options,
        IScanReportExporter exporter,
        DpapiUploadApiKeyStore keyStore,
        IHttpClientFactory httpClientFactory,
        ILogger<ScanUploadService> logger)
    {
        _options = options;
        _exporter = exporter;
        _keyStore = keyStore;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(_options.BaseUrl) &&
        !string.IsNullOrWhiteSpace(ResolveApiKey());

    private string? ResolveApiKey()
    {
        var fromStore = _keyStore.TryRead();
        if (!string.IsNullOrWhiteSpace(fromStore))
        {
            return fromStore.Trim();
        }

        if (!string.IsNullOrWhiteSpace(_options.UploadApiKey))
        {
            return _options.UploadApiKey.Trim();
        }

        return null;
    }

    public async Task<ScanUploadResult> UploadAsync(ScanSession session, CancellationToken cancellationToken)
    {
        var baseUrl = _options.BaseUrl?.Trim().TrimEnd('/');
        var apiKey = ResolveApiKey();
        if (string.IsNullOrWhiteSpace(baseUrl) || string.IsNullOrWhiteSpace(apiKey))
        {
            return new ScanUploadResult(false, "Server upload is not configured. Set BaseUrl and store an Upload API key.");
        }

        // Persist key from config into DPAPI store on first successful resolve from config
        if (_keyStore.TryRead() is null && !string.IsNullOrWhiteSpace(_options.UploadApiKey))
        {
            try
            {
                _keyStore.Save(apiKey);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not persist upload API key to DPAPI store.");
            }
        }

        var privacy = new ExportPrivacyOptions(
            IncludeSerialHash: true,
            IncludeDriverImagePaths: true,
            IncludeCodeIntegrityEvents: true,
            IncludeInstanceIds: true,
            IncludeRawSerial: false);

        var json = _exporter.ToJson(session, privacy);
        var body = Encoding.UTF8.GetBytes(json);

        using var client = _httpClientFactory.CreateClient("IronTraceUpload");
        client.BaseAddress = new Uri(baseUrl + "/");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        ChallengeResponse? challenge;
        try
        {
            using var challengeResponse = await client.PostAsync("v1/challenges", content: null, cancellationToken)
                .ConfigureAwait(false);
            if (!challengeResponse.IsSuccessStatusCode)
            {
                var err = await challengeResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                return new ScanUploadResult(false, $"Challenge failed ({(int)challengeResponse.StatusCode}): {Trim(err)}");
            }

            var jsonOpts = new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            challenge = await challengeResponse.Content.ReadFromJsonAsync<ChallengeResponse>(jsonOpts, cancellationToken)
                .ConfigureAwait(false);
            if (challenge is null)
            {
                return new ScanUploadResult(false, "Challenge response was empty.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Challenge request failed.");
            return new ScanUploadResult(false, $"Could not reach server: {ex.Message}");
        }

        var signature = UploadHmac.ComputeSignature(apiKey, challenge.SessionId, challenge.Nonce, body);
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, "v1/scans") { Content = content };
        request.Headers.TryAddWithoutValidation(UploadHmac.SessionHeader, challenge.SessionId.ToString("D"));
        request.Headers.TryAddWithoutValidation(UploadHmac.NonceHeader, challenge.Nonce);
        request.Headers.TryAddWithoutValidation(UploadHmac.SignatureHeader, signature);

        try
        {
            using var uploadResponse = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var responseBody = await uploadResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!uploadResponse.IsSuccessStatusCode)
            {
                return new ScanUploadResult(false, $"Upload failed ({(int)uploadResponse.StatusCode}): {Trim(responseBody)}");
            }

            var parsed = System.Text.Json.JsonSerializer.Deserialize<ScanUploadResponse>(
                responseBody,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return new ScanUploadResult(
                true,
                parsed?.Message ?? "Scan uploaded for administrator review.",
                parsed?.ScanId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Scan upload failed.");
            return new ScanUploadResult(false, $"Upload error: {ex.Message}");
        }
    }

    private static string Trim(string s) =>
        s.Length <= 240 ? s : s[..240] + "…";
}

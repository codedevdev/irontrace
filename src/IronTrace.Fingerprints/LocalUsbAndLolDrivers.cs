using System.Globalization;
using System.Text;
using System.Text.Json;
using IronTrace.Contracts;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Reference;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace IronTrace.Fingerprints;

public sealed class LocalUsbIdsProvider : IUsbReferenceProvider, IAsyncDisposable
{
    private readonly string _databasePath;
    private readonly ILogger<LocalUsbIdsProvider> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqliteConnection? _connection;
    private ReferenceDbInfo? _info;

    public LocalUsbIdsProvider(string databasePath, ILogger<LocalUsbIdsProvider> logger)
    {
        _databasePath = databasePath;
        _logger = logger;
        Name = "LocalUsbIdsProvider";
    }

    public string Name { get; }

    public async Task<UsbResolvedIdentity?> ResolveAsync(UsbDeviceIdentity identity, CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        if (_connection is null)
        {
            return null;
        }

        var vendor = await ScalarAsync(
            "SELECT name FROM vendors WHERE vendor_id = $id",
            ("$id", (long)identity.VendorId),
            cancellationToken).ConfigureAwait(false);
        var product = await ScalarAsync(
            "SELECT name FROM products WHERE vendor_id = $v AND product_id = $p",
            ("$v", (long)identity.VendorId),
            ("$p", (long)identity.ProductId),
            cancellationToken).ConfigureAwait(false);

        if (vendor is null && product is null)
        {
            return null;
        }

        return new UsbResolvedIdentity(
            vendor,
            product,
            Source: "usb.ids",
            RetrievedAt: _info?.RetrievedAt,
            Confidence: FindingConfidence.ReferenceIdentity);
    }

    public async Task<ReferenceDbInfo?> GetInfoAsync(CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        return _info;
    }

    private async Task EnsureOpenAsync(CancellationToken cancellationToken)
    {
        if (_connection is not null)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_connection is not null)
            {
                return;
            }

            if (!File.Exists(_databasePath))
            {
                _logger.LogWarning("USB reference database not found at {Path}", _databasePath);
                return;
            }

            var connection = new SqliteConnection($"Data Source={_databasePath};Mode=ReadOnly");
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            _connection = connection;
            _info = await ReadMetaAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ReferenceDbInfo> ReadMetaAsync(CancellationToken cancellationToken)
    {
        async Task<string?> Meta(string key)
        {
            await using var cmd = _connection!.CreateCommand();
            cmd.CommandText = "SELECT value FROM meta WHERE key = $k";
            cmd.Parameters.AddWithValue("$k", key);
            var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            return result?.ToString();
        }

        var schema = int.TryParse(await Meta("schema_version").ConfigureAwait(false), out var s)
            ? s
            : IronTraceVersions.UsbReferenceDbSchema;
        DateTimeOffset? retrieved = null;
        if (DateTimeOffset.TryParse(await Meta("retrieved_at").ConfigureAwait(false), CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var dt))
        {
            retrieved = dt;
        }

        return new ReferenceDbInfo(
            schema,
            await Meta("source_name").ConfigureAwait(false) ?? "usb.ids",
            await Meta("source_url").ConfigureAwait(false),
            await Meta("license").ConfigureAwait(false),
            retrieved,
            await Meta("content_hash").ConfigureAwait(false),
            _databasePath);
    }

    private async Task<string?> ScalarAsync(
        string sql,
        (string Name, long Value) p1,
        CancellationToken cancellationToken)
    {
        if (_connection is null)
        {
            return null;
        }

        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue(p1.Name, p1.Value);
        var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result?.ToString();
    }

    private async Task<string?> ScalarAsync(
        string sql,
        (string Name, long Value) p1,
        (string Name, long Value) p2,
        CancellationToken cancellationToken)
    {
        if (_connection is null)
        {
            return null;
        }

        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue(p1.Name, p1.Value);
        cmd.Parameters.AddWithValue(p2.Name, p2.Value);
        var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result?.ToString();
    }

    public async ValueTask DisposeAsync()
    {
        if (_connection is not null)
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
            _connection = null;
        }

        _gate.Dispose();
    }
}

public static class UsbIdsImporter
{
    public const long MaxInputBytes = 20 * 1024 * 1024;

    public static async Task ImportAsync(
        string usbIdsPath,
        string outputDbPath,
        CancellationToken cancellationToken = default)
    {
        var fileInfo = new FileInfo(usbIdsPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("usb.ids not found", usbIdsPath);
        }

        if (fileInfo.Length > MaxInputBytes)
        {
            throw new InvalidOperationException($"usb.ids exceeds max size ({MaxInputBytes} bytes).");
        }

        var bytes = await File.ReadAllBytesAsync(usbIdsPath, cancellationToken).ConfigureAwait(false);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        var text = Encoding.UTF8.GetString(bytes);

        var directory = Path.GetDirectoryName(outputDbPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = outputDbPath + ".tmp";
        if (File.Exists(tempPath))
        {
            File.Delete(tempPath);
        }

        await using (var connection = new SqliteConnection($"Data Source={tempPath};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText =
                    """
                    PRAGMA journal_mode=OFF;
                    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE vendors(vendor_id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                    CREATE TABLE products(
                      vendor_id INTEGER NOT NULL,
                      product_id INTEGER NOT NULL,
                      name TEXT NOT NULL,
                      PRIMARY KEY(vendor_id, product_id));
                    """;
                await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            ushort? currentVendor = null;

            foreach (var rawLine in text.Split('\n'))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = rawLine.TrimEnd('\r');
                if (line.Length == 0 || line[0] == '#')
                {
                    continue;
                }

                // Skip class / other sections (lines starting with letters other than hex vendor)
                if (line.StartsWith("C ", StringComparison.Ordinal) ||
                    line.StartsWith("AT ", StringComparison.Ordinal) ||
                    line.StartsWith("HID ", StringComparison.Ordinal) ||
                    line.StartsWith("R ", StringComparison.Ordinal) ||
                    line.StartsWith("PHY ", StringComparison.Ordinal) ||
                    line.StartsWith("BIAS ", StringComparison.Ordinal) ||
                    line.StartsWith("L ", StringComparison.Ordinal))
                {
                    currentVendor = null;
                    continue;
                }

                if (line.StartsWith('\t'))
                {
                    if (currentVendor is null)
                    {
                        continue;
                    }

                    var parts = SplitIdName(line.AsSpan(1));
                    if (!ushort.TryParse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var productId))
                    {
                        continue;
                    }

                    await InsertProductAsync(connection, (SqliteTransaction)tx, currentVendor.Value, productId, parts.Name, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                {
                    var parts = SplitIdName(line);
                    if (!ushort.TryParse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var vendorId))
                    {
                        currentVendor = null;
                        continue;
                    }

                    currentVendor = vendorId;
                    await InsertVendorAsync(connection, (SqliteTransaction)tx, vendorId, parts.Name, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            await SetMetaAsync(connection, (SqliteTransaction)tx, "schema_version", IronTraceVersions.UsbReferenceDbSchema.ToString(CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "source_name", "usb.ids", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "source_url", "http://www.linux-usb.org/usb.ids", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "license", "GPLv2+/BSD-style (see upstream)", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "retrieved_at", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "content_hash", hash, cancellationToken).ConfigureAwait(false);
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            await connection.CloseAsync().ConfigureAwait(false);
        }

        SqliteConnection.ClearAllPools();
        AtomicReplace(outputDbPath, tempPath);
    }

    private static void AtomicReplace(string outputDbPath, string tempPath)
    {
        if (File.Exists(outputDbPath))
        {
            var bak = outputDbPath + ".bak";
            if (File.Exists(bak))
            {
                File.Delete(bak);
            }

            File.Move(outputDbPath, bak);
        }

        File.Move(tempPath, outputDbPath);
    }

    private static (string Id, string Name) SplitIdName(ReadOnlySpan<char> span)
    {
        span = span.Trim();
        var space = span.IndexOf(' ');
        if (space <= 0)
        {
            return (span.ToString(), "");
        }

        return (span[..space].ToString(), span[(space + 1)..].Trim().ToString());
    }

    private static async Task InsertVendorAsync(SqliteConnection c, SqliteTransaction tx, ushort id, string name, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO vendors(vendor_id, name) VALUES ($id, $name)";
        cmd.Parameters.AddWithValue("$id", (long)id);
        cmd.Parameters.AddWithValue("$name", name);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task InsertProductAsync(SqliteConnection c, SqliteTransaction tx, ushort v, ushort p, string name, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO products(vendor_id, product_id, name) VALUES ($v,$p,$name)";
        cmd.Parameters.AddWithValue("$v", (long)v);
        cmd.Parameters.AddWithValue("$p", (long)p);
        cmd.Parameters.AddWithValue("$name", name);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task SetMetaAsync(SqliteConnection c, SqliteTransaction tx, string key, string value, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO meta(key, value) VALUES ($k,$v)";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}

public sealed class LocalLolDriversProvider : ILolDriversProvider, IAsyncDisposable
{
    private readonly string _databasePath;
    private readonly ILogger<LocalLolDriversProvider> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqliteConnection? _connection;
    private ReferenceDbInfo? _info;

    public LocalLolDriversProvider(string databasePath, ILogger<LocalLolDriversProvider> logger)
    {
        _databasePath = databasePath;
        _logger = logger;
        Name = "LocalLolDriversProvider";
    }

    public string Name { get; }

    public async Task<VulnerableDriverMatch?> MatchBySha256Async(string sha256Hex, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sha256Hex))
        {
            return null;
        }

        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        if (_connection is null)
        {
            return null;
        }

        var normalized = sha256Hex.Trim().ToLowerInvariant();
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT s.sha256, s.filename, d.id, d.title, d.category
            FROM samples s
            JOIN drivers d ON d.id = s.driver_id
            WHERE lower(s.sha256) = $h
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("$h", normalized);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        return new VulnerableDriverMatch(
            MatchKind: "sha256",
            Confidence: FindingConfidence.High,
            DriverFileName: reader.IsDBNull(1) ? null : reader.GetString(1),
            DriverSha256: reader.GetString(0),
            LolDriversId: reader.GetString(2),
            Title: reader.IsDBNull(3) ? null : reader.GetString(3),
            Category: reader.IsDBNull(4) ? null : reader.GetString(4),
            Evidence: $"SHA-256 match against local LOLDrivers snapshot: {normalized}",
            RelatedPath: null);
    }

    public async Task<VulnerableDriverMatch?> MatchByFileNameAsync(string fileName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return null;
        }

        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        if (_connection is null)
        {
            return null;
        }

        var baseName = Path.GetFileName(fileName).ToLowerInvariant();
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT s.sha256, s.filename, d.id, d.title, d.category
            FROM samples s
            JOIN drivers d ON d.id = s.driver_id
            WHERE lower(s.filename) = $f
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("$f", baseName);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        return new VulnerableDriverMatch(
            MatchKind: "filename",
            Confidence: FindingConfidence.Medium,
            DriverFileName: reader.IsDBNull(1) ? null : reader.GetString(1),
            DriverSha256: reader.IsDBNull(0) ? null : reader.GetString(0),
            LolDriversId: reader.GetString(2),
            Title: reader.IsDBNull(3) ? null : reader.GetString(3),
            Category: reader.IsDBNull(4) ? null : reader.GetString(4),
            Evidence: $"Filename match against local LOLDrivers snapshot: {baseName}",
            RelatedPath: null);
    }

    public async Task<ReferenceDbInfo?> GetInfoAsync(CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        return _info;
    }

    private async Task EnsureOpenAsync(CancellationToken cancellationToken)
    {
        if (_connection is not null)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_connection is not null)
            {
                return;
            }

            if (!File.Exists(_databasePath))
            {
                _logger.LogWarning("LOLDrivers database not found at {Path}", _databasePath);
                return;
            }

            var connection = new SqliteConnection($"Data Source={_databasePath};Mode=ReadOnly");
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            _connection = connection;
            _info = await ReadMetaAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ReferenceDbInfo> ReadMetaAsync(CancellationToken cancellationToken)
    {
        async Task<string?> Meta(string key)
        {
            await using var cmd = _connection!.CreateCommand();
            cmd.CommandText = "SELECT value FROM meta WHERE key = $k";
            cmd.Parameters.AddWithValue("$k", key);
            var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            return result?.ToString();
        }

        var schema = int.TryParse(await Meta("schema_version").ConfigureAwait(false), out var s)
            ? s
            : IronTraceVersions.LolDriversDbSchema;
        DateTimeOffset? retrieved = null;
        if (DateTimeOffset.TryParse(await Meta("retrieved_at").ConfigureAwait(false), CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var dt))
        {
            retrieved = dt;
        }

        return new ReferenceDbInfo(
            schema,
            await Meta("source_name").ConfigureAwait(false) ?? "LOLDrivers",
            await Meta("source_url").ConfigureAwait(false),
            await Meta("license").ConfigureAwait(false),
            retrieved,
            await Meta("content_hash").ConfigureAwait(false),
            _databasePath);
    }

    public async ValueTask DisposeAsync()
    {
        if (_connection is not null)
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
            _connection = null;
        }

        _gate.Dispose();
    }
}

public static class LolDriversImporter
{
    public const long MaxInputBytes = 50 * 1024 * 1024;

    public static async Task ImportAsync(
        string jsonPath,
        string outputDbPath,
        CancellationToken cancellationToken = default)
    {
        var fileInfo = new FileInfo(jsonPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("LOLDrivers JSON not found", jsonPath);
        }

        if (fileInfo.Length > MaxInputBytes)
        {
            throw new InvalidOperationException($"LOLDrivers JSON exceeds max size ({MaxInputBytes} bytes).");
        }

        var bytes = await File.ReadAllBytesAsync(jsonPath, cancellationToken).ConfigureAwait(false);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

        using var doc = JsonDocument.Parse(bytes);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("LOLDrivers JSON root must be an array.");
        }

        var directory = Path.GetDirectoryName(outputDbPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = outputDbPath + ".tmp";
        if (File.Exists(tempPath))
        {
            File.Delete(tempPath);
        }

        await using (var connection = new SqliteConnection($"Data Source={tempPath};Pooling=False"))
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText =
                    """
                    PRAGMA journal_mode=OFF;
                    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE drivers(
                      id TEXT PRIMARY KEY,
                      title TEXT,
                      category TEXT);
                    CREATE TABLE samples(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      driver_id TEXT NOT NULL,
                      filename TEXT,
                      sha256 TEXT,
                      FOREIGN KEY(driver_id) REFERENCES drivers(id));
                    CREATE INDEX idx_samples_sha ON samples(sha256);
                    CREATE INDEX idx_samples_name ON samples(filename);
                    """;
                await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var sampleCount = 0;

            foreach (var entry in doc.RootElement.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var id = GetString(entry, "Id") ?? GetString(entry, "id") ?? Guid.NewGuid().ToString("N");
                var title = GetString(entry, "Tags") ?? GetString(entry, "title") ?? GetString(entry, "Description") ?? id;
                if (entry.TryGetProperty("Tags", out var tags) && tags.ValueKind == JsonValueKind.Array && tags.GetArrayLength() > 0)
                {
                    title = tags[0].GetString() ?? title;
                }

                var category = GetString(entry, "Category") ?? GetString(entry, "category");

                await using (var insertDriver = connection.CreateCommand())
                {
                    insertDriver.Transaction = (SqliteTransaction)tx;
                    insertDriver.CommandText = "INSERT OR REPLACE INTO drivers(id, title, category) VALUES ($id,$t,$c)";
                    insertDriver.Parameters.AddWithValue("$id", id);
                    insertDriver.Parameters.AddWithValue("$t", (object?)title ?? DBNull.Value);
                    insertDriver.Parameters.AddWithValue("$c", (object?)category ?? DBNull.Value);
                    await insertDriver.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                if (entry.TryGetProperty("KnownVulnerableSamples", out var samples) &&
                    samples.ValueKind == JsonValueKind.Array)
                {
                    foreach (var sample in samples.EnumerateArray())
                    {
                        var fileName = GetString(sample, "Filename") ?? GetString(sample, "filename");
                        var sha = GetString(sample, "SHA256") ?? GetString(sample, "sha256");
                        if (string.IsNullOrWhiteSpace(fileName) && string.IsNullOrWhiteSpace(sha))
                        {
                            continue;
                        }

                        await InsertSampleAsync(connection, (SqliteTransaction)tx, id, fileName, sha?.ToLowerInvariant(), cancellationToken)
                            .ConfigureAwait(false);
                        sampleCount++;
                    }
                }
                else if (entry.TryGetProperty("samples", out var simpleSamples) &&
                         simpleSamples.ValueKind == JsonValueKind.Array)
                {
                    foreach (var sample in simpleSamples.EnumerateArray())
                    {
                        var fileName = GetString(sample, "filename") ?? GetString(sample, "Filename");
                        var sha = GetString(sample, "sha256") ?? GetString(sample, "SHA256");
                        await InsertSampleAsync(connection, (SqliteTransaction)tx, id, fileName, sha?.ToLowerInvariant(), cancellationToken)
                            .ConfigureAwait(false);
                        sampleCount++;
                    }
                }
            }

            await SetMetaAsync(connection, (SqliteTransaction)tx, "schema_version", IronTraceVersions.LolDriversDbSchema.ToString(CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "source_name", "LOLDrivers", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "source_url", "https://www.loldrivers.io/", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "license", "Apache-2.0", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "retrieved_at", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "content_hash", hash, cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "sample_count", sampleCount.ToString(CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            await connection.CloseAsync().ConfigureAwait(false);
        }

        SqliteConnection.ClearAllPools();

        if (File.Exists(outputDbPath))
        {
            var bak = outputDbPath + ".bak";
            if (File.Exists(bak))
            {
                File.Delete(bak);
            }

            File.Move(outputDbPath, bak);
        }

        File.Move(tempPath, outputDbPath);
    }

    private static string? GetString(JsonElement element, string name)
        => element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;

    private static async Task InsertSampleAsync(
        SqliteConnection c, SqliteTransaction tx, string driverId, string? fileName, string? sha, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO samples(driver_id, filename, sha256) VALUES ($d,$f,$s)";
        cmd.Parameters.AddWithValue("$d", driverId);
        cmd.Parameters.AddWithValue("$f", (object?)fileName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$s", (object?)sha ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task SetMetaAsync(SqliteConnection c, SqliteTransaction tx, string key, string value, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO meta(key, value) VALUES ($k,$v)";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}

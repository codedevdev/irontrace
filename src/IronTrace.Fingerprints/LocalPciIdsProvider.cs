using System.Globalization;
using System.Text;
using IronTrace.Contracts;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Contracts.Reference;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace IronTrace.Fingerprints;

public sealed class LocalPciIdsProvider : IHardwareReferenceProvider, IAsyncDisposable
{
    private readonly string _databasePath;
    private readonly ILogger<LocalPciIdsProvider> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqliteConnection? _connection;
    private ReferenceDbInfo? _info;

    public LocalPciIdsProvider(string databasePath, ILogger<LocalPciIdsProvider> logger)
    {
        _databasePath = databasePath;
        _logger = logger;
        Name = "LocalPciIdsProvider";
    }

    public string Name { get; }

    public async Task<ResolvedIdentity?> ResolveAsync(PciDeviceIdentity identity, CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        if (_connection is null)
        {
            return null;
        }

        var vendor = await FindVendorNameAsync(identity.VendorId, cancellationToken).ConfigureAwait(false);
        var device = await FindDeviceNameAsync(identity.VendorId, identity.DeviceId, cancellationToken).ConfigureAwait(false);
        string? subsystem = null;
        if (identity.SubsystemVendorId is ushort sv && identity.SubsystemDeviceId is ushort sd)
        {
            subsystem = await FindSubsystemNameAsync(identity.VendorId, identity.DeviceId, sv, sd, cancellationToken)
                .ConfigureAwait(false);
        }

        string? className = null;
        if (identity.ClassCode is byte cc)
        {
            className = await FindClassNameAsync(cc, identity.Subclass, identity.ProgrammingInterface, cancellationToken)
                .ConfigureAwait(false);
        }

        if (vendor is null && device is null && subsystem is null && className is null)
        {
            return null;
        }

        return new ResolvedIdentity(
            vendor,
            device,
            subsystem,
            className,
            Source: "pci.ids",
            RetrievedAt: _info?.RetrievedAt,
            Confidence: FindingConfidence.ReferenceIdentity);
    }

    public async Task<string?> FindVendorNameAsync(ushort vendorId, CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        return await ScalarAsync(
            "SELECT name FROM vendors WHERE vendor_id = $id",
            ("$id", (long)vendorId),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> FindDeviceNameAsync(ushort vendorId, ushort deviceId, CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        return await ScalarAsync(
            "SELECT name FROM devices WHERE vendor_id = $v AND device_id = $d",
            ("$v", (long)vendorId),
            ("$d", (long)deviceId),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> FindSubsystemNameAsync(
        ushort vendorId,
        ushort deviceId,
        ushort subsystemVendorId,
        ushort subsystemDeviceId,
        CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        return await ScalarAsync(
            """
            SELECT name FROM subsystems
            WHERE vendor_id = $v AND device_id = $d AND subvendor_id = $sv AND subdevice_id = $sd
            """,
            ("$v", (long)vendorId),
            ("$d", (long)deviceId),
            ("$sv", (long)subsystemVendorId),
            ("$sd", (long)subsystemDeviceId),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> FindClassNameAsync(
        byte classCode,
        byte? subclass,
        byte? programmingInterface,
        CancellationToken cancellationToken)
    {
        await EnsureOpenAsync(cancellationToken).ConfigureAwait(false);
        if (subclass is null)
        {
            return await ScalarAsync(
                "SELECT name FROM classes WHERE class_code = $c AND subclass IS NULL AND prog_if IS NULL",
                ("$c", (long)classCode),
                cancellationToken).ConfigureAwait(false);
        }

        if (programmingInterface is null)
        {
            return await ScalarAsync(
                "SELECT name FROM classes WHERE class_code = $c AND subclass = $s AND prog_if IS NULL",
                ("$c", (long)classCode),
                ("$s", (long)subclass.Value),
                cancellationToken).ConfigureAwait(false);
        }

        return await ScalarAsync(
            "SELECT name FROM classes WHERE class_code = $c AND subclass = $s AND prog_if = $p",
            ("$c", (long)classCode),
            ("$s", (long)subclass.Value),
            ("$p", (long)programmingInterface.Value),
            cancellationToken).ConfigureAwait(false);
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
                _logger.LogWarning("Reference database not found at {Path}", _databasePath);
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
            : IronTraceVersions.ReferenceDbSchema;
        DateTimeOffset? retrieved = null;
        if (DateTimeOffset.TryParse(await Meta("retrieved_at").ConfigureAwait(false), CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var dt))
        {
            retrieved = dt;
        }

        return new ReferenceDbInfo(
            schema,
            await Meta("source_name").ConfigureAwait(false) ?? "pci.ids",
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

    private async Task<string?> ScalarAsync(
        string sql,
        (string Name, long Value) p1,
        (string Name, long Value) p2,
        (string Name, long Value) p3,
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
        cmd.Parameters.AddWithValue(p3.Name, p3.Value);
        var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result?.ToString();
    }

    private async Task<string?> ScalarAsync(
        string sql,
        (string Name, long Value) p1,
        (string Name, long Value) p2,
        (string Name, long Value) p3,
        (string Name, long Value) p4,
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
        cmd.Parameters.AddWithValue(p3.Name, p3.Value);
        cmd.Parameters.AddWithValue(p4.Name, p4.Value);
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

public static class PciIdsImporter
{
    public const long MaxInputBytes = 20 * 1024 * 1024;

    public static async Task ImportAsync(
        string pciIdsPath,
        string outputDbPath,
        CancellationToken cancellationToken = default)
    {
        var fileInfo = new FileInfo(pciIdsPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("pci.ids not found", pciIdsPath);
        }

        if (fileInfo.Length > MaxInputBytes)
        {
            throw new InvalidOperationException($"pci.ids exceeds max size ({MaxInputBytes} bytes).");
        }

        var bytes = await File.ReadAllBytesAsync(pciIdsPath, cancellationToken).ConfigureAwait(false);
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
                    CREATE TABLE devices(
                      vendor_id INTEGER NOT NULL,
                      device_id INTEGER NOT NULL,
                      name TEXT NOT NULL,
                      PRIMARY KEY(vendor_id, device_id));
                    CREATE TABLE subsystems(
                      vendor_id INTEGER NOT NULL,
                      device_id INTEGER NOT NULL,
                      subvendor_id INTEGER NOT NULL,
                      subdevice_id INTEGER NOT NULL,
                      name TEXT NOT NULL,
                      PRIMARY KEY(vendor_id, device_id, subvendor_id, subdevice_id));
                    CREATE TABLE classes(
                      class_code INTEGER NOT NULL,
                      subclass INTEGER NULL,
                      prog_if INTEGER NULL,
                      name TEXT NOT NULL);
                    CREATE INDEX idx_classes ON classes(class_code, subclass, prog_if);
                    """;
                await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            ushort? currentVendor = null;
            ushort? currentDevice = null;
            byte? currentClass = null;
            byte? currentSubclass = null;
            var inClassSection = false;

            foreach (var rawLine in text.Split('\n'))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = rawLine.TrimEnd('\r');
                if (line.Length == 0 || line[0] == '#')
                {
                    continue;
                }

                if (line.StartsWith("C ", StringComparison.Ordinal))
                {
                    inClassSection = true;
                    currentVendor = null;
                    currentDevice = null;
                    // C cc  Name
                    var parts = SplitIdName(line.AsSpan(2));
                    currentClass = byte.Parse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    currentSubclass = null;
                    await InsertClassAsync(connection, (SqliteTransaction)tx, currentClass.Value, null, null, parts.Name, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                if (inClassSection)
                {
                    if (line.StartsWith("\t\t", StringComparison.Ordinal))
                    {
                        var parts = SplitIdName(line.AsSpan(2));
                        var prog = byte.Parse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                        await InsertClassAsync(connection, (SqliteTransaction)tx, currentClass!.Value, currentSubclass, prog, parts.Name, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    else if (line.StartsWith('\t'))
                    {
                        var parts = SplitIdName(line.AsSpan(1));
                        currentSubclass = byte.Parse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                        await InsertClassAsync(connection, (SqliteTransaction)tx, currentClass!.Value, currentSubclass, null, parts.Name, cancellationToken)
                            .ConfigureAwait(false);
                    }

                    continue;
                }

                if (line.StartsWith("\t\t", StringComparison.Ordinal))
                {
                    // subsystem: \t\tsubvendor subdevice  Name
                    var span = line.AsSpan(2).Trim();
                    var firstSpace = span.IndexOf(' ');
                    if (firstSpace <= 0 || currentVendor is null || currentDevice is null)
                    {
                        continue;
                    }

                    var subVen = ushort.Parse(span[..firstSpace], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    span = span[(firstSpace + 1)..].TrimStart();
                    var secondSpace = span.IndexOf(' ');
                    if (secondSpace <= 0)
                    {
                        continue;
                    }

                    var subDev = ushort.Parse(span[..secondSpace], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    var name = span[(secondSpace + 1)..].Trim().ToString();
                    await InsertSubsystemAsync(connection, (SqliteTransaction)tx, currentVendor.Value, currentDevice.Value, subVen, subDev, name, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                if (line.StartsWith('\t'))
                {
                    var parts = SplitIdName(line.AsSpan(1));
                    currentDevice = ushort.Parse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    await InsertDeviceAsync(connection, (SqliteTransaction)tx, currentVendor!.Value, currentDevice.Value, parts.Name, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                // vendor line
                {
                    var parts = SplitIdName(line);
                    currentVendor = ushort.Parse(parts.Id, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    currentDevice = null;
                    await InsertVendorAsync(connection, (SqliteTransaction)tx, currentVendor.Value, parts.Name, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            await SetMetaAsync(connection, (SqliteTransaction)tx, "schema_version", IronTraceVersions.ReferenceDbSchema.ToString(CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "source_name", "pci.ids", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "source_url", "https://pci-ids.ucw.cz/", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "license", "BSD-3-Clause", cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "retrieved_at", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture), cancellationToken).ConfigureAwait(false);
            await SetMetaAsync(connection, (SqliteTransaction)tx, "content_hash", hash, cancellationToken).ConfigureAwait(false);
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

    private static async Task InsertDeviceAsync(SqliteConnection c, SqliteTransaction tx, ushort v, ushort d, string name, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO devices(vendor_id, device_id, name) VALUES ($v,$d,$name)";
        cmd.Parameters.AddWithValue("$v", (long)v);
        cmd.Parameters.AddWithValue("$d", (long)d);
        cmd.Parameters.AddWithValue("$name", name);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task InsertSubsystemAsync(
        SqliteConnection c, SqliteTransaction tx, ushort v, ushort d, ushort sv, ushort sd, string name, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            "INSERT OR REPLACE INTO subsystems(vendor_id, device_id, subvendor_id, subdevice_id, name) VALUES ($v,$d,$sv,$sd,$name)";
        cmd.Parameters.AddWithValue("$v", (long)v);
        cmd.Parameters.AddWithValue("$d", (long)d);
        cmd.Parameters.AddWithValue("$sv", (long)sv);
        cmd.Parameters.AddWithValue("$sd", (long)sd);
        cmd.Parameters.AddWithValue("$name", name);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task InsertClassAsync(
        SqliteConnection c, SqliteTransaction tx, byte cc, byte? sc, byte? pi, string name, CancellationToken ct)
    {
        await using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO classes(class_code, subclass, prog_if, name) VALUES ($c,$s,$p,$name)";
        cmd.Parameters.AddWithValue("$c", (long)cc);
        cmd.Parameters.AddWithValue("$s", sc is null ? DBNull.Value : (long)sc.Value);
        cmd.Parameters.AddWithValue("$p", pi is null ? DBNull.Value : (long)pi.Value);
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

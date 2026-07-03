using Microsoft.Data.Sqlite;
using UsbSentinel.Contracts;
using SentinelLogLevel = UsbSentinel.Contracts.LogLevel;

namespace UsbSentinel.Service;

public sealed class LogRepository
{
    private readonly string _connectionString;

    public LogRepository()
    {
        var dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "USB Sentinel Pro");
        Directory.CreateDirectory(dataDirectory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataDirectory, "sentinel.db"),
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString();
        Initialize();
    }

    private void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS Logs (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp TEXT NOT NULL,
                Level TEXT NOT NULL,
                EventType TEXT NOT NULL,
                Message TEXT NOT NULL,
                Drive TEXT NULL,
                Result TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Logs_Timestamp ON Logs(Timestamp DESC);
            CREATE TABLE IF NOT EXISTS Settings (
                Key TEXT PRIMARY KEY,
                Value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS SecuritySecrets (
                Name TEXT PRIMARY KEY,
                Salt BLOB NOT NULL,
                Hash BLOB NOT NULL,
                Iterations INTEGER NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }

    public LogEntry Add(SentinelLogLevel level, string eventType, string message, string? drive = null, string? result = null)
    {
        var timestamp = DateTimeOffset.UtcNow;
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO Logs(Timestamp, Level, EventType, Message, Drive, Result)
            VALUES($timestamp, $level, $eventType, $message, $drive, $result);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$timestamp", timestamp.ToString("O"));
        command.Parameters.AddWithValue("$level", level.ToString());
        command.Parameters.AddWithValue("$eventType", eventType);
        command.Parameters.AddWithValue("$message", message);
        command.Parameters.AddWithValue("$drive", (object?)drive ?? DBNull.Value);
        command.Parameters.AddWithValue("$result", (object?)result ?? DBNull.Value);
        var id = (long)(command.ExecuteScalar() ?? 0L);
        return new LogEntry(id, timestamp, level, eventType, message, drive, result);
    }

    public IReadOnlyList<LogEntry> GetRecent(int count = 200)
    {
        var entries = new List<LogEntry>();
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT Id, Timestamp, Level, EventType, Message, Drive, Result
            FROM Logs ORDER BY Id DESC LIMIT $count;
            """;
        command.Parameters.AddWithValue("$count", Math.Clamp(count, 1, 1000));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            entries.Add(new LogEntry(
                reader.GetInt64(0),
                DateTimeOffset.Parse(reader.GetString(1)),
                Enum.Parse<SentinelLogLevel>(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6)));
        }
        entries.Reverse();
        return entries;
    }

    internal string ConnectionString => _connectionString;
}

public sealed class SettingsRepository(LogRepository logs)
{
    public SentinelSettings Load()
    {
        using var connection = new SqliteConnection(logs.ConnectionString);
        connection.Open();
        var values = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Key, Value FROM Settings;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
            values[reader.GetString(0)] = bool.TryParse(reader.GetString(1), out var value) && value;

        return new SentinelSettings(
            values.GetValueOrDefault(nameof(SentinelSettings.AutoDisableOnDisconnect), true),
            values.GetValueOrDefault(nameof(SentinelSettings.VoiceAlerts), true),
            values.GetValueOrDefault(nameof(SentinelSettings.BlockAllUsbDevices), false),
            values.GetValueOrDefault(nameof(SentinelSettings.WarnBeforeRemediation), true));
    }

    public void Save(SentinelSettings settings)
    {
        using var connection = new SqliteConnection(logs.ConnectionString);
        connection.Open();
        using var transaction = connection.BeginTransaction();
        foreach (var property in typeof(SentinelSettings).GetProperties().Where(p => p.CanWrite || p.Name != nameof(SentinelSettings.ScanBeforeEnable)))
        {
            if (property.PropertyType != typeof(bool) || property.Name == nameof(SentinelSettings.ScanBeforeEnable))
                continue;
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                "INSERT INTO Settings(Key, Value) VALUES($key, $value) ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;";
            command.Parameters.AddWithValue("$key", property.Name);
            command.Parameters.AddWithValue("$value", property.GetValue(settings)?.ToString() ?? "False");
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }
}

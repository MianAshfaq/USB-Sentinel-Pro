using System.Text.Json;
using System.Text.Json.Serialization;

namespace UsbSentinel.Contracts;

public static class SentinelProtocol
{
    public const string PipeName = "UsbSentinelPro";
    public const int Version = 4;
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };
}

public enum UsbState
{
    Disabled,
    Enabling,
    WaitingForDevice,
    Scanning,
    Enabled,
    ThreatFound,
    Failed
}

public enum CommandType
{
    GetSnapshot,
    EnableUsb,
    DisableUsb,
    UpdateSettings,
    GetRecentLogs,
    SetPassword,
    ChangePassword,
    ResetPassword,
    RemediateThreats,
    FormatUsb
}

public enum EventType
{
    Snapshot,
    StateChanged,
    Log,
    ScanProgress,
    Error,
    PasswordConfigured,
    HistoricalLog
}

public enum LogLevel
{
    Information,
    Warning,
    Error,
    Security
}

public sealed record SentinelSettings(
    bool AutoDisableOnDisconnect = true,
    bool VoiceAlerts = true,
    bool BlockAllUsbDevices = false,
    bool WarnBeforeRemediation = true)
{
    public bool ScanBeforeEnable => true;
}

public sealed record ServiceSnapshot(
    UsbState State,
    bool StorageBlocked,
    int ScanProgress,
    string StatusText,
    IReadOnlyList<string> ConnectedDrives,
    SentinelSettings Settings,
    DateTimeOffset UpdatedAt,
    bool PasswordConfigured = false,
    bool DefenderAvailable = false,
    string DefenderSignatureVersion = "Unknown",
    IReadOnlyList<UsbDeviceInfo>? DetectedDevices = null);

public sealed record UsbDeviceInfo(string Id, string Name, string Status);

public sealed record PipeCommand(
    int ProtocolVersion,
    CommandType Type,
    SentinelSettings? Settings = null,
    string? Password = null,
    string? NewPassword = null,
    string? Drive = null,
    string? Confirmation = null,
    bool QuickFormat = true,
    string FileSystem = "exFAT",
    string? UserSid = null);

public sealed record PipeEvent(
    int ProtocolVersion,
    EventType Type,
    ServiceSnapshot? Snapshot = null,
    LogEntry? Log = null,
    int? Progress = null,
    string? Message = null);

public sealed record LogEntry(
    long Id,
    DateTimeOffset Timestamp,
    LogLevel Level,
    string EventType,
    string Message,
    string? Drive = null,
    string? Result = null);

public sealed record DefenderScanResult(
    string Drive,
    bool Succeeded,
    bool ThreatFound,
    bool RemediationAttempted,
    bool RemediationSucceeded,
    int ExitCode,
    string Summary);

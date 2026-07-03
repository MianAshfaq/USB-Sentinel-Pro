using UsbSentinel.Contracts;
using LogLevel = UsbSentinel.Contracts.LogLevel;

namespace UsbSentinel.Service;

public sealed class SentinelCoordinator(
    UsbPolicyController policy,
    DefenderScanner defender,
    LogRepository logs,
    SettingsRepository settingsRepository,
    PasswordRepository passwords,
    UsbDriveInventory inventory)
{
    private readonly SemaphoreSlim _operationLock = new(1, 1);
    private readonly object _stateLock = new();
    private readonly object _deviceLock = new();
    private HashSet<string> _knownUsbVolumes = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _suppressVolumeEventsUntil;
    private CancellationTokenSource? _operationCancellation;
    private SentinelSettings _settings = settingsRepository.Load();
    private ServiceSnapshot _snapshot = new(
        UsbState.Disabled, true, 0, "USB storage is disabled.",
        Array.Empty<string>(), settingsRepository.Load(), DateTimeOffset.UtcNow, passwords.IsConfigured,
        defender.IsAvailable, defender.SignatureVersion);

    public event EventHandler<PipeEvent>? EventPublished;

    public ServiceSnapshot Snapshot
    {
        get
        {
            lock (_stateLock)
                return _snapshot with
                {
                    PasswordConfigured = passwords.IsConfigured,
                    DefenderAvailable = defender.IsAvailable,
                    DefenderSignatureVersion = defender.SignatureVersion
                };
        }
    }

    public IReadOnlyList<LogEntry> RecentLogs => logs.GetRecent();

    public void InitializeFailClosed()
    {
        BlockStorage();
        policy.SetBlockAllUsb(_settings.BlockAllUsbDevices);
        SetState(UsbState.Disabled, "USB storage is disabled.", 0, Array.Empty<string>());
        PublishLog(LogLevel.Security, "ServiceStarted", "Service started with USB storage blocked.");
    }

    public async Task EnableAsync(CancellationToken cancellationToken)
    {
        if (!await _operationLock.WaitAsync(0, cancellationToken))
        {
            PublishLog(LogLevel.Warning, "CommandRejected", "Another USB operation is already running.");
            return;
        }

        _operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _operationCancellation.Token;
        try
        {
            SetState(UsbState.Enabling, "Temporarily enabling storage for inspection.", 2, Array.Empty<string>());
            PublishLog(LogLevel.Security, "EnableRequested", "Administrator requested controlled USB enable.");
            policy.AllowStorageForScan();

            var drives = await WaitForRemovableDrivesAsync(TimeSpan.FromSeconds(20), token);
            if (drives.Count == 0)
            {
                BlockStorage();
                SetState(UsbState.Disabled, "No removable drive detected. USB storage remains disabled.", 0, drives);
                PublishLog(LogLevel.Warning, "NoDevice", "No removable drive was detected.");
                return;
            }

            SetState(UsbState.Scanning, "Updating Defender signatures.", 5, drives);
            await defender.UpdateSignaturesAsync(message => PublishLog(LogLevel.Information, "Defender", message), token);

            for (var index = 0; index < drives.Count; index++)
            {
                var drive = drives[index];
                SetState(UsbState.Scanning, $"Scanning {drive}", 10, drives);
                PublishLog(LogLevel.Information, "ScanStarted", $"Scanning started for {drive}", drive);
                var result = await defender.ScanAsync(
                    drive,
                    message => PublishLog(LogLevel.Information, "Defender", message, drive),
                    value =>
                    {
                        var overall = (index * 100 + value) / drives.Count;
                        SetState(UsbState.Scanning, $"Scanning {drive}", overall, drives);
                    },
                    token);

                if (!result.Succeeded || result.ThreatFound)
                {
                    BlockStorage();
                    var state = result.ThreatFound ? UsbState.ThreatFound : UsbState.Failed;
                    SetState(state, result.Summary + " USB storage is blocked.", 100, drives);
                    PublishLog(
                        result.ThreatFound ? LogLevel.Security : LogLevel.Error,
                        result.ThreatFound ? "ThreatFound" : "ScanFailed",
                        result.Summary,
                        drive,
                        result.RemediationSucceeded ? "Removed/Quarantined" : "Blocked");
                    return;
                }

                PublishLog(LogLevel.Security, "ScanClean", $"{drive} passed Microsoft Defender scan.", drive, "Clean");
            }

            SetState(UsbState.Enabled, "USB is clean. Access enabled.", 100, drives);
            PublishLog(LogLevel.Security, "AccessGranted", "All detected removable drives are clean.", result: "Clean");
        }
        catch (OperationCanceledException)
        {
            BlockStorage();
            SetState(UsbState.Disabled, "Operation cancelled. USB storage is disabled.", 0, Array.Empty<string>());
            PublishLog(LogLevel.Warning, "OperationCancelled", "USB operation was cancelled.");
        }
        catch (Exception ex)
        {
            TryBlockStorage();
            SetState(UsbState.Failed, "Security operation failed. USB storage is blocked.", 0, Array.Empty<string>());
            PublishLog(LogLevel.Error, "OperationFailed", ex.Message);
        }
        finally
        {
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _operationLock.Release();
        }
    }

    public async Task DisableAsync(CancellationToken cancellationToken)
    {
        _operationCancellation?.Cancel();
        await _operationLock.WaitAsync(cancellationToken);
        try
        {
            BlockStorage();
            SetState(UsbState.Disabled, "USB storage is disabled.", 0, Array.Empty<string>());
            PublishLog(LogLevel.Security, "Disabled", "USB storage was disabled by administrator.");
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public void OnVolumeRemoved()
    {
        var drives = GetUsbDrives();
        bool removed;
        bool suppressed;
        lock (_deviceLock)
        {
            removed = _knownUsbVolumes.Except(drives, StringComparer.OrdinalIgnoreCase).Any();
            _knownUsbVolumes = drives.ToHashSet(StringComparer.OrdinalIgnoreCase);
            suppressed = DateTimeOffset.UtcNow <= _suppressVolumeEventsUntil;
        }
        if (!removed || suppressed || !_settings.AutoDisableOnDisconnect)
            return;
        _operationCancellation?.Cancel();
        TryBlockStorage();
        SetState(UsbState.Disabled, "USB disconnected. USB storage is disabled.", 0, drives);
        PublishLog(LogLevel.Security, "DeviceRemoved", "Removable device disconnected; storage was disabled.");
    }

    public void OnVolumeInserted()
    {
        var drives = GetUsbDrives();
        string[] added;
        lock (_deviceLock)
        {
            added = drives.Except(_knownUsbVolumes, StringComparer.OrdinalIgnoreCase).ToArray();
            _knownUsbVolumes = drives.ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        if (added.Length == 0)
            return;
        PublishLog(LogLevel.Information, "DeviceDetected", "USB storage device detected.", added[0]);
        var current = Snapshot;
        if (current.State == UsbState.Disabled)
            SetState(UsbState.Disabled, "USB detected. Click Enable USB to scan it.", 0, drives);
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _settings = settings with { };
        settingsRepository.Save(_settings);
        policy.SetBlockAllUsb(_settings.BlockAllUsbDevices);
        lock (_stateLock)
            _snapshot = _snapshot with { Settings = _settings, UpdatedAt = DateTimeOffset.UtcNow };
        Publish(new PipeEvent(SentinelProtocol.Version, EventType.Snapshot, Snapshot: Snapshot));
        PublishLog(LogLevel.Security, "SettingsChanged", "Security settings were updated.");
    }

    public void PasswordConfigured()
    {
        lock (_stateLock)
            _snapshot = _snapshot with { PasswordConfigured = true, UpdatedAt = DateTimeOffset.UtcNow };
        PublishLog(LogLevel.Security, "PasswordConfigured", "USB enable password was configured.");
        Publish(new PipeEvent(SentinelProtocol.Version, EventType.Snapshot, Snapshot: Snapshot));
    }

    public void RecordAuthenticationFailure(string message) =>
        PublishLog(LogLevel.Warning, "AuthenticationFailed", message);

    public void RecordSecurityEvent(string eventType, string message) =>
        PublishLog(LogLevel.Security, eventType, message);

    public async Task RemediateThreatsAsync(CancellationToken token)
    {
        if (!await _operationLock.WaitAsync(0, token))
        {
            PublishLog(LogLevel.Warning, "CommandRejected", "Another USB operation is already running.");
            return;
        }
        try
        {
            BlockStorage();
            var succeeded = await defender.RemediateThreatsAsync(
                message => PublishLog(LogLevel.Information, "Defender", message), token);
            PublishLog(succeeded ? LogLevel.Security : LogLevel.Error, "ThreatRemediation",
                succeeded ? "Microsoft Defender remediation completed." : "Microsoft Defender could not complete remediation.");
        }
        catch (Exception ex)
        {
            PublishLog(LogLevel.Error, "ThreatRemediationFailed", ex.Message);
        }
        finally { _operationLock.Release(); }
    }

    public async Task FormatUsbAsync(string drive, bool quickFormat, CancellationToken token)
    {
        var root = UsbDriveInventory.NormalizeRoot(drive);
        if (!await _operationLock.WaitAsync(0, token))
        {
            PublishLog(LogLevel.Warning, "CommandRejected", "Another USB operation is already running.");
            return;
        }
        var completed = false;
        try
        {
            policy.AllowStorageForScan();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
            while (!inventory.IsMountedUsbVolume(root) && DateTimeOffset.UtcNow < deadline)
                await Task.Delay(500, token);
            if (!inventory.IsMountedUsbVolume(root))
                throw new InvalidOperationException("The selected drive is not a mounted USB storage volume.");

            SetState(UsbState.Enabling, $"Formatting {root}", 10, [root]);
            PublishLog(LogLevel.Security, "FormatStarted", $"Administrator approved formatting {root}.", root);
            var letter = char.ToUpperInvariant(root[0]);
            var full = quickFormat ? string.Empty : " -Full";
            var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var command = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Format-Volume -DriveLetter {letter} -FileSystem exFAT -NewFileSystemLabel USB_SENTINEL -Confirm:$false -Force{full} -ErrorAction Stop\"";
            var result = await DefenderScanner.RunProcessAsync(powershell, command, token);
            if (result.ExitCode != 0)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Output) ? "Windows could not format the drive." : result.Output.Trim());
            PublishLog(LogLevel.Security, "FormatCompleted", $"{root} was formatted as exFAT.", root, "Completed");
            completed = true;
        }
        catch (Exception ex)
        {
            PublishLog(LogLevel.Error, "FormatFailed", ex.Message, root, "Failed");
        }
        finally
        {
            TryBlockStorage();
            SetState(completed ? UsbState.Disabled : UsbState.Failed,
                completed ? "Format completed. USB storage is disabled." : "Format failed. USB storage is disabled.",
                completed ? 100 : 0, [root]);
            _operationLock.Release();
        }
    }

    private async Task<IReadOnlyList<string>> WaitForRemovableDrivesAsync(TimeSpan timeout, CancellationToken token)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var drives = GetUsbDrives();
            if (drives.Count > 0)
            {
                lock (_deviceLock)
                    _knownUsbVolumes = drives.ToHashSet(StringComparer.OrdinalIgnoreCase);
                return drives;
            }
            SetState(UsbState.WaitingForDevice, "Waiting for a removable drive...", 5, drives);
            await Task.Delay(750, token);
        }
        return Array.Empty<string>();
    }

    private IReadOnlyList<string> GetUsbDrives()
    {
        try
        {
            return inventory.GetMountedUsbVolumes();
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
    }

    private void SetState(UsbState state, string status, int progress, IReadOnlyList<string> drives)
    {
        lock (_stateLock)
        {
            _snapshot = new ServiceSnapshot(
                state,
                policy.IsStorageBlocked(),
                Math.Clamp(progress, 0, 100),
                status,
                drives,
                _settings,
                DateTimeOffset.UtcNow);
        }
        Publish(new PipeEvent(SentinelProtocol.Version, EventType.StateChanged, Snapshot: Snapshot, Progress: progress));
    }

    private void PublishLog(LogLevel level, string eventType, string message, string? drive = null, string? result = null)
    {
        var entry = logs.Add(level, eventType, message, drive, result);
        Publish(new PipeEvent(SentinelProtocol.Version, EventType.Log, Log: entry, Message: message));
    }

    private void Publish(PipeEvent pipeEvent) => EventPublished?.Invoke(this, pipeEvent);

    private void TryBlockStorage()
    {
        try { BlockStorage(); }
        catch (Exception ex) { PublishLog(LogLevel.Error, "FailClosedError", ex.Message); }
    }

    private void BlockStorage()
    {
        lock (_deviceLock)
            _suppressVolumeEventsUntil = DateTimeOffset.UtcNow.AddSeconds(4);
        policy.BlockStorage();
    }
}

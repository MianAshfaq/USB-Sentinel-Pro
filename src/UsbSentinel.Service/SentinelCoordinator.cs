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
    private HashSet<string> _knownUsbDevices = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _suppressVolumeEventsUntil;
    private DateTimeOffset _suppressHardwareEventsUntil;
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
        _knownUsbDevices = inventory.GetConnectedUsbStorageDevices().Select(device => device.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        SetState(UsbState.Disabled, "USB storage is disabled.", 0, Array.Empty<string>());
        PublishLog(LogLevel.Security, "ServiceStarted", "Service started with USB storage blocked.");
    }

    public async Task EnableAsync(string? userSid, CancellationToken cancellationToken)
    {
        if (!await _operationLock.WaitAsync(0, cancellationToken))
        {
            if (Snapshot.State is UsbState.Enabling or UsbState.Scanning or UsbState.WaitingForDevice)
            {
                PublishLog(LogLevel.Warning, "CommandRejected", "Another USB operation is already running.");
                return;
            }

            PublishLog(LogLevel.Information, "CommandQueued", "Waiting for background security maintenance to finish.");
            if (!await _operationLock.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken))
            {
                PublishLog(LogLevel.Warning, "CommandRejected", "USB enable could not start because maintenance is still running. Please try again.");
                return;
            }
        }

        _operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _operationCancellation.Token;
        try
        {
            SetState(UsbState.Enabling, "Temporarily enabling storage for inspection.", 2, Array.Empty<string>());
            PublishLog(LogLevel.Security, "EnableRequested", "Administrator requested controlled USB enable.");
            policy.AllowStorageForScan();

            var drives = await WaitForRemovableDrivesAsync(TimeSpan.FromSeconds(45), token);
            if (drives.Count == 0)
            {
                BlockStorage();
                SetState(UsbState.Disabled, "No removable drive detected. USB storage remains disabled.", 0, drives);
                PublishLog(LogLevel.Warning, "NoDevice", "No removable drive was detected.");
                return;
            }

            var inaccessibleBeforeScan = drives.Where(drive => !inventory.IsAccessibleDriveRoot(drive)).ToArray();
            if (inaccessibleBeforeScan.Length > 0)
            {
                TryBlockStorage();
                SetState(UsbState.Failed, "Windows mounted the USB drive letter but denied filesystem access. USB storage remains blocked.", 0, drives);
                PublishLog(LogLevel.Error, "AccessVerificationFailed",
                    $"USB drive letters are not readable before scan: {string.Join(", ", inaccessibleBeforeScan)}.",
                    result: "Access denied");
                return;
            }

            SetState(UsbState.Scanning, "Updating Defender signatures.", 5, drives);
            var signaturesUpdated = true;
            if (defender.SignaturesRecentlyUpdated)
                PublishLog(LogLevel.Information, "Defender", "Using recently updated Defender signatures for a faster scan start.");
            else
                signaturesUpdated = await defender.UpdateSignaturesAsync(message => PublishLog(LogLevel.Information, "Defender", message), token);
            if (!signaturesUpdated)
            {
                var signatureAge = await defender.GetSignatureAgeAsync(token);
                if (signatureAge is null || signatureAge > TimeSpan.FromDays(7))
                {
                    BlockStorage();
                    var ageText = signatureAge is null ? "unknown" : $"{signatureAge.Value.TotalDays:0.0} days";
                    SetState(UsbState.Failed, "Defender signatures are too old or could not be verified. USB storage is blocked.", 0, drives);
                    PublishLog(LogLevel.Error, "StaleSignatures", $"Defender signature age is {ageText}; access was denied.");
                    return;
                }
            }

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
                    if (result.ThreatFound)
                    {
                        var details = await defender.GetRecentThreatDetailsAsync(token);
                        PublishLog(LogLevel.Security, "ThreatDetails", details, drive, "Defender confirmed");
                    }
                    return;
                }

                PublishLog(LogLevel.Security, "ScanClean", $"{drive} passed Microsoft Defender scan.", drive, "Clean");
            }

            if (!string.IsNullOrWhiteSpace(userSid))
            {
                var accessGranted = true;
                foreach (var drive in drives)
                    accessGranted &= await GrantRequesterAccessAsync(drive, userSid, token);
                if (!accessGranted)
                {
                    TryBlockStorage();
                    SetState(UsbState.Failed, "USB scan passed, but Windows user access could not be granted. USB storage remains blocked.", 100, drives);
                    PublishLog(LogLevel.Error, "AccessGrantRequired",
                        "USB access was not enabled because Windows ACL repair failed.",
                        result: "Access denied");
                    return;
                }

                SetState(UsbState.Enabling, "Scan passed. Finalizing USB access.", 99, drives);
                drives = await RefreshUsbDeviceAccessAsync(drives, token);
            }

            var inaccessible = drives.Where(drive => !inventory.IsAccessibleDriveRoot(drive)).ToArray();
            if (inaccessible.Length > 0)
            {
                TryBlockStorage();
                SetState(UsbState.Failed, "Windows still denies access to one or more USB volumes. USB storage remains blocked.", 100, GetUsbDrives());
                PublishLog(LogLevel.Error, "AccessVerificationFailed",
                    $"Windows did not expose accessible filesystem roots after scan: {string.Join(", ", inaccessible)}.",
                    result: "Access denied");
                return;
            }

            SetState(UsbState.Enabled, "Defender verification passed. USB access enabled.", 100, drives);
            PublishLog(LogLevel.Security, "AccessGranted", "All detected USB storage passed the configured Defender verification.", result: "Verified");
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
        if (Snapshot.State is UsbState.Disabled or UsbState.Failed or UsbState.ThreatFound)
            return;
        var drives = GetUsbDrives();
        bool removed;
        bool suppressed;
        lock (_deviceLock)
        {
            suppressed = DateTimeOffset.UtcNow <= _suppressVolumeEventsUntil;
            removed = _knownUsbVolumes.Except(drives, StringComparer.OrdinalIgnoreCase).Any();
            if (!suppressed)
                _knownUsbVolumes = drives.ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        if (suppressed)
        {
            PublishLog(LogLevel.Information, "DeviceEventSuppressed",
                "Ignoring temporary USB remove event during controlled device refresh.");
            return;
        }
        if (!removed || !_settings.AutoDisableOnDisconnect)
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
        bool suppressed;
        lock (_deviceLock)
        {
            suppressed = DateTimeOffset.UtcNow <= _suppressVolumeEventsUntil;
            added = drives.Except(_knownUsbVolumes, StringComparer.OrdinalIgnoreCase).ToArray();
            _knownUsbVolumes = drives.ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        if (added.Length == 0)
            return;
        if (suppressed)
        {
            PublishLog(LogLevel.Information, "DeviceEventSuppressed",
                "USB volume returned after controlled device refresh.", added[0]);
            return;
        }
        PublishLog(LogLevel.Information, "VolumeMounted", "USB storage volume mounted for inspection.", added[0]);
        var current = Snapshot;
        if (current.State == UsbState.Disabled)
            SetState(UsbState.Disabled, "USB detected. Click Enable USB to scan it.", 0, drives);
    }

    public void OnHardwareChanged()
    {
        try
        {
            var devices = inventory.GetConnectedUsbStorageDevices();
            var ids = devices.Select(device => device.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            string[] added;
            bool suppressed;
            lock (_deviceLock)
            {
                suppressed = DateTimeOffset.UtcNow <= _suppressHardwareEventsUntil;
                added = ids.Except(_knownUsbDevices, StringComparer.OrdinalIgnoreCase).ToArray();
                _knownUsbDevices = ids;
            }
            lock (_stateLock)
                _snapshot = _snapshot with { DetectedDevices = devices, UpdatedAt = DateTimeOffset.UtcNow };
            if (suppressed)
            {
                Publish(new PipeEvent(SentinelProtocol.Version, EventType.Snapshot, Snapshot: Snapshot));
                return;
            }
            if (added.Length > 0)
            {
                var device = devices.First(item => added.Contains(item.Id, StringComparer.OrdinalIgnoreCase));
                PublishLog(LogLevel.Information, "DeviceDetected", $"USB storage hardware detected: {device.Name}.");
                if (Snapshot.State == UsbState.Disabled)
                    SetState(UsbState.Disabled, "USB storage detected. Click Enable USB to mount and scan it.", 0, GetUsbDrives());
            }
            else
            {
                Publish(new PipeEvent(SentinelProtocol.Version, EventType.Snapshot, Snapshot: Snapshot));
            }
        }
        catch (Exception ex)
        {
            PublishLog(LogLevel.Warning, "HardwareInventoryFailed", ex.Message);
        }
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

    public async Task UpdateDefenderSignaturesInBackgroundAsync(CancellationToken token)
    {
        if (!await _operationLock.WaitAsync(0, token))
            return;
        try
        {
            var previousVersion = defender.SignatureVersion;
            var succeeded = await defender.UpdateSignaturesAsync(
                message => PublishLog(LogLevel.Information, "SignatureUpdate", message), token);
            var currentVersion = defender.SignatureVersion;
            PublishLog(succeeded ? LogLevel.Security : LogLevel.Warning, "SignatureUpdateCompleted",
                succeeded
                    ? $"Microsoft Defender security intelligence is current ({currentVersion})."
                    : $"Automatic signature update failed; installed version {previousVersion} remains active.",
                result: succeeded ? "Updated" : "Offline/Unavailable");
            Publish(new PipeEvent(SentinelProtocol.Version, EventType.Snapshot, Snapshot: Snapshot));
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            PublishLog(LogLevel.Warning, "SignatureUpdateFailed", ex.Message);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public void AuditProtectionState()
    {
        var state = Snapshot.State;
        if (state is UsbState.Enabled)
        {
            var inaccessible = Snapshot.ConnectedDrives
                .Where(drive => !inventory.IsAccessibleDriveRoot(drive))
                .ToArray();
            if (inaccessible.Length == 0)
                return;

            TryBlockStorage();
            SetState(UsbState.Failed, "Windows denied access after USB was enabled. USB storage was blocked again.", 0, GetUsbDrives());
            PublishLog(LogLevel.Error, "EnabledAccessLost",
                $"Enabled USB volume became inaccessible: {string.Join(", ", inaccessible)}.",
                result: "Access denied");
            return;
        }

        if (state is UsbState.Enabling or UsbState.Scanning or UsbState.WaitingForDevice)
            return;
        if (policy.IsStorageBlocked())
            return;
        TryBlockStorage();
        PublishLog(LogLevel.Security, "TamperDetected",
            "USB storage policy changed unexpectedly and was restored to blocked.");
        SetState(UsbState.Disabled, "Protection policy was restored after an unexpected change.", 0, GetUsbDrives());
    }

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

    public async Task FormatUsbAsync(string drive, string fileSystem, bool quickFormat, CancellationToken token)
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
            var command = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Format-Volume -DriveLetter {letter} -FileSystem {fileSystem} -NewFileSystemLabel USB_SENTINEL -Confirm:$false -Force{full} -ErrorAction Stop\"";
            var result = await DefenderScanner.RunProcessAsync(powershell, command, token);
            if (result.ExitCode != 0)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Output) ? "Windows could not format the drive." : result.Output.Trim());
            PublishLog(LogLevel.Security, "FormatCompleted", $"{root} was formatted as {fileSystem}.", root, "Completed");
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
                DateTimeOffset.UtcNow,
                PasswordConfigured: passwords.IsConfigured,
                DefenderAvailable: defender.IsAvailable,
                DefenderSignatureVersion: defender.SignatureVersion,
                DetectedDevices: inventory.GetConnectedUsbStorageDevices());
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

    private async Task<bool> GrantRequesterAccessAsync(string drive, string userSid, CancellationToken token)
    {
        try
        {
            _ = new System.Security.Principal.SecurityIdentifier(userSid);

            var root = UsbDriveInventory.NormalizeRoot(drive);
            var aclTarget = root.TrimEnd('\\') + @"\.";
            var icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");
            var result = await DefenderScanner.RunProcessAsync(
                icacls,
                $"\"{aclTarget}\" /grant \"*{userSid}:(OI)(CI)M\" /C",
                token);
            var succeeded = AccessGrantSucceeded(result.ExitCode, result.Output);
            PublishLog(succeeded ? LogLevel.Security : LogLevel.Warning,
                succeeded ? "AccessGrantApplied" : "AccessGrantFailed",
                succeeded
                    ? $"Granted the requesting Windows user access to {root}."
                    : $"Could not grant requesting user access to {root}: {result.Output.Trim()}",
                root,
                succeeded ? "Granted" : "Failed");
            return succeeded;
        }
        catch (Exception ex)
        {
            PublishLog(LogLevel.Warning, "AccessGrantFailed", ex.Message, drive, "Failed");
            return false;
        }
    }

    private async Task<IReadOnlyList<string>> RefreshUsbDeviceAccessAsync(
        IReadOnlyList<string> approvedDrives,
        CancellationToken token)
    {
        var devices = inventory.GetConnectedUsbStorageDevices()
            .Select(device => device.Id)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (devices.Length == 0)
            return approvedDrives;

        SuppressDeviceEvents(TimeSpan.FromSeconds(75));
        var pnputil = Path.Combine(Environment.SystemDirectory, "pnputil.exe");
        foreach (var deviceId in devices)
        {
            token.ThrowIfCancellationRequested();
            var result = await DefenderScanner.RunProcessAsync(
                pnputil,
                $"/restart-device \"{deviceId.Replace("\"", "\\\"")}\"",
                token);
            var succeeded = result.ExitCode == 0 &&
                result.Output.Contains("Device restarted successfully", StringComparison.OrdinalIgnoreCase);
            PublishLog(succeeded ? LogLevel.Security : LogLevel.Warning,
                succeeded ? "UsbDeviceRestarted" : "UsbDeviceRestartFailed",
                succeeded
                    ? "USB storage device access state was refreshed."
                    : $"Could not refresh USB storage device access state: {result.Output.Trim()}",
                result: succeeded ? "Restarted" : "Failed");
        }

        var deadline = DateTimeOffset.UtcNow.AddSeconds(12);
        while (DateTimeOffset.UtcNow < deadline)
        {
            token.ThrowIfCancellationRequested();
            if (approvedDrives.All(inventory.IsAccessibleDriveRoot))
                return approvedDrives;
            await Task.Delay(150, token);
        }

        // A drive letter can rarely change while Windows restarts a USB disk. Use one
        // complete inventory refresh only after the fast path has timed out.
        var rediscoveredDrives = GetUsbDrives();
        return rediscoveredDrives.Count > 0 ? rediscoveredDrives : approvedDrives;
    }

    private void SuppressDeviceEvents(TimeSpan duration)
    {
        lock (_deviceLock)
        {
            var until = DateTimeOffset.UtcNow.Add(duration);
            _suppressVolumeEventsUntil = until;
            _suppressHardwareEventsUntil = until;
        }
    }

    public static bool AccessGrantSucceeded(int exitCode, string output)
    {
        if (exitCode != 0)
            return false;
        if (output.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("The filename, directory name, or volume label syntax is incorrect", StringComparison.OrdinalIgnoreCase))
            return false;
        return !System.Text.RegularExpressions.Regex.IsMatch(
            output,
            @"Failed processing\s+[1-9]\d*\s+files",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }
}

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Speech.Synthesis;
using System.Windows.Media;
using System.Windows.Threading;
using UsbSentinel.Contracts;
using Microsoft.Win32;
using MediaBrushes = System.Windows.Media.Brushes;
using MediaColor = System.Windows.Media.Color;
using WpfSaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace UsbSentinel.Desktop;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly ServiceClient _client = new();
    private SpeechSynthesizer? _speech;
    private readonly DispatcherTimer _animationTimer;
    private readonly DispatcherTimer _reconnectTimer;
    private ServiceSnapshot? _snapshot;
    private bool _connected;
    private double _ringAngle;
    private bool _autoDisableOnDisconnect = true;
    private bool _voiceAlerts = true;
    private bool _blockAllUsbDevices;
    private bool _warnBeforeRemediation = true;
    private UsbState? _lastSpokenState;
    private string _voiceName = "Windows voice unavailable";
    private bool _connecting;
    private readonly Dictionary<string, string> _driveResults = new(StringComparer.OrdinalIgnoreCase);

    public MainViewModel(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        EnableCommand = new RelayCommand(EnableUsbAsync, () => _connected);
        DisableCommand = new RelayCommand(() => SendAsync(CommandType.DisableUsb), () => _connected);
        SaveSettingsCommand = new RelayCommand(SaveSettingsAsync, () => _connected);
        TestVoiceCommand = new RelayCommand(TestVoiceAsync);
        ChangePasswordCommand = new RelayCommand(ChangePasswordAsync, () => _connected && PasswordConfigured);
        ResetPasswordCommand = new RelayCommand(ResetPasswordAsync, () => _connected);
        ExportLogsCommand = new RelayCommand(ExportLogsAsync);
        RefreshCommand = new RelayCommand(RefreshAsync, () => _connected);
        OpenSecurityCommand = new RelayCommand(OpenWindowsSecurityAsync);
        RemediateThreatsCommand = new RelayCommand(RemediateThreatsAsync, () => _connected && PasswordConfigured);
        FormatUsbCommand = new RelayCommand(FormatUsbAsync, () => _connected && (_snapshot?.ConnectedDrives.Count ?? 0) > 0);
        OpenFacebookCommand = new RelayCommand(() => OpenUrlAsync("https://fb.com/MianAshfaq012"));
        OpenGitHubCommand = new RelayCommand(() => OpenUrlAsync("https://github.com/MianAshfaq"));
        OpenWebsiteCommand = new RelayCommand(() => OpenUrlAsync("https://cyberoly.com"));
        _client.EventReceived += OnEventReceived;
        _client.ConnectionChanged += (_, connected) => _dispatcher.Invoke(() => Connected = connected);
        _animationTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(45), DispatcherPriority.Render,
            (_, _) =>
            {
                if (State is UsbState.Scanning or UsbState.Enabling or UsbState.WaitingForDevice)
                    RingAngle = (RingAngle + 3) % 360;
            }, dispatcher);
        _animationTimer.Start();
        _reconnectTimer = new DispatcherTimer(TimeSpan.FromSeconds(3), DispatcherPriority.Background,
            async (_, _) => await EnsureConnectedAsync(), dispatcher);
        _reconnectTimer.Start();
        InitializeVoice();
    }

    public ObservableCollection<string> Logs { get; } = new();
    public ObservableCollection<string> DriveStatuses { get; } = new();
    public RelayCommand EnableCommand { get; }
    public RelayCommand DisableCommand { get; }
    public RelayCommand SaveSettingsCommand { get; }
    public RelayCommand TestVoiceCommand { get; }
    public RelayCommand ChangePasswordCommand { get; }
    public RelayCommand ResetPasswordCommand { get; }
    public RelayCommand ExportLogsCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand OpenSecurityCommand { get; }
    public RelayCommand RemediateThreatsCommand { get; }
    public RelayCommand FormatUsbCommand { get; }
    public RelayCommand OpenFacebookCommand { get; }
    public RelayCommand OpenGitHubCommand { get; }
    public RelayCommand OpenWebsiteCommand { get; }
    public Func<bool, string?>? PasswordPrompt { get; set; }
    public Func<(string CurrentPassword, string NewPassword)?>? ChangePasswordPrompt { get; set; }
    public Func<string?>? ResetPasswordPrompt { get; set; }
    public Func<IReadOnlyList<string>, FormatUsbRequest?>? FormatUsbPrompt { get; set; }
    public Func<string, bool>? PostOperationEnablePrompt { get; set; }
    public event EventHandler? PasswordSetupRequired;
    public event Action<string>? TrayStatusChanged;
    public event Action<string, string, bool>? TrayNotificationRequested;

    public UsbState State => _snapshot?.State ?? UsbState.Disabled;
    public string StatusText => _snapshot?.StatusText ?? "Connecting to USB Sentinel service...";
    public string ProgressText => State == UsbState.Scanning ? $"{_snapshot?.ScanProgress ?? 0}% SCANNED" : State.ToString().ToUpperInvariant();
    public string ConnectedDrivesText => _snapshot?.ConnectedDrives.Count > 0
        ? string.Join("   ", _snapshot.ConnectedDrives)
        : "NONE";
    public string DetectedHardwareText => _snapshot?.DetectedDevices is { Count: > 0 } devices
        ? string.Join(Environment.NewLine, devices.Select(device => $"{device.Name}  -  {device.Status}"))
        : "No USB storage hardware detected";
    public string LastUpdatedText => _snapshot is null ? "" : $"UPDATED {_snapshot.UpdatedAt.ToLocalTime():HH:mm:ss}";
    public string ConnectionText => Connected ? "SERVICE ONLINE" : "SERVICE OFFLINE";
    public string VoiceName { get => _voiceName; private set => Set(ref _voiceName, value); }
    public bool PasswordConfigured => _snapshot?.PasswordConfigured ?? false;
    public string DefenderStatusText => _snapshot?.DefenderAvailable == true ? "ENGINE READY" : "ENGINE UNAVAILABLE";
    public string DefenderSignatureText => $"SIGNATURE {_snapshot?.DefenderSignatureVersion ?? "Unknown"}";
    public System.Windows.Media.Brush ConnectionBrush => Connected ? MediaBrushes.SpringGreen : MediaBrushes.IndianRed;
    public System.Windows.Media.Brush StatusBrush => State switch
    {
        UsbState.Enabled => new SolidColorBrush(MediaColor.FromRgb(57, 255, 154)),
        UsbState.Scanning or UsbState.Enabling or UsbState.WaitingForDevice => new SolidColorBrush(MediaColor.FromRgb(53, 207, 255)),
        UsbState.ThreatFound or UsbState.Failed => new SolidColorBrush(MediaColor.FromRgb(255, 85, 115)),
        _ => new SolidColorBrush(MediaColor.FromRgb(131, 161, 167))
    };
    public double RingAngle { get => _ringAngle; private set => Set(ref _ringAngle, value); }

    public bool AutoDisableOnDisconnect { get => _autoDisableOnDisconnect; set => Set(ref _autoDisableOnDisconnect, value); }
    public bool VoiceAlerts { get => _voiceAlerts; set => Set(ref _voiceAlerts, value); }
    public bool BlockAllUsbDevices { get => _blockAllUsbDevices; set => Set(ref _blockAllUsbDevices, value); }
    public bool WarnBeforeRemediation { get => _warnBeforeRemediation; set => Set(ref _warnBeforeRemediation, value); }

    private bool Connected
    {
        get => _connected;
        set
        {
            if (!Set(ref _connected, value))
                return;
            OnPropertyChanged(nameof(ConnectionText));
            OnPropertyChanged(nameof(ConnectionBrush));
            EnableCommand.RaiseCanExecuteChanged();
            DisableCommand.RaiseCanExecuteChanged();
            SaveSettingsCommand.RaiseCanExecuteChanged();
            ChangePasswordCommand.RaiseCanExecuteChanged();
            ResetPasswordCommand.RaiseCanExecuteChanged();
            RefreshCommand.RaiseCanExecuteChanged();
            RemediateThreatsCommand.RaiseCanExecuteChanged();
            FormatUsbCommand.RaiseCanExecuteChanged();
        }
    }

    public async Task StartAsync()
    {
        await EnsureConnectedAsync();
    }

    private async Task EnsureConnectedAsync()
    {
        if (Connected || _connecting)
            return;

        _connecting = true;
        try
        {
            await _client.ConnectAsync(CancellationToken.None);
            await _client.SendAsync(CommandType.GetSnapshot);
        }
        catch (Exception ex)
        {
            AddError($"Service connection: {ex.Message}");
        }
        finally
        {
            _connecting = false;
        }
    }

    private async Task SendAsync(CommandType command)
    {
        try { await _client.SendAsync(command); }
        catch (Exception ex) { AddError(ex.Message); }
    }

    private async Task EnableUsbAsync()
    {
        var creatingPassword = !PasswordConfigured;
        var password = PasswordPrompt?.Invoke(creatingPassword);
        if (string.IsNullOrEmpty(password))
            return;

        try
        {
            if (creatingPassword)
                await _client.SendAsync(CommandType.SetPassword, password: password);
            await _client.SendAsync(CommandType.EnableUsb, password: password);
        }
        catch (Exception ex)
        {
            AddError(ex.Message);
        }
    }

    public async Task ConfigureFirstRunPasswordAsync(string password)
    {
        try { await _client.SendAsync(CommandType.SetPassword, password: password); }
        catch (Exception ex) { AddError(ex.Message); }
    }

    private async Task ChangePasswordAsync()
    {
        var passwords = ChangePasswordPrompt?.Invoke();
        if (passwords is null)
            return;
        try
        {
            await _client.SendAsync(
                CommandType.ChangePassword,
                password: passwords.Value.CurrentPassword,
                newPassword: passwords.Value.NewPassword);
        }
        catch (Exception ex) { AddError(ex.Message); }
    }

    private async Task ResetPasswordAsync()
    {
        var password = ResetPasswordPrompt?.Invoke();
        if (string.IsNullOrEmpty(password))
            return;
        try
        {
            await _client.SendAsync(CommandType.ResetPassword, newPassword: password);
        }
        catch (Exception ex) { AddError(ex.Message); }
    }

    private Task ExportLogsAsync()
    {
        var dialog = new WpfSaveFileDialog
        {
            Title = "Export USB Sentinel audit log",
            Filter = "CSV file (*.csv)|*.csv|Text file (*.txt)|*.txt",
            FileName = $"USB-Sentinel-Audit-{DateTime.Now:yyyyMMdd-HHmm}.csv",
            AddExtension = true
        };
        if (dialog.ShowDialog() != true)
            return Task.CompletedTask;

        var lines = new[] { "Entry" }.Concat(Logs.Select(log => $"\"{log.Replace("\"", "\"\"")}\""));
        File.WriteAllLines(dialog.FileName, lines);
        Logs.Add($"[{DateTime.Now:HH:mm:ss}] INFORMATION Audit log exported.");
        return Task.CompletedTask;
    }

    private async Task RefreshAsync()
    {
        await _client.SendAsync(CommandType.GetSnapshot);
        await _client.SendAsync(CommandType.GetRecentLogs);
    }

    private static Task OpenWindowsSecurityAsync()
    {
        Process.Start(new ProcessStartInfo("windowsdefender://threat/") { UseShellExecute = true });
        return Task.CompletedTask;
    }

    private async Task RemediateThreatsAsync()
    {
        var password = PasswordPrompt?.Invoke(false);
        if (string.IsNullOrEmpty(password))
            return;
        if (System.Windows.MessageBox.Show(
                "Ask Microsoft Defender to remove or quarantine confirmed active threats? USB storage remains blocked.",
                "Defender remediation", System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Warning, System.Windows.MessageBoxResult.No) != System.Windows.MessageBoxResult.Yes)
            return;
        await _client.SendAsync(CommandType.RemediateThreats, password: password);
    }

    private async Task FormatUsbAsync()
    {
        var drives = _snapshot?.ConnectedDrives ?? Array.Empty<string>();
        var request = FormatUsbPrompt?.Invoke(drives);
        if (request is null)
            return;
        await _client.SendAsync(CommandType.FormatUsb, password: request.Password, drive: request.Drive,
            confirmation: request.Confirmation, quickFormat: request.QuickFormat, fileSystem: request.FileSystem);
    }

    private static Task OpenUrlAsync(string url)
    {
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        return Task.CompletedTask;
    }

    private async Task SaveSettingsAsync()
    {
        try
        {
            await _client.SendAsync(CommandType.UpdateSettings,
                new SentinelSettings(AutoDisableOnDisconnect, VoiceAlerts, BlockAllUsbDevices, WarnBeforeRemediation));
        }
        catch (Exception ex) { AddError(ex.Message); }
    }

    private void OnEventReceived(object? sender, PipeEvent pipeEvent)
    {
        _dispatcher.Invoke(() =>
        {
            if (pipeEvent.Snapshot is not null)
                ApplySnapshot(pipeEvent.Snapshot);
            if (pipeEvent.Log is not null)
            {
                var log = pipeEvent.Log;
                var isLiveEvent = pipeEvent.Type == EventType.Log;
                if (isLiveEvent)
                    UpdateDriveResult(log);
                Logs.Add($"[{log.Timestamp.ToLocalTime():HH:mm:ss}] {log.Level,-11} {log.Message}");
                while (Logs.Count > 500)
                    Logs.RemoveAt(0);
                if (isLiveEvent && log.EventType is ("DeviceDetected" or "DeviceRemoved" or "ThreatFound" or "ScanFailed" or
                    "AccessGranted" or "FormatCompleted" or "ThreatRemediation"))
                    TrayNotificationRequested?.Invoke(
                        "USB Sentinel Pro",
                        log.Message,
                        log.EventType is "ThreatFound" or "ScanFailed");
                if (isLiveEvent && log.Level == LogLevel.Security &&
                    log.EventType is ("FormatCompleted" or "ThreatRemediation"))
                {
                    _dispatcher.BeginInvoke(async () =>
                    {
                        var prompt = "The operation completed and USB storage remains blocked. " +
                                     "Scan the connected USB storage again and enable access only if clean?";
                        if (PostOperationEnablePrompt?.Invoke(prompt) == true)
                            await EnableUsbAsync();
                    });
                }
            }
            if (pipeEvent.Type == EventType.Error && pipeEvent.Message is not null)
                AddError(pipeEvent.Message);
            if (pipeEvent.Type == EventType.PasswordConfigured)
            {
                Logs.Add($"[{DateTime.Now:HH:mm:ss}] SECURITY    Password saved successfully.");
                SpeakMessage("Security password saved successfully.");
            }
        });
    }

    private void ApplySnapshot(ServiceSnapshot snapshot)
    {
        _snapshot = snapshot;
        AutoDisableOnDisconnect = snapshot.Settings.AutoDisableOnDisconnect;
        VoiceAlerts = snapshot.Settings.VoiceAlerts;
        BlockAllUsbDevices = snapshot.Settings.BlockAllUsbDevices;
        WarnBeforeRemediation = snapshot.Settings.WarnBeforeRemediation;
        var connected = snapshot.ConnectedDrives.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var removed in _driveResults.Keys.Where(root => !connected.Contains(root)).ToArray())
            _driveResults.Remove(removed);
        foreach (var drive in snapshot.ConnectedDrives)
            _driveResults.TryAdd(drive, "DETECTED");
        RebuildDriveStatuses();
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(ProgressText));
        OnPropertyChanged(nameof(ConnectedDrivesText));
        OnPropertyChanged(nameof(DetectedHardwareText));
        OnPropertyChanged(nameof(LastUpdatedText));
        OnPropertyChanged(nameof(StatusBrush));
        OnPropertyChanged(nameof(PasswordConfigured));
        OnPropertyChanged(nameof(DefenderStatusText));
        OnPropertyChanged(nameof(DefenderSignatureText));
        ChangePasswordCommand.RaiseCanExecuteChanged();
        ResetPasswordCommand.RaiseCanExecuteChanged();
        RemediateThreatsCommand.RaiseCanExecuteChanged();
        FormatUsbCommand.RaiseCanExecuteChanged();
        TrayStatusChanged?.Invoke(snapshot.StatusText);
        if (!snapshot.PasswordConfigured)
            PasswordSetupRequired?.Invoke(this, EventArgs.Empty);
        SpeakState(snapshot.State, snapshot.StatusText);
    }

    private void SpeakState(UsbState state, string status)
    {
        if (!VoiceAlerts || _lastSpokenState == state)
            return;
        _lastSpokenState = state;
        var message = state switch
        {
            UsbState.Scanning => "Scanning started.",
            UsbState.Enabled => "USB is clean. Access enabled.",
            UsbState.ThreatFound => "Threat found. USB storage is blocked.",
            UsbState.Disabled when status.Contains("disconnected", StringComparison.OrdinalIgnoreCase)
                => "USB disconnected. USB storage disabled.",
            UsbState.WaitingForDevice => "Waiting for USB device.",
            UsbState.Failed => "USB security operation failed.",
            _ => null
        };
        if (message is null)
            return;

        SpeakMessage(message);
    }

    private Task TestVoiceAsync()
    {
        SpeakMessage("USB Sentinel Pro voice assistant is online. Your system is protected.");
        return Task.CompletedTask;
    }

    private void SpeakMessage(string message)
    {
        if (_speech is null)
        {
            AddError("No compatible Windows speech voice is installed.");
            return;
        }

        try
        {
            _speech.SpeakAsyncCancelAll();
            _speech.SpeakAsync(message);
        }
        catch (Exception ex)
        {
            AddError($"Voice alert unavailable: {ex.Message}");
            _speech.Dispose();
            _speech = null;
            VoiceName = "Windows voice unavailable";
        }
    }

    private void InitializeVoice()
    {
        try
        {
            var speech = new SpeechSynthesizer
            {
                Rate = -1,
                Volume = 100
            };
            var femaleVoice = speech.GetInstalledVoices()
                .Where(voice => voice.Enabled)
                .Select(voice => voice.VoiceInfo)
                .OrderByDescending(voice => voice.Gender == VoiceGender.Female)
                .ThenByDescending(voice => voice.Culture.Name.StartsWith("en", StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();

            if (femaleVoice is not null)
            {
                speech.SelectVoice(femaleVoice.Name);
                VoiceName = femaleVoice.Name;
            }

            _speech = speech;
        }
        catch (Exception)
        {
            VoiceName = "Windows voice unavailable";
        }
    }

    private void AddError(string message) => Logs.Add($"[{DateTime.Now:HH:mm:ss}] ERROR       {message}");

    private void UpdateDriveResult(LogEntry log)
    {
        if (string.IsNullOrWhiteSpace(log.Drive))
            return;
        var status = log.EventType switch
        {
            "DeviceDetected" => "DETECTED",
            "ScanStarted" => "SCANNING",
            "ScanClean" => "CLEAN",
            "ThreatFound" => "THREAT FOUND - BLOCKED",
            "ScanFailed" => "SCAN FAILED - BLOCKED",
            "FormatStarted" => "FORMATTING",
            "FormatCompleted" => "FORMATTED - BLOCKED",
            "FormatFailed" => "FORMAT FAILED - BLOCKED",
            _ => null
        };
        if (status is null)
            return;
        _driveResults[log.Drive] = status;
        RebuildDriveStatuses();
    }

    private void RebuildDriveStatuses()
    {
        DriveStatuses.Clear();
        foreach (var drive in _driveResults.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
            DriveStatuses.Add($"{drive.Key}  -  {drive.Value}");
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    public void Dispose()
    {
        _animationTimer.Stop();
        _reconnectTimer.Stop();
        _speech?.Dispose();
        _client.Dispose();
    }
}

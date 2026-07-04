using System.Management;

namespace UsbSentinel.Service;

public sealed class SentinelWorker(
    SentinelCoordinator coordinator,
    PipeServer pipeServer,
    ILogger<SentinelWorker> logger) : BackgroundService
{
    private ManagementEventWatcher? _insertWatcher;
    private ManagementEventWatcher? _removeWatcher;
    private ManagementEventWatcher? _hardwareWatcher;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        coordinator.InitializeFailClosed();
        StartWatchers();
        try
        {
            await pipeServer.RunAsync(stoppingToken);
        }
        finally
        {
            StopWatchers();
            try { await coordinator.DisableAsync(CancellationToken.None); }
            catch (Exception ex) { logger.LogCritical(ex, "Could not restore USB storage block during service shutdown."); }
        }
    }

    private void StartWatchers()
    {
        _insertWatcher = CreateWatcher(2, (_, _) => coordinator.OnVolumeInserted());
        _removeWatcher = CreateWatcher(3, (_, _) => coordinator.OnVolumeRemoved());
        _hardwareWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent"));
        _hardwareWatcher.EventArrived += (_, _) => coordinator.OnHardwareChanged();
        _insertWatcher.Start();
        _removeWatcher.Start();
        _hardwareWatcher.Start();
    }

    private static ManagementEventWatcher CreateWatcher(int eventType, EventArrivedEventHandler handler)
    {
        var query = new WqlEventQuery(
            $"SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = {eventType}");
        var watcher = new ManagementEventWatcher(query);
        watcher.EventArrived += handler;
        return watcher;
    }

    private void StopWatchers()
    {
        foreach (var watcher in new[] { _insertWatcher, _removeWatcher, _hardwareWatcher })
        {
            if (watcher is null)
                continue;
            try { watcher.Stop(); }
            catch (ManagementException) { }
            watcher.Dispose();
        }
    }
}

namespace UsbSentinel.Service;

public sealed class DefenderSignatureWorker(
    SentinelCoordinator coordinator,
    ILogger<DefenderSignatureWorker> logger) : BackgroundService
{
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan UpdateInterval = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                await coordinator.UpdateDefenderSignaturesInBackgroundAsync(stoppingToken);
                await Task.Delay(UpdateInterval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "The Defender signature update worker stopped unexpectedly.");
        }
    }
}

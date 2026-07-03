using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using UsbSentinel.Contracts;

namespace UsbSentinel.Desktop;

public sealed class ServiceClient : IDisposable
{
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private CancellationTokenSource? _readerCancellation;
    private int _connectionVersion;

    public event EventHandler<PipeEvent>? EventReceived;
    public event EventHandler<bool>? ConnectionChanged;

    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        DisposePipe();
        var connectionVersion = _connectionVersion;
        _pipe = new NamedPipeClientStream(
            ".", SentinelProtocol.PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough);
        await _pipe.ConnectAsync(5000, cancellationToken);
        _reader = new StreamReader(_pipe, leaveOpen: true);
        _writer = new StreamWriter(_pipe, leaveOpen: true) { AutoFlush = true };
        _readerCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ConnectionChanged?.Invoke(this, true);
        _ = ReadLoopAsync(connectionVersion, _readerCancellation.Token);
    }

    public async Task SendAsync(
        CommandType command,
        SentinelSettings? settings = null,
        string? password = null,
        string? newPassword = null,
        CancellationToken token = default)
    {
        if (_writer is null)
            throw new InvalidOperationException("USB Sentinel service is not connected.");
        await _writeLock.WaitAsync(token);
        try
        {
            var payload = new PipeCommand(SentinelProtocol.Version, command, settings, password, newPassword);
            await _writer.WriteLineAsync(JsonSerializer.Serialize(payload, SentinelProtocol.JsonOptions));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task ReadLoopAsync(int connectionVersion, CancellationToken token)
    {
        try
        {
            while (_reader is not null && !token.IsCancellationRequested)
            {
                var line = await _reader.ReadLineAsync(token);
                if (line is null)
                    break;
                var pipeEvent = JsonSerializer.Deserialize<PipeEvent>(line, SentinelProtocol.JsonOptions);
                if (pipeEvent is not null)
                    EventReceived?.Invoke(this, pipeEvent);
            }
        }
        catch (IOException)
        {
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            if (connectionVersion == _connectionVersion)
                ConnectionChanged?.Invoke(this, false);
        }
    }

    private void DisposePipe()
    {
        Interlocked.Increment(ref _connectionVersion);
        _readerCancellation?.Cancel();
        _readerCancellation?.Dispose();
        _readerCancellation = null;
        _reader?.Dispose();
        _writer?.Dispose();
        _pipe?.Dispose();
        _reader = null;
        _writer = null;
        _pipe = null;
    }

    public void Dispose()
    {
        DisposePipe();
        _writeLock.Dispose();
    }
}

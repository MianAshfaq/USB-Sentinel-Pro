using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using UsbSentinel.Contracts;

namespace UsbSentinel.Service;

public sealed class PipeServer(SentinelCoordinator coordinator, PasswordRepository passwords)
{
    private readonly ConcurrentDictionary<Guid, ClientConnection> _clients = new();

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        coordinator.EventPublished += Broadcast;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var pipe = CreateSecurePipe();
                try
                {
                    await pipe.WaitForConnectionAsync(cancellationToken);
                    _ = HandleClientAsync(pipe, cancellationToken);
                }
                catch
                {
                    pipe.Dispose();
                    throw;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            coordinator.EventPublished -= Broadcast;
            foreach (var client in _clients.Values)
                client.Dispose();
        }
    }

    private static NamedPipeServerStream CreateSecurePipe()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            SentinelProtocol.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            16 * 1024,
            16 * 1024,
            security);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken serviceToken)
    {
        var id = Guid.NewGuid();
        var client = new ClientConnection(pipe);
        _clients[id] = client;
        try
        {
            await client.SendAsync(new PipeEvent(
                SentinelProtocol.Version, EventType.Snapshot, Snapshot: coordinator.Snapshot), serviceToken);
            foreach (var entry in coordinator.RecentLogs)
                await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.HistoricalLog, Log: entry), serviceToken);

            while (pipe.IsConnected && !serviceToken.IsCancellationRequested)
            {
                var line = await client.Reader.ReadLineAsync(serviceToken);
                if (line is null)
                    break;
                var command = JsonSerializer.Deserialize<PipeCommand>(line, SentinelProtocol.JsonOptions);
                if (command is null || command.ProtocolVersion != SentinelProtocol.Version)
                {
                    await client.SendAsync(new PipeEvent(
                        SentinelProtocol.Version, EventType.Error, Message: "Unsupported protocol request."), serviceToken);
                    continue;
                }
                await DispatchAsync(command, client, serviceToken);
            }
        }
        catch (IOException)
        {
        }
        catch (OperationCanceledException) when (serviceToken.IsCancellationRequested)
        {
        }
        finally
        {
            _clients.TryRemove(id, out _);
            client.Dispose();
        }
    }

    private async Task DispatchAsync(PipeCommand command, ClientConnection client, CancellationToken token)
    {
        switch (command.Type)
        {
            case CommandType.GetSnapshot:
                await client.SendAsync(new PipeEvent(
                    SentinelProtocol.Version, EventType.Snapshot, Snapshot: coordinator.Snapshot), token);
                break;
            case CommandType.EnableUsb:
                if (!passwords.Verify(command.Password, out var authenticationError))
                {
                    coordinator.RecordAuthenticationFailure(authenticationError);
                    await client.SendAsync(new PipeEvent(
                        SentinelProtocol.Version, EventType.Error, Message: authenticationError), token);
                    break;
                }
                _ = coordinator.EnableAsync(command.UserSid, token);
                break;
            case CommandType.DisableUsb:
                await coordinator.DisableAsync(token);
                break;
            case CommandType.UpdateSettings when command.Settings is not null:
                coordinator.UpdateSettings(command.Settings);
                break;
            case CommandType.GetRecentLogs:
                foreach (var entry in coordinator.RecentLogs)
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.HistoricalLog, Log: entry), token);
                break;
            case CommandType.SetPassword:
                if (passwords.TryCreate(command.Password ?? string.Empty, out var passwordError))
                {
                    coordinator.PasswordConfigured();
                    await client.SendAsync(new PipeEvent(
                        SentinelProtocol.Version, EventType.PasswordConfigured,
                        Message: "Security password saved successfully."), token);
                }
                else
                {
                    await client.SendAsync(new PipeEvent(
                        SentinelProtocol.Version, EventType.Error, Message: passwordError), token);
                }
                break;
            case CommandType.ChangePassword:
                if (passwords.TryChange(command.Password, command.NewPassword, out var changeError))
                {
                    coordinator.RecordSecurityEvent("PasswordChanged", "USB enable password was changed.");
                    await client.SendAsync(new PipeEvent(
                        SentinelProtocol.Version, EventType.PasswordConfigured,
                        Message: "Security password changed successfully."), token);
                }
                else
                {
                    coordinator.RecordAuthenticationFailure(changeError);
                    await client.SendAsync(new PipeEvent(
                        SentinelProtocol.Version, EventType.Error, Message: changeError), token);
                }
                break;
            case CommandType.ResetPassword:
                if (passwords.TryReset(command.NewPassword, out var resetError))
                {
                    coordinator.RecordSecurityEvent("PasswordResetByAdministrator",
                        "The USB enable password was reset by a local Windows administrator.");
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.PasswordConfigured,
                        Message: "Security password reset successfully."), token);
                }
                else
                {
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.Error,
                        Message: resetError), token);
                }
                break;
            case CommandType.RemediateThreats:
                if (!passwords.Verify(command.Password, out var remediationError))
                {
                    coordinator.RecordAuthenticationFailure(remediationError);
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.Error, Message: remediationError), token);
                    break;
                }
                _ = coordinator.RemediateThreatsAsync(token);
                break;
            case CommandType.FormatUsb:
                if (!passwords.Verify(command.Password, out var formatError))
                {
                    coordinator.RecordAuthenticationFailure(formatError);
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.Error, Message: formatError), token);
                    break;
                }
                string? root;
                try { root = command.Drive is null ? null : UsbDriveInventory.NormalizeRoot(command.Drive); }
                catch (ArgumentException) { root = null; }
                if (root is null || !string.Equals(command.Confirmation, $"ERASE {root[..2]}", StringComparison.Ordinal))
                {
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.Error,
                        Message: "The erase confirmation phrase is invalid."), token);
                    break;
                }
                if (command.FileSystem is not ("exFAT" or "NTFS"))
                {
                    await client.SendAsync(new PipeEvent(SentinelProtocol.Version, EventType.Error,
                        Message: "Only exFAT and NTFS formats are supported."), token);
                    break;
                }
                _ = coordinator.FormatUsbAsync(root, command.FileSystem, command.QuickFormat, token);
                break;
        }
    }

    private void Broadcast(object? sender, PipeEvent pipeEvent)
    {
        foreach (var client in _clients.Values)
            _ = client.TrySendAsync(pipeEvent);
    }

    private sealed class ClientConnection : IDisposable
    {
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly StreamWriter _writer;
        public StreamReader Reader { get; }

        public ClientConnection(Stream stream)
        {
            Reader = new StreamReader(stream, leaveOpen: true);
            _writer = new StreamWriter(stream, leaveOpen: true) { AutoFlush = true };
        }

        public async Task SendAsync(PipeEvent pipeEvent, CancellationToken token)
        {
            await _writeLock.WaitAsync(token);
            try
            {
                await _writer.WriteLineAsync(JsonSerializer.Serialize(pipeEvent, SentinelProtocol.JsonOptions));
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task TrySendAsync(PipeEvent pipeEvent)
        {
            try { await SendAsync(pipeEvent, CancellationToken.None); }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }

        public void Dispose()
        {
            Reader.Dispose();
            _writer.Dispose();
            _writeLock.Dispose();
        }
    }
}

using System.Text.Json;
using UsbSentinel.Contracts;
using Xunit;

namespace UsbSentinel.Tests;

public sealed class ProtocolTests
{
    [Fact]
    public void Settings_AlwaysRequireScanBeforeEnable()
    {
        var settings = new SentinelSettings(
            AutoDisableOnDisconnect: false,
            VoiceAlerts: false,
            BlockAllUsbDevices: true,
            WarnBeforeRemediation: false);

        Assert.True(settings.ScanBeforeEnable);
    }

    [Fact]
    public void PipeCommand_RoundTripsUsingSharedProtocol()
    {
        var command = new PipeCommand(
            SentinelProtocol.Version,
            CommandType.UpdateSettings,
            new SentinelSettings());

        var json = JsonSerializer.Serialize(command, SentinelProtocol.JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PipeCommand>(json, SentinelProtocol.JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal(CommandType.UpdateSettings, deserialized.Type);
        Assert.True(deserialized.Settings!.AutoDisableOnDisconnect);
    }

    [Theory]
    [InlineData(-1, 0)]
    [InlineData(30, 30)]
    [InlineData(101, 100)]
    public void ProgressContract_UsesExpectedBounds(int input, int expected)
    {
        Assert.Equal(expected, Math.Clamp(input, 0, 100));
    }

    [Fact]
    public void EnableCommand_CarriesPasswordWithoutWritingItToSettings()
    {
        var command = new PipeCommand(
            SentinelProtocol.Version,
            CommandType.EnableUsb,
            Password: "TestPassword9");

        var json = JsonSerializer.Serialize(command, SentinelProtocol.JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PipeCommand>(json, SentinelProtocol.JsonOptions);

        Assert.Equal("TestPassword9", deserialized!.Password);
        Assert.Null(deserialized.Settings);
    }

    [Fact]
    public void Snapshot_DefaultsToPasswordNotConfigured()
    {
        var snapshot = new ServiceSnapshot(
            UsbState.Disabled,
            true,
            0,
            "Protected",
            Array.Empty<string>(),
            new SentinelSettings(),
            DateTimeOffset.UtcNow);

        Assert.False(snapshot.PasswordConfigured);
    }

    [Fact]
    public void FormatCommand_RoundTripsEverySafetyField()
    {
        var command = new PipeCommand(
            SentinelProtocol.Version,
            CommandType.FormatUsb,
            Password: "TestPassword9",
            Drive: @"E:\",
            Confirmation: "ERASE E:",
            QuickFormat: false,
            FileSystem: "NTFS");

        var json = JsonSerializer.Serialize(command, SentinelProtocol.JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PipeCommand>(json, SentinelProtocol.JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal(CommandType.FormatUsb, deserialized.Type);
        Assert.Equal(@"E:\", deserialized.Drive);
        Assert.Equal("ERASE E:", deserialized.Confirmation);
        Assert.False(deserialized.QuickFormat);
        Assert.Equal("NTFS", deserialized.FileSystem);
    }

    [Fact]
    public void ResetPasswordCommand_CarriesOnlyTheNewPassword()
    {
        var command = new PipeCommand(
            SentinelProtocol.Version,
            CommandType.ResetPassword,
            NewPassword: "ReplacementPassword9");

        var json = JsonSerializer.Serialize(command, SentinelProtocol.JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PipeCommand>(json, SentinelProtocol.JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal(CommandType.ResetPassword, deserialized.Type);
        Assert.Null(deserialized.Password);
        Assert.Equal("ReplacementPassword9", deserialized.NewPassword);
    }
}

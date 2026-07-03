using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using UsbSentinel.Contracts;

namespace UsbSentinel.Service;

public sealed class DefenderScanner
{
    private readonly string? _mpCmdRun = ResolveMpCmdRun();

    public bool IsAvailable => _mpCmdRun is not null;

    public string SignatureVersion
    {
        get
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
            return key?.GetValue("AVSignatureVersion") as string ?? "Unknown";
        }
    }

    public async Task<bool> UpdateSignaturesAsync(Action<string> log, CancellationToken cancellationToken)
    {
        if (_mpCmdRun is null)
        {
            log("Microsoft Defender command-line engine is unavailable.");
            return false;
        }
        log("Checking Microsoft Defender signatures...");
        var result = await RunAsync("-SignatureUpdate", null, cancellationToken);
        log(result.ExitCode == 0
            ? "Defender signatures are current."
            : "Signature update unavailable; continuing with installed definitions.");
        return result.ExitCode == 0;
    }

    public async Task<DefenderScanResult> ScanAsync(
        string drive,
        Action<string> log,
        Action<int> progress,
        CancellationToken cancellationToken)
    {
        var root = Path.GetPathRoot(drive) ?? drive;
        if (_mpCmdRun is null)
            return new DefenderScanResult(root, false, false, false, false, -1, "Microsoft Defender is unavailable.");
        progress(10);
        log($"Starting Defender custom scan of {root}");
        var result = await RunAsync("-Scan -ScanType 3 -File", root, cancellationToken);
        progress(90);

        var output = result.Output;
        var threatFound = result.ExitCode == 2;
        var succeeded = result.ExitCode is 0 or 2;

        // MpCmdRun invokes Defender's configured remediation policy. We never delete files ourselves.
        var remediationSucceeded = threatFound &&
            !output.Contains("failed", StringComparison.OrdinalIgnoreCase) &&
            !output.Contains("not remediated", StringComparison.OrdinalIgnoreCase);
        progress(100);

        var summary = !succeeded ? "Defender scan failed."
            : threatFound && remediationSucceeded ? "Threat detected and Defender remediation completed."
            : threatFound ? "Threat detected; remediation requires attention."
            : "No threats detected.";

        return new DefenderScanResult(root, succeeded, threatFound, threatFound, remediationSucceeded, result.ExitCode, summary);
    }

    public async Task<bool> RemediateThreatsAsync(Action<string> log, CancellationToken cancellationToken)
    {
        log("Requesting Microsoft Defender remediation for confirmed active threats.");
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var result = await RunProcessAsync(
            powershell,
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Remove-MpThreat -ErrorAction Stop\"",
            cancellationToken);
        log(result.Output);
        return result.ExitCode == 0;
    }

    private async Task<(int ExitCode, string Output)> RunAsync(
        string arguments,
        string? quotedArgument,
        CancellationToken cancellationToken)
    {
        var executable = _mpCmdRun ?? throw new InvalidOperationException("Microsoft Defender is unavailable.");
        return await RunProcessAsync(executable,
            quotedArgument is null ? arguments : $"{arguments} \"{quotedArgument.Replace("\"", "\\\"")}\"",
            cancellationToken);
    }

    public static async Task<(int ExitCode, string Output)> RunProcessAsync(
        string executable, string arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        using var process = new Process { StartInfo = psi };
        var output = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) output.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) output.AppendLine(e.Data); };
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        await process.WaitForExitAsync(cancellationToken);
        return (process.ExitCode, output.ToString());
    }

    private static string? ResolveMpCmdRun()
    {
        var platform = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var standard = Path.Combine(platform, "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(standard))
            return standard;

        var platformDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        var latest = Directory.Exists(platformDirectory)
            ? Directory.GetDirectories(platformDirectory)
                .OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
                .Select(path => Path.Combine(path, "MpCmdRun.exe"))
                .FirstOrDefault(File.Exists)
            : null;
        return latest;
    }
}

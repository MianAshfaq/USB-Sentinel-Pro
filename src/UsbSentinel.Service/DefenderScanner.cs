using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using UsbSentinel.Contracts;

namespace UsbSentinel.Service;

public sealed class DefenderScanner
{
    private static readonly string[] HighRiskExtensions =
    [
        ".exe", ".dll", ".scr", ".msi", ".cmd", ".bat", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".hta", ".lnk", ".com", ".pif", ".jar"
    ];
    private const long FullScanSizeLimitBytes = 64L * 1024 * 1024 * 1024;
    private const int FastScanFileLimit = 250;
    private readonly string? _mpCmdRun = ResolveMpCmdRun();
    private DateTimeOffset? _lastSuccessfulSignatureUpdate;

    public bool IsAvailable => _mpCmdRun is not null;
    public bool SignaturesRecentlyUpdated =>
        _lastSuccessfulSignatureUpdate is { } updated && DateTimeOffset.UtcNow - updated < TimeSpan.FromHours(6);

    public string SignatureVersion
    {
        get
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
            return key?.GetValue("AVSignatureVersion") as string ?? "Unknown";
        }
    }

    public async Task<TimeSpan?> GetSignatureAgeAsync(CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var result = await RunProcessAsync(powershell,
            "-NoProfile -NonInteractive -Command \"(Get-MpComputerStatus).AntivirusSignatureLastUpdated.ToUniversalTime().ToString('O')\"",
            cancellationToken);
        return result.ExitCode == 0 && DateTimeOffset.TryParse(result.Output.Trim(), out var updated)
            ? DateTimeOffset.UtcNow - updated
            : null;
    }

    public async Task<string> GetRecentThreatDetailsAsync(CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var result = await RunProcessAsync(powershell,
            "-NoProfile -NonInteractive -Command \"Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5 ThreatID,ThreatStatusID,InitialDetectionTime,Resources | ConvertTo-Json -Compress\"",
            cancellationToken);
        return result.ExitCode == 0 && !string.IsNullOrWhiteSpace(result.Output)
            ? result.Output.Trim()
            : "Defender threat details are available in Windows Security Protection History.";
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
        if (result.ExitCode == 0)
        {
            _lastSuccessfulSignatureUpdate = DateTimeOffset.UtcNow;
            log("Defender signatures are current.");
            return true;
        }

        log("Configured update source failed; trying Microsoft's direct security-intelligence service.");
        result = await RunAsync("-SignatureUpdate -MMPC", null, cancellationToken);
        if (result.ExitCode == 0)
            _lastSuccessfulSignatureUpdate = DateTimeOffset.UtcNow;
        log(result.ExitCode == 0 ? "Defender signatures were updated directly from Microsoft."
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
        var plan = BuildScanPlan(root);
        log(plan.Description);
        var result = plan.FastGate
            ? await RunFastGateScanAsync(root, plan.Targets, log, progress, cancellationToken)
            : await RunAsync("-Scan -ScanType 3 -File", root, cancellationToken);
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
            : plan.FastGate ? "Fast Defender safety scan passed. Full scan is recommended for large storage."
            : "No threats detected.";

        return new DefenderScanResult(root, succeeded, threatFound, threatFound, remediationSucceeded, result.ExitCode, summary);
    }

    private async Task<(int ExitCode, string Output)> RunFastGateScanAsync(
        string root,
        IReadOnlyList<string> targets,
        Action<string> log,
        Action<int> progress,
        CancellationToken cancellationToken)
    {
        log("Running Microsoft Defender quick scan before USB access.");
        var quickScan = await RunAsync("-Scan -ScanType 1", null, cancellationToken);
        if (quickScan.ExitCode is not 0 and not 2)
            return quickScan;
        if (quickScan.ExitCode == 2)
            return quickScan;

        var output = new StringBuilder(quickScan.Output);
        var index = 0;
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            index++;
            progress(10 + (index * 75 / Math.Max(targets.Count, 1)));
            log($"Fast gate scan target {index}/{targets.Count}: {target}");
            var result = await RunAsync("-Scan -ScanType 3 -File", target, cancellationToken);
            output.AppendLine(result.Output);
            if (result.ExitCode is not 0)
                return (result.ExitCode, output.ToString());
        }

        if (targets.Count == 0)
            log($"No high-risk launch files were found on {root}; quick scan result is being used.");
        return (0, output.ToString());
    }

    private static ScanPlan BuildScanPlan(string root)
    {
        try
        {
            var drive = new DriveInfo(root);
            if (drive.IsReady && drive.TotalSize > FullScanSizeLimitBytes)
            {
                var targets = EnumerateFastGateTargets(root).ToArray();
                return new ScanPlan(
                    true,
                    targets,
                    $"Large USB storage detected ({FormatBytes(drive.TotalSize)}). Starting fast Defender safety scan of high-risk launch files; full scan remains recommended.");
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return new ScanPlan(false, Array.Empty<string>(), $"Starting Defender full custom scan of {root}");
    }

    private static IEnumerable<string> EnumerateFastGateTargets(string root)
    {
        foreach (var fileName in new[] { "autorun.inf", "desktop.ini" })
        {
            var path = Path.Combine(root, fileName);
            if (File.Exists(path))
                yield return path;
        }

        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.System | FileAttributes.Temporary
        };
        var count = 0;
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(root, "*", options);
        }
        catch (IOException)
        {
            yield break;
        }
        catch (UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var file in files)
        {
            if (!HighRiskExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                continue;
            yield return file;
            count++;
            if (count >= FastScanFileLimit)
                yield break;
        }
    }

    private static string FormatBytes(long bytes)
    {
        var gib = bytes / 1024d / 1024d / 1024d;
        return $"{gib:0.0} GB";
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

    private sealed record ScanPlan(bool FastGate, IReadOnlyList<string> Targets, string Description);
}

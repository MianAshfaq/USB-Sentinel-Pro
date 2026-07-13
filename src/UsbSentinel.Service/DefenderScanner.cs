using System.Diagnostics;
using System.Text;
using System.Text.Json;
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
    private static readonly HashSet<string> FastGateExcludedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "$Recycle.Bin", "Boot", "MSOCache", "PerfLogs", "Program Files",
        "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", "Windows"
    };
    private const long FullScanSizeLimitBytes = 64L * 1024 * 1024 * 1024;
    // Large disks use a focused Defender gate before access is approved. Keep the
    // total bounded so slow installers cannot make approval take several minutes.
    private const int DefaultFastScanFileLimit = 8;
    private const long FastGateFileSizeLimitBytes = 128L * 1024 * 1024;
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

    public async Task<bool> IsRealTimeProtectionEnabledAsync(CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var result = await RunProcessAsync(powershell,
            "-NoProfile -NonInteractive -Command \"(Get-MpComputerStatus).RealTimeProtectionEnabled\"",
            cancellationToken);
        return result.ExitCode == 0 && bool.TryParse(result.Output.Trim(), out var enabled) && enabled;
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
        CancellationToken cancellationToken,
        int fastTargetLimit = DefaultFastScanFileLimit)
    {
        var root = Path.GetPathRoot(drive) ?? drive;
        if (_mpCmdRun is null)
            return new DefenderScanResult(root, false, false, false, false, -1, "Microsoft Defender is unavailable.");
        progress(10);
        var plan = BuildScanPlan(root, fastTargetLimit);
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
        log("Running focused Microsoft Defender checks on USB launch files.");
        var output = new StringBuilder();
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
            log($"No high-risk launch files were found in the fast-gate locations on {root}.");
        return (0, output.ToString());
    }

    private static ScanPlan BuildScanPlan(string root, int fastTargetLimit)
    {
        try
        {
            var drive = new DriveInfo(root);
            if (drive.IsReady && drive.TotalSize > FullScanSizeLimitBytes)
            {
                var targets = EnumerateFastGateTargets(
                    root, Math.Clamp(fastTargetLimit, 1, DefaultFastScanFileLimit)).ToArray();
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

    private static IEnumerable<string> EnumerateFastGateTargets(string root, int targetLimit)
    {
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;
        foreach (var fileName in new[] { "autorun.inf", "desktop.ini" })
        {
            var path = Path.Combine(root, fileName);
            if (File.Exists(path) && emitted.Add(path))
            {
                yield return path;
                if (++count >= targetLimit)
                    yield break;
            }
        }

        foreach (var file in EnumerateHighRiskFiles(root, recurse: false))
        {
            if (!emitted.Add(file))
                continue;
            yield return file;
            if (++count >= targetLimit)
                yield break;
        }

        foreach (var directory in GetFastGateDirectories(root))
        {
            foreach (var file in EnumerateHighRiskFiles(directory, recurse: true))
            {
                if (!emitted.Add(file))
                    continue;
                yield return file;
                if (++count >= targetLimit)
                    yield break;
            }
        }
    }

    private static IEnumerable<string> GetFastGateDirectories(string root)
    {
        var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddDirectoryIfPresent(directories, Path.Combine(root, "Downloads"));

        try
        {
            var usersRoot = Path.Combine(root, "Users");
            if (Directory.Exists(usersRoot))
            {
                foreach (var userDirectory in Directory.EnumerateDirectories(usersRoot))
                {
                    AddDirectoryIfPresent(directories, Path.Combine(userDirectory, "Downloads"));
                    AddDirectoryIfPresent(directories, Path.Combine(userDirectory, "Desktop"));
                    AddDirectoryIfPresent(directories, Path.Combine(userDirectory, "Documents"));
                }
            }

            foreach (var directory in Directory.EnumerateDirectories(root))
            {
                if (!FastGateExcludedDirectories.Contains(Path.GetFileName(directory)))
                    directories.Add(directory);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return directories;
    }

    private static void AddDirectoryIfPresent(HashSet<string> directories, string path)
    {
        if (Directory.Exists(path))
            directories.Add(path);
    }

    private static IEnumerable<string> EnumerateHighRiskFiles(string directory, bool recurse)
    {
        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = recurse,
            AttributesToSkip = FileAttributes.System | FileAttributes.Temporary
        };
        try
        {
            return Directory.EnumerateFiles(directory, "*", options)
                .Where(file => HighRiskExtensions.Contains(
                    Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                .Where(IsFastGateFileSize);
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
        catch (UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
    }

    private static bool IsFastGateFileSize(string path)
    {
        try
        {
            return new FileInfo(path).Length <= FastGateFileSizeLimitBytes;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
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

    public async Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var result = await RunProcessAsync(powershell,
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-MpThreatDetection | Select-Object ThreatID,ThreatStatusID,InitialDetectionTime,Resources | ConvertTo-Json -Compress -Depth 6\"",
            cancellationToken);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Output))
            return Array.Empty<QuarantineItem>();

        try
        {
            using var document = JsonDocument.Parse(result.Output);
            var elements = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray()
                : new[] { document.RootElement }.AsEnumerable();
            return elements.Select(item => new QuarantineItem(
                GetJsonText(item, "ThreatID"),
                GetJsonText(item, "ThreatStatusID"),
                GetJsonText(item, "InitialDetectionTime"),
                GetJsonText(item, "Resources"))).ToArray();
        }
        catch (JsonException)
        {
            return Array.Empty<QuarantineItem>();
        }
    }

    public async Task<bool> RestoreQuarantineAsync(string threatId, CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var escaped = threatId.Replace("'", "''", StringComparison.Ordinal);
        var result = await RunProcessAsync(powershell,
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Restore-MpThreat -ThreatID '{escaped}' -ErrorAction Stop\"",
            cancellationToken);
        return result.ExitCode == 0;
    }

    public async Task<bool> DeleteQuarantineAsync(string threatId, CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var escaped = threatId.Replace("'", "''", StringComparison.Ordinal);
        var result = await RunProcessAsync(powershell,
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Remove-MpThreat -ThreatID '{escaped}' -ErrorAction Stop\"",
            cancellationToken);
        return result.ExitCode == 0;
    }

    private static string GetJsonText(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null)
            return "Unknown";
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "Unknown" : value.ToString();
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

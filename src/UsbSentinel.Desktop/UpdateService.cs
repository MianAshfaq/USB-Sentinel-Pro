using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;

namespace UsbSentinel.Desktop;

public sealed record AppUpdateInfo(string Version, string DownloadUrl);

public sealed class UpdateService
{
    private const string LatestReleaseUrl = "https://github.com/MianAshfaq/USB-Sentinel-Pro/releases/latest";
    private const string DownloadTemplate = "https://github.com/MianAshfaq/USB-Sentinel-Pro/releases/download/{0}/USB-Sentinel-Pro-Setup.msi";

    public async Task<AppUpdateInfo?> CheckAsync(CancellationToken token = default)
    {
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("USB-Sentinel-Pro-Updater");
        using var response = await client.GetAsync(LatestReleaseUrl, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode is not System.Net.HttpStatusCode.MovedPermanently and
            not System.Net.HttpStatusCode.Found and not System.Net.HttpStatusCode.SeeOther)
            return null;
        var location = response.Headers.Location?.ToString();
        var tag = location?.TrimEnd('/').Split('/').LastOrDefault();
        if (string.IsNullOrWhiteSpace(tag) || !TryVersion(tag, out var latest))
            return null;
        var current = Assembly.GetEntryAssembly()?.GetName().Version ?? new Version(0, 0);
        return latest > current ? new AppUpdateInfo(tag, string.Format(DownloadTemplate, tag)) : null;
    }

    public async Task<bool> DownloadAndStartAsync(AppUpdateInfo update, CancellationToken token = default)
    {
        using var client = new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("USB-Sentinel-Pro-Updater");
        var path = Path.Combine(Path.GetTempPath(), $"USB-Sentinel-Pro-{update.Version}.msi");
        await using (var input = await client.GetStreamAsync(update.DownloadUrl, token))
        await using (var output = File.Create(path))
            await input.CopyToAsync(output, token);
        Process.Start(new ProcessStartInfo("msiexec.exe", $"/i \"{path}\"") { UseShellExecute = true });
        return true;
    }

    private static bool TryVersion(string tag, out Version version)
    {
        version = new Version(0, 0);
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var parsed) || parsed is null)
            return false;
        version = parsed;
        return true;
    }
}

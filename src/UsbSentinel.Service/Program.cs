using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UsbSentinel.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "USB Sentinel Pro Service");
builder.Services.AddSingleton<LogRepository>();
builder.Services.AddSingleton<SettingsRepository>();
builder.Services.AddSingleton<PasswordRepository>();
builder.Services.AddSingleton<UsbPolicyController>();
builder.Services.AddSingleton<UsbDriveInventory>();
builder.Services.AddSingleton<DefenderScanner>();
builder.Services.AddSingleton<SentinelCoordinator>();
builder.Services.AddSingleton<PipeServer>();
builder.Services.AddHostedService<SentinelWorker>();
builder.Services.AddHostedService<DefenderSignatureWorker>();

await builder.Build().RunAsync();

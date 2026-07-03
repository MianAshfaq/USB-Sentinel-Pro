using System.IO;
using System.Windows;
using System.Windows.Threading;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;

namespace UsbSentinel.Desktop;

public partial class App : System.Windows.Application
{
    private Forms.NotifyIcon? _trayIcon;
    private bool _exitRequested;
    private bool _hideNoticeShown;

    public bool ExitRequested => _exitRequested;

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        base.OnStartup(e);
        CreateTrayIcon();
    }

    private void CreateTrayIcon()
    {
        var resource = GetResourceStream(new Uri("pack://application:,,,/Assets/UsbSentinel.ico"))
            ?? throw new InvalidOperationException("The tray icon resource is missing.");
        using var iconStream = resource.Stream;
        using var sourceIcon = new Drawing.Icon(iconStream);
        _trayIcon = new Forms.NotifyIcon
        {
            Icon = (Drawing.Icon)sourceIcon.Clone(),
            Text = "USB Sentinel Pro - monitoring USB storage",
            Visible = true,
            ContextMenuStrip = new Forms.ContextMenuStrip()
        };
        _trayIcon.ContextMenuStrip.Items.Add("Open USB Sentinel Pro", null, (_, _) => Dispatcher.Invoke(ShowMainWindow));
        _trayIcon.ContextMenuStrip.Items.Add(new Forms.ToolStripSeparator());
        _trayIcon.ContextMenuStrip.Items.Add("Exit", null, (_, _) => Dispatcher.Invoke(RequestExit));
        _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowMainWindow);
    }

    public void HideToTray()
    {
        MainWindow?.Hide();
        if (_hideNoticeShown)
            return;
        _hideNoticeShown = true;
        ShowTrayNotification("USB Sentinel Pro", "USB monitoring continues in the system tray.", false);
    }

    public void ShowMainWindow()
    {
        if (MainWindow is null)
            return;
        MainWindow.Show();
        MainWindow.WindowState = WindowState.Maximized;
        MainWindow.Activate();
    }

    public void ShowTrayNotification(string title, string message, bool warning)
    {
        _trayIcon?.ShowBalloonTip(
            5000,
            title,
            message,
            warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
    }

    public void UpdateTrayStatus(string status)
    {
        if (_trayIcon is null)
            return;
        var text = $"USB Sentinel Pro - {status}";
        _trayIcon.Text = text.Length <= 63 ? text : text[..63];
    }

    private void RequestExit()
    {
        _exitRequested = true;
        MainWindow?.Close();
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        base.OnExit(e);
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        _exitRequested = true;
        base.OnSessionEnding(e);
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "USB Sentinel Pro");
            Directory.CreateDirectory(directory);
            File.AppendAllText(
                Path.Combine(directory, "desktop-errors.log"),
                $"[{DateTimeOffset.Now:O}] {e.Exception}\n\n");
        }
        catch
        {
            // Error reporting must never terminate the security dashboard.
        }

        e.Handled = true;
    }
}

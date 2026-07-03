using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace UsbSentinel.Desktop;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private bool _scrollPending;
    private bool _passwordDialogOpen;
    private bool _setupPromptShown;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel(Dispatcher);
        DataContext = _viewModel;
        _viewModel.PasswordPrompt = ShowPasswordDialog;
        _viewModel.ChangePasswordPrompt = ShowChangePasswordDialog;
        _viewModel.FormatUsbPrompt = ShowFormatUsbDialog;
        _viewModel.PostOperationEnablePrompt = ShowPostOperationEnablePrompt;
        _viewModel.PasswordSetupRequired += OnPasswordSetupRequired;
        _viewModel.TrayStatusChanged += status => ((App)System.Windows.Application.Current).UpdateTrayStatus(status);
        _viewModel.TrayNotificationRequested += (title, message, warning) =>
            ((App)System.Windows.Application.Current).ShowTrayNotification(title, message, warning);
        _viewModel.Logs.CollectionChanged += ScrollLogs;
        Loaded += OnLoaded;
        Closed += (_, _) => _viewModel.Dispose();
        Closing += OnClosing;
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        var app = (App)System.Windows.Application.Current;
        if (app.ExitRequested)
            return;
        e.Cancel = true;
        app.HideToTray();
    }

    private void OnPasswordSetupRequired(object? sender, EventArgs e)
    {
        if (_setupPromptShown)
            return;
        _setupPromptShown = true;
        Dispatcher.BeginInvoke(async () =>
        {
            if (_passwordDialogOpen || _viewModel.PasswordConfigured)
                return;
            var password = ShowPasswordDialog(true);
            if (!string.IsNullOrEmpty(password))
                await _viewModel.ConfigureFirstRunPasswordAsync(password);
        });
    }

    private string? ShowPasswordDialog(bool firstRun)
    {
        if (_passwordDialogOpen)
            return null;
        _passwordDialogOpen = true;
        try
        {
            var dialog = new PasswordDialog(firstRun) { Owner = this };
            return dialog.ShowDialog() == true ? dialog.Password : null;
        }
        finally
        {
            _passwordDialogOpen = false;
        }
    }

    private (string CurrentPassword, string NewPassword)? ShowChangePasswordDialog()
    {
        var dialog = new ChangePasswordDialog { Owner = this };
        return dialog.ShowDialog() == true
            ? (dialog.CurrentPassword, dialog.NewPassword)
            : null;
    }

    private FormatUsbRequest? ShowFormatUsbDialog(IReadOnlyList<string> drives)
    {
        var dialog = new FormatUsbDialog(drives) { Owner = this };
        return dialog.ShowDialog() == true ? dialog.Request : null;
    }

    private bool ShowPostOperationEnablePrompt(string message) =>
        MessageBox.Show(this, message, "USB verification required",
            MessageBoxButton.YesNo, MessageBoxImage.Information, MessageBoxResult.No) == MessageBoxResult.Yes;

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await _viewModel.StartAsync();
    }

    private void ScrollLogs(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (_scrollPending)
            return;

        _scrollPending = true;
        Dispatcher.BeginInvoke(() =>
        {
            _scrollPending = false;
            if (LogList.Items.Count > 0)
                LogList.ScrollIntoView(LogList.Items[^1]);
        }, System.Windows.Threading.DispatcherPriority.ContextIdle);
    }
}

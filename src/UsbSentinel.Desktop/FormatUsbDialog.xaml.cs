using System.Windows;
using System.Windows.Controls;
using MessageBox = System.Windows.MessageBox;

namespace UsbSentinel.Desktop;

public partial class FormatUsbDialog : Window
{
    public IReadOnlyList<string> Drives { get; }
    public FormatUsbRequest? Request { get; private set; }

    public FormatUsbDialog(IReadOnlyList<string> drives)
    {
        Drives = drives;
        InitializeComponent();
        DataContext = this;
        DriveBox.SelectedIndex = drives.Count > 0 ? 0 : -1;
        UpdatePhrase();
    }

    private void DriveChanged(object sender, SelectionChangedEventArgs e) => UpdatePhrase();

    private void UpdatePhrase()
    {
        var drive = DriveBox.SelectedItem as string;
        PhraseHelp.Text = drive is null ? "Select a USB volume." : $"Type ERASE {drive[..2]} to confirm";
    }

    private void ConfirmClick(object sender, RoutedEventArgs e)
    {
        if (DriveBox.SelectedItem is not string drive || string.IsNullOrWhiteSpace(PasswordBox.Password))
        {
            MessageBox.Show(this, "Select a USB volume and enter the administrator password.", "USB Sentinel Pro",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var expected = $"ERASE {drive[..2]}";
        if (!string.Equals(ConfirmationBox.Text, expected, StringComparison.Ordinal))
        {
            MessageBox.Show(this, $"Type {expected} exactly to continue.", "Confirmation required",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (MessageBox.Show(this, $"Erase every file on {drive}? This cannot be undone.", "Final format warning",
                MessageBoxButton.YesNo, MessageBoxImage.Stop, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        var fileSystem = ((ComboBoxItem)FileSystemBox.SelectedItem).Content.ToString() ?? "exFAT";
        Request = new FormatUsbRequest(drive, PasswordBox.Password, expected, QuickBox.IsChecked == true, fileSystem);
        DialogResult = true;
    }
}

public sealed record FormatUsbRequest(
    string Drive, string Password, string Confirmation, bool QuickFormat, string FileSystem);

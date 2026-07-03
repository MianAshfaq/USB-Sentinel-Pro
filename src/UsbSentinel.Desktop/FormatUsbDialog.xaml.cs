using System.Windows;
using System.Windows.Controls;
using System.IO;
using MessageBox = System.Windows.MessageBox;

namespace UsbSentinel.Desktop;

public partial class FormatUsbDialog : Window
{
    public IReadOnlyList<DriveChoice> DriveChoices { get; }
    public FormatUsbRequest? Request { get; private set; }

    public FormatUsbDialog(IReadOnlyList<string> drives)
    {
        DriveChoices = drives.Select(CreateDriveChoice).ToArray();
        InitializeComponent();
        DataContext = this;
        DriveBox.SelectedIndex = drives.Count > 0 ? 0 : -1;
        UpdatePhrase();
    }

    private void DriveChanged(object sender, SelectionChangedEventArgs e) => UpdatePhrase();

    private void UpdatePhrase()
    {
        var drive = (DriveBox.SelectedItem as DriveChoice)?.Root;
        PhraseHelp.Text = drive is null ? "Select a USB volume." : $"Type ERASE {drive[..2]} to confirm";
    }

    private void ConfirmClick(object sender, RoutedEventArgs e)
    {
        if (DriveBox.SelectedItem is not DriveChoice choice || string.IsNullOrWhiteSpace(PasswordBox.Password))
        {
            MessageBox.Show(this, "Select a USB volume and enter the administrator password.", "USB Sentinel Pro",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var drive = choice.Root;
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

    private static DriveChoice CreateDriveChoice(string root)
    {
        try
        {
            var drive = new DriveInfo(root);
            var size = drive.IsReady ? $"{drive.TotalSize / 1_073_741_824d:0.0} GB" : "size unavailable";
            var label = drive.IsReady && !string.IsNullOrWhiteSpace(drive.VolumeLabel) ? drive.VolumeLabel : "No label";
            var format = drive.IsReady ? drive.DriveFormat : "Unknown";
            return new DriveChoice(root, $"{root}  |  {label}  |  {size}  |  {format}");
        }
        catch (IOException) { return new DriveChoice(root, $"{root}  |  details unavailable"); }
        catch (UnauthorizedAccessException) { return new DriveChoice(root, $"{root}  |  details unavailable"); }
    }
}

public sealed record DriveChoice(string Root, string Summary);

public sealed record FormatUsbRequest(
    string Drive, string Password, string Confirmation, bool QuickFormat, string FileSystem);

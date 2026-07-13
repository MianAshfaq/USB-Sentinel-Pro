using System.Windows;
using UsbSentinel.Contracts;
using MessageBox = System.Windows.MessageBox;

namespace UsbSentinel.Desktop;

public partial class QuarantineDialog : Window
{
    public IReadOnlyList<QuarantineRow> Items { get; }
    public QuarantineActionRequest? Request { get; private set; }

    public QuarantineDialog(IReadOnlyList<QuarantineItem> items)
    {
        Items = items.Select(item => new QuarantineRow(item)).ToArray();
        InitializeComponent();
        DataContext = this;
    }

    private void RestoreClick(object sender, RoutedEventArgs e) => Complete("Restore");
    private void DeleteClick(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Delete the selected Defender detection permanently?", "Confirm deletion",
                MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes)
            Complete("Delete");
    }

    private void Complete(string action)
    {
        if (ItemsList.SelectedItem is not QuarantineRow row)
        {
            MessageBox.Show(this, "Select a quarantine detection first.", "Defender quarantine",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Request = new QuarantineActionRequest(action, row.ThreatId);
        DialogResult = true;
    }

    public sealed record QuarantineRow(string ThreatId, string Summary)
    {
        public QuarantineRow(QuarantineItem item)
            : this(item.ThreatId, $"Threat {item.ThreatId} | Status {item.Status} | {item.DetectedAt}\n{item.Resources}") { }
    }
}

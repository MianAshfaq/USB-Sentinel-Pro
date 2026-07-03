using System.Windows;

namespace UsbSentinel.Desktop;

public partial class ChangePasswordDialog : Window
{
    public ChangePasswordDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => CurrentInput.Focus();
    }

    public string CurrentPassword => CurrentInput.Password;
    public string NewPassword => NewInput.Password;

    private void SaveClick(object sender, RoutedEventArgs e)
    {
        if (NewInput.Password.Length < 8 || !NewInput.Password.Any(char.IsLetter) || !NewInput.Password.Any(char.IsDigit))
        {
            ErrorText.Text = "Use at least 8 characters with a letter and a number.";
            return;
        }
        if (NewInput.Password != ConfirmInput.Password)
        {
            ErrorText.Text = "The new passwords do not match.";
            return;
        }
        DialogResult = true;
    }

    private void CancelClick(object sender, RoutedEventArgs e) => DialogResult = false;
}

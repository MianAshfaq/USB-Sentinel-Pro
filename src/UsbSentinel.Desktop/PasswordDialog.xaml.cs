using System.Windows;

namespace UsbSentinel.Desktop;

public partial class PasswordDialog : Window
{
    private readonly bool _firstRun;

    public PasswordDialog(bool firstRun)
    {
        InitializeComponent();
        _firstRun = firstRun;
        if (firstRun)
        {
            Heading.Text = "Create security password";
            Description.Text = "This password will be required every time USB access is enabled. Use at least 8 characters with a letter and a number.";
            ConfirmButton.Content = "CREATE PASSWORD";
        }
        else
        {
            ConfirmPanel.Visibility = Visibility.Collapsed;
        }
        Loaded += (_, _) => PasswordInput.Focus();
    }

    public string Password => PasswordInput.Password;

    public void UseResetMode()
    {
        Heading.Text = "Reset security password";
        Description.Text = "Create a replacement password with at least 8 characters, one letter, and one number.";
        ConfirmButton.Content = "RESET PASSWORD";
    }

    private void ConfirmClick(object sender, RoutedEventArgs e)
    {
        if (PasswordInput.Password.Length < 8 ||
            !PasswordInput.Password.Any(char.IsLetter) ||
            !PasswordInput.Password.Any(char.IsDigit))
        {
            ErrorText.Text = "Use at least 8 characters with a letter and a number.";
            return;
        }

        if (_firstRun && PasswordInput.Password != ConfirmInput.Password)
        {
            ErrorText.Text = "The confirmation password does not match.";
            return;
        }

        DialogResult = true;
    }

    private void CancelClick(object sender, RoutedEventArgs e) => DialogResult = false;
}

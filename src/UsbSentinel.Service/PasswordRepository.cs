using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace UsbSentinel.Service;

public sealed class PasswordRepository(LogRepository logs)
{
    private const int Iterations = 210_000;
    private readonly object _gate = new();
    private int _failedAttempts;
    private DateTimeOffset _lockedUntil;

    public bool IsConfigured
    {
        get
        {
            using var connection = new SqliteConnection(logs.ConnectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM SecuritySecrets WHERE Name = 'EnablePassword';";
            return Convert.ToInt64(command.ExecuteScalar()) > 0;
        }
    }

    public bool TryCreate(string password, out string error)
    {
        lock (_gate)
        {
            if (IsConfigured)
            {
                error = "An enable password is already configured.";
                return false;
            }

            if (!ValidateStrength(password, out error))
                return false;

            var salt = RandomNumberGenerator.GetBytes(32);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
            try
            {
                using var connection = new SqliteConnection(logs.ConnectionString);
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText =
                    "INSERT INTO SecuritySecrets(Name, Salt, Hash, Iterations) VALUES('EnablePassword', $salt, $hash, $iterations);";
                command.Parameters.AddWithValue("$salt", salt);
                command.Parameters.AddWithValue("$hash", hash);
                command.Parameters.AddWithValue("$iterations", Iterations);
                command.ExecuteNonQuery();
                error = string.Empty;
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
    }

    public bool Verify(string? password, out string error)
    {
        lock (_gate)
        {
            if (DateTimeOffset.UtcNow < _lockedUntil)
            {
                error = $"Too many failed attempts. Try again in {Math.Ceiling((_lockedUntil - DateTimeOffset.UtcNow).TotalSeconds)} seconds.";
                return false;
            }
        }

        if (string.IsNullOrEmpty(password))
        {
            error = "Password is required.";
            return false;
        }

        using var connection = new SqliteConnection(logs.ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Salt, Hash, Iterations FROM SecuritySecrets WHERE Name = 'EnablePassword';";
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            error = "Create the first-run password before enabling USB.";
            return false;
        }

        var salt = (byte[])reader[0];
        var expected = (byte[])reader[1];
        var iterations = reader.GetInt32(2);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        var valid = CryptographicOperations.FixedTimeEquals(actual, expected);
        CryptographicOperations.ZeroMemory(actual);

        lock (_gate)
        {
            if (valid)
            {
                _failedAttempts = 0;
                _lockedUntil = default;
                error = string.Empty;
                return true;
            }

            _failedAttempts++;
            if (_failedAttempts >= 5)
            {
                _failedAttempts = 0;
                _lockedUntil = DateTimeOffset.UtcNow.AddSeconds(30);
            }
        }

        error = "Incorrect password.";
        return false;
    }

    public bool TryChange(string? currentPassword, string? newPassword, out string error)
    {
        if (!Verify(currentPassword, out error))
            return false;
        if (newPassword is null || !ValidateStrength(newPassword, out error))
            return false;

        var salt = RandomNumberGenerator.GetBytes(32);
        var hash = Rfc2898DeriveBytes.Pbkdf2(newPassword, salt, Iterations, HashAlgorithmName.SHA256, 32);
        try
        {
            using var connection = new SqliteConnection(logs.ConnectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "UPDATE SecuritySecrets SET Salt = $salt, Hash = $hash, Iterations = $iterations WHERE Name = 'EnablePassword';";
            command.Parameters.AddWithValue("$salt", salt);
            command.Parameters.AddWithValue("$hash", hash);
            command.Parameters.AddWithValue("$iterations", Iterations);
            if (command.ExecuteNonQuery() != 1)
            {
                error = "Password configuration was not found.";
                return false;
            }
            error = string.Empty;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static bool ValidateStrength(string password, out string error)
    {
        if (password.Length < 8 || !password.Any(char.IsLetter) || !password.Any(char.IsDigit))
        {
            error = "Use at least 8 characters with a letter and a number.";
            return false;
        }

        error = string.Empty;
        return true;
    }
}

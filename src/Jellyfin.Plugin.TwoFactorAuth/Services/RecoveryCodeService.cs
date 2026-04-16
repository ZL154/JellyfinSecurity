using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Generates and validates one-time recovery codes for account recovery when
/// the user loses access to their TOTP authenticator app.
/// Codes are stored as SHA-256 hashes; the plaintext is shown once at generation.
/// Format: 10 codes, 10 chars each (5+5 with hyphen for readability), letters+digits only.
/// </summary>
public class RecoveryCodeService
{
    private const int CodeCount = 10;
    private const int CodeLength = 10;
    // Avoid ambiguous chars: 0/O, 1/I/L
    private const string ValidChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    /// <summary>
    /// Generate a fresh batch of recovery codes. Returns plaintext codes (to display once)
    /// and hash records (to persist). Old codes are wiped.
    /// </summary>
    public (List<string> plaintextCodes, List<RecoveryCode> records) GenerateCodes()
    {
        var plaintexts = new List<string>(CodeCount);
        var records = new List<RecoveryCode>(CodeCount);

        for (int i = 0; i < CodeCount; i++)
        {
            var code = GenerateOne();
            plaintexts.Add(FormatForDisplay(code));
            records.Add(new RecoveryCode
            {
                Hash = HashCode(code),
                Used = false,
                UsedAt = null,
            });
        }

        return (plaintexts, records);
    }

    private static string GenerateOne()
    {
        var sb = new StringBuilder(CodeLength);
        for (int i = 0; i < CodeLength; i++)
        {
            sb.Append(ValidChars[RandomNumberGenerator.GetInt32(ValidChars.Length)]);
        }
        return sb.ToString();
    }

    private static string FormatForDisplay(string code)
    {
        if (code.Length != CodeLength) return code;
        return code.Substring(0, 5) + "-" + code.Substring(5);
    }

    public static string NormalizeForCompare(string submitted)
    {
        return submitted.Replace("-", "").Replace(" ", "").ToUpperInvariant();
    }

    public static string HashCode(string normalized)
    {
        var bytes = Encoding.UTF8.GetBytes(normalized);
        return Convert.ToBase64String(SHA256.HashData(bytes));
    }
}

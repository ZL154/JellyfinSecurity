using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Generates and validates one-time recovery codes for account recovery when
/// the user loses access to their TOTP authenticator app.
///
/// Storage: PBKDF2-SHA256, 100k iterations, per-code salt. Format string:
/// `v2$iter$saltB64$hashB64`. Previously stored v1 (unsalted SHA-256 base64)
/// is still accepted on validate — any legacy code, once used, is consumed
/// and future generations write v2. Plaintext is shown once at generation.
/// Format: 10 codes, 10 chars each (5+5 with hyphen for readability), letters+digits only.
/// </summary>
public class RecoveryCodeService
{
    private const int CodeCount = 10;
    private const int CodeLength = 10;
    private const int PbkdfIterations = 100_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

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
                Hash = HashCodeV2(code),
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

    /// <summary>PBKDF2-hash a normalized code for storage. v2 format.</summary>
    public static string HashCodeV2(string normalized)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(normalized),
            salt,
            PbkdfIterations,
            HashAlgorithmName.SHA256,
            HashBytes);
        return $"v2${PbkdfIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>Constant-time verify against a stored hash. Supports v2 (PBKDF2)
    /// and v1 (legacy unsalted SHA-256) for smooth upgrade.</summary>
    public static bool Verify(string normalized, string storedHash)
    {
        if (string.IsNullOrEmpty(storedHash)) return false;

        if (storedHash.StartsWith("v2$", StringComparison.Ordinal))
        {
            var parts = storedHash.Split('$');
            if (parts.Length != 4) return false;
            if (!int.TryParse(parts[1], out var iter) || iter <= 0 || iter > 10_000_000) return false;
            byte[] salt, expected;
            try
            {
                salt = Convert.FromBase64String(parts[2]);
                expected = Convert.FromBase64String(parts[3]);
            }
            catch { return false; }
            var computed = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(normalized),
                salt,
                iter,
                HashAlgorithmName.SHA256,
                expected.Length);
            return CryptographicOperations.FixedTimeEquals(computed, expected);
        }

        // v1 legacy: bare base64(sha256(utf8(code))). Still constant-time compared.
        byte[] legacyStored;
        try { legacyStored = Convert.FromBase64String(storedHash); }
        catch { return false; }
        var legacyComputed = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        if (legacyStored.Length != legacyComputed.Length) return false;
        return CryptographicOperations.FixedTimeEquals(legacyComputed, legacyStored);
    }
}

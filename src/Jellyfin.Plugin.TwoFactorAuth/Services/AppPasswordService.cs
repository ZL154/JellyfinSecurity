using System;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Generates app-specific passwords and verifies them against PBKDF2-SHA256 hashes.
/// Format on disk: "v1$iterations$saltBase64$hashBase64".
/// Iteration count is intentionally high (200_000) — these are auth-critical
/// secrets, and the verify path runs once per native-client login.
/// </summary>
public class AppPasswordService
{
    private const int Iterations = 200_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    /// <summary>Returns (plaintextShownToUser, hashToStore).</summary>
    public (string plaintext, string hash) Generate()
    {
        // 24 bytes -> 32 base32 chars. Display in 4-char groups for readability.
        var raw = RandomNumberGenerator.GetBytes(24);
        var b32 = Base32Encode(raw);
        var grouped = string.Join("-", Chunk(b32, 4));
        var hash = HashPassword(grouped);
        return (grouped, hash);
    }

    public string HashPassword(string plaintext)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var derived = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(plaintext),
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashBytes);
        return $"v1${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(derived)}";
    }

    public bool Verify(string plaintext, string storedHash)
    {
        if (string.IsNullOrEmpty(plaintext) || string.IsNullOrEmpty(storedHash)) return false;
        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != "v1") return false;
        if (!int.TryParse(parts[1], out var iterations)) return false;

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch { return false; }

        var actual = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(plaintext),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Find the matching app password for a user, or null. Constant-time
    /// per entry: every entry is checked even after a match to avoid timing leaks
    /// about list size.</summary>
    public AppPassword? FindMatch(string plaintext, IEnumerable<AppPassword> entries)
    {
        AppPassword? matched = null;
        foreach (var ap in entries)
        {
            if (Verify(plaintext, ap.PasswordHash) && matched is null)
            {
                matched = ap;
                // don't break — keep iterating to keep timing flat
            }
        }

        return matched;
    }

    // ---------- helpers ----------

    private static IEnumerable<string> Chunk(string s, int n)
    {
        for (var i = 0; i < s.Length; i += n)
        {
            yield return s.Substring(i, Math.Min(n, s.Length - i));
        }
    }

    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static string Base32Encode(byte[] data)
    {
        var sb = new StringBuilder();
        var bits = 0;
        var value = 0;
        foreach (var b in data)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(Base32Alphabet[(value >> bits) & 0x1F]);
            }
        }
        if (bits > 0)
        {
            sb.Append(Base32Alphabet[(value << (5 - bits)) & 0x1F]);
        }
        return sb.ToString();
    }
}

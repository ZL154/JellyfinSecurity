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
        // Reject implausible parameters: prevents a tampered hash from forcing
        // the server to waste CPU on an absurd iteration count / derive size.
        if (iterations < 50_000 || iterations > 2_000_000) return false;

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch { return false; }
        if (salt.Length < 8 || salt.Length > 64) return false;
        if (expected.Length != HashBytes) return false;

        var actual = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(plaintext),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HashBytes);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Find the matching app password for a user, or null.
    /// Runs at least one PBKDF2 probe regardless of list size so an attacker
    /// can't tell empty-list vs. populated-list from timing alone.</summary>
    public AppPassword? FindMatch(string plaintext, IEnumerable<AppPassword> entries)
    {
        AppPassword? matched = null;
        var probedAny = false;
        foreach (var ap in entries)
        {
            probedAny = true;
            if (Verify(plaintext, ap.PasswordHash) && matched is null)
            {
                matched = ap;
                // don't break — keep iterating to keep timing flat
            }
        }

        // No entries: do one dummy PBKDF2 so total time is indistinguishable
        // from a single-entry probe.
        if (!probedAny)
        {
            Verify(plaintext, $"v1${Iterations}${Convert.ToBase64String(_dummySalt)}${Convert.ToBase64String(_dummyHash)}");
        }

        return matched;
    }

    // Stable dummy salt/hash for the empty-list timing mask. Never actually
    // matches any real password (the hash is random and unrelated).
    private static readonly byte[] _dummySalt = RandomNumberGenerator.GetBytes(SaltBytes);
    private static readonly byte[] _dummyHash = RandomNumberGenerator.GetBytes(HashBytes);

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

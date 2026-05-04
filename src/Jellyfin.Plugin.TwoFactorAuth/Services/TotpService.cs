using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using MediaBrowser.Common.Configuration;
using Microsoft.Extensions.Logging;
using OtpNet;
using QRCoder;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class TotpService
{
    private readonly byte[] _encryptionKey;
    private readonly ILogger<TotpService> _logger;

    // Per-user replay protection: userId -> (timeStepMatched -> placeholder)
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<long, byte>> _usedTimeSteps = new();

    public TotpService(IApplicationPaths applicationPaths, ILogger<TotpService> logger)
    {
        _logger = logger;
        _encryptionKey = LoadOrCreateKey(applicationPaths);
    }

    /// <summary>
    /// Loads a persistent 32-byte AES key from the plugin data directory, creating one if needed.
    /// This survives Jellyfin restarts so encrypted TOTP secrets remain decryptable.
    /// Unix: chmod 0600. Windows: inherits plugin-dir ACLs — admins should
    /// ensure the plugin dir is restricted to the Jellyfin service account.
    /// </summary>
    private byte[] LoadOrCreateKey(IApplicationPaths applicationPaths)
    {
        var pluginDir = Path.Combine(applicationPaths.PluginConfigurationsPath, "TwoFactorAuth");
        Directory.CreateDirectory(pluginDir);
        var keyPath = Path.Combine(pluginDir, "secret.key");

        if (File.Exists(keyPath))
        {
            try
            {
                var bytes = File.ReadAllBytes(keyPath);
                if (bytes.Length == 32)
                {
                    // SEC-L9: reapply 0600 on every load. A file created by an
                    // older plugin version, restored from a backup, or copied
                    // by the admin may have lax perms. Repeating chmod is
                    // cheap and idempotent.
                    TryChmod0600(keyPath);
                    return bytes;
                }
                _logger.LogWarning("Existing secret.key is not 32 bytes — regenerating");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read existing secret.key — regenerating");
            }
        }

        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(keyPath, key);
        TryChmod0600(keyPath);

        _logger.LogInformation("Generated new persistent encryption key at {Path}", keyPath);
        return key;
    }

    private static void TryChmod0600(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch { /* best effort */ }
    }

    public (string secret, string qrCodeBase64, string manualEntryKey) GenerateSecret(string username)
    {
        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var manualEntryKey = Base32Encoding.ToString(secretBytes);

        var issuer = Plugin.Instance?.Configuration.TotpIssuerName;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = "Jellyfin";
        var encodedIssuer = Uri.EscapeDataString(issuer);
        var uri = $"otpauth://totp/{encodedIssuer}:{Uri.EscapeDataString(username)}?secret={manualEntryKey}&issuer={encodedIssuer}";

        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.M);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var pngBytes = qrCode.GetGraphic(5);
        var qrCodeBase64 = Convert.ToBase64String(pngBytes);

        _logger.LogInformation("Generated new TOTP secret for user '{Username}'", username);
        return (manualEntryKey, qrCodeBase64, manualEntryKey);
    }

    /// <summary>
    /// Encrypts a base32-encoded TOTP secret using AES-GCM with the persistent key.
    /// SEC-M3: when userId is provided, binds the ciphertext to that user via
    /// AAD so an attacker with file-system write access can't swap blobs
    /// between users' JSON files to log in as another user. Output format:
    ///   v2: "v2:" + base64( nonce[12] | ciphertext | tag[16] )  (AAD = userId.ToByteArray())
    ///   v1 (legacy, no AAD): base64( nonce[12] | ciphertext | tag[16] )
    /// New writes are always v2 when userId is supplied. Decrypt accepts both.
    /// </summary>
    public string EncryptSecret(string base32Secret, Guid? userId = null)
    {
        var plaintext = Encoding.UTF8.GetBytes(base32Secret);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(_encryptionKey, 16);
        if (userId.HasValue && userId.Value != Guid.Empty)
        {
            var aad = userId.Value.ToByteArray();
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        else
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var result = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);
        var b64 = Convert.ToBase64String(result);
        return userId.HasValue && userId.Value != Guid.Empty ? "v2:" + b64 : b64;
    }

    public string DecryptSecret(string encryptedSecret, Guid? userId = null)
    {
        // SEC-M3: detect v2 (AAD-bound) vs v1 (legacy, no AAD). The "v2:"
        // prefix is unambiguous — base64 alphabet does not contain ':'. v1
        // ciphertexts are still accepted to keep existing enrollments working
        // until they next rotate; they auto-upgrade to v2 on next save.
        bool isV2 = encryptedSecret.StartsWith("v2:", StringComparison.Ordinal);
        var b64 = isV2 ? encryptedSecret.Substring(3) : encryptedSecret;
        var bytes = Convert.FromBase64String(b64);
        if (bytes.Length < 12 + 16)
        {
            throw new CryptographicException("Ciphertext too short");
        }

        var nonce = new byte[12];
        var tag = new byte[16];
        var ciphertext = new byte[bytes.Length - 12 - 16];
        Buffer.BlockCopy(bytes, 0, nonce, 0, 12);
        Buffer.BlockCopy(bytes, 12, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(bytes, bytes.Length - 16, tag, 0, 16);

        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_encryptionKey, 16);
        if (isV2)
        {
            if (!userId.HasValue || userId.Value == Guid.Empty)
            {
                throw new CryptographicException("v2 ciphertext requires userId for decrypt");
            }
            var aad = userId.Value.ToByteArray();
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        else
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>SEC-M3 migration helper: re-encrypt a v1 (no-AAD) ciphertext
    /// as v2 bound to userId. Returns the v2 string. Idempotent — already-v2
    /// inputs are returned unchanged. Errors are logged and the original
    /// returned so a corrupt blob doesn't lock the user out (they can
    /// re-enroll).</summary>
    public string? MigrateToV2(string? encryptedSecret, Guid userId)
    {
        if (string.IsNullOrEmpty(encryptedSecret)) return encryptedSecret;
        if (encryptedSecret.StartsWith("v2:", StringComparison.Ordinal)) return encryptedSecret;
        try
        {
            var plaintext = DecryptSecret(encryptedSecret, null);
            return EncryptSecret(plaintext, userId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] TOTP secret v1->v2 migration failed for user {UserId}", userId);
            return encryptedSecret;
        }
    }

    /// <summary>Validate a TOTP code with replay protection. SEC-M4: callers
    /// may pass <paramref name="persistedFloor"/> = the last-used time-step
    /// previously persisted to the user's record across restarts. Codes at
    /// or below that floor are rejected (catches a replay window that
    /// otherwise re-opens after a Jellyfin restart, since the in-memory
    /// _usedTimeSteps cache is empty post-boot). On success, the matched
    /// time-step is reported via <paramref name="acceptedStep"/> so the
    /// caller can persist it.</summary>
    public bool ValidateCode(string base32Secret, string code, string userId, long persistedFloor, out long acceptedStep)
    {
        acceptedStep = 0;
        if (string.IsNullOrWhiteSpace(code) || code.Length != 6)
        {
            return false;
        }

        byte[] secretBytes;
        try
        {
            secretBytes = Base32Encoding.ToBytes(base32Secret);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to decode base32 secret for user '{UserId}'", userId);
            return false;
        }

        var totp = new Totp(secretBytes, step: 30, totpSize: 6);
        var window = new VerificationWindow(previous: 1, future: 1);
        var isValid = totp.VerifyTotp(code, out long timeStepMatched, window);

        if (!isValid)
        {
            return false;
        }

        // SEC-M4: persisted floor catches restarts. The 30s step cadence
        // means a captured code was usable for up to one window; if the
        // server restarted mid-window, the in-memory cache forgot. Floor
        // lets us still reject it on resumption.
        if (timeStepMatched <= persistedFloor)
        {
            _logger.LogWarning("Replay rejected (persisted floor) for user '{UserId}' step={Step} floor={Floor}",
                userId, timeStepMatched, persistedFloor);
            return false;
        }

        var userSteps = _usedTimeSteps.GetOrAdd(userId, _ => new ConcurrentDictionary<long, byte>());
        if (!userSteps.TryAdd(timeStepMatched, 0))
        {
            _logger.LogWarning("Replay attempt detected for user '{UserId}' at time step {TimeStep}", userId, timeStepMatched);
            return false;
        }

        CleanOldTimeSteps(userSteps, timeStepMatched);
        acceptedStep = timeStepMatched;
        return true;
    }

    /// <summary>Convenience overload — keeps the original 3-arg signature for
    /// callers that don't yet wire SEC-M4 persistence (e.g., enrollment
    /// confirm where the user just minted the secret seconds ago and there's
    /// no replay risk).</summary>
    public bool ValidateCode(string base32Secret, string code, string userId)
        => ValidateCode(base32Secret, code, userId, persistedFloor: 0, out _);

    /// <summary>Drop a user's replay-protection cache. Call after rotating
    /// their TOTP secret — the old cache's time-steps block legitimate codes
    /// from the new secret if they happen to share a step, which makes fresh
    /// setups look broken ("Invalid code" on a code the authenticator just
    /// showed).</summary>
    public void ResetReplayCache(string userId)
    {
        _usedTimeSteps.TryRemove(userId, out _);
    }

    private static void CleanOldTimeSteps(ConcurrentDictionary<long, byte> userSteps, long currentStep)
    {
        const int maxAge = 3;
        foreach (var key in userSteps.Keys)
        {
            if (currentStep - key > maxAge)
            {
                userSteps.TryRemove(key, out _);
            }
        }
    }
}

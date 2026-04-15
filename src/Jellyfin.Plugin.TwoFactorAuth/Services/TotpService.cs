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
        try
        {
            // Restrict permissions on Unix-like systems
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // Best effort — ignore on Windows or if permission change fails
        }

        _logger.LogInformation("Generated new persistent encryption key at {Path}", keyPath);
        return key;
    }

    public (string secret, string qrCodeBase64, string manualEntryKey) GenerateSecret(string username)
    {
        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var manualEntryKey = Base32Encoding.ToString(secretBytes);

        var uri = $"otpauth://totp/Jellyfin:{Uri.EscapeDataString(username)}?secret={manualEntryKey}&issuer=Jellyfin";

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
    /// Format: base64( nonce[12] | ciphertext | tag[16] )
    /// </summary>
    public string EncryptSecret(string base32Secret)
    {
        var plaintext = Encoding.UTF8.GetBytes(base32Secret);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(_encryptionKey, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[nonce.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);
        return Convert.ToBase64String(result);
    }

    public string DecryptSecret(string encryptedSecret)
    {
        var bytes = Convert.FromBase64String(encryptedSecret);
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
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    public bool ValidateCode(string base32Secret, string code, string userId)
    {
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

        var userSteps = _usedTimeSteps.GetOrAdd(userId, _ => new ConcurrentDictionary<long, byte>());
        if (!userSteps.TryAdd(timeStepMatched, 0))
        {
            _logger.LogWarning("Replay attempt detected for user '{UserId}' at time step {TimeStep}", userId, timeStepMatched);
            return false;
        }

        CleanOldTimeSteps(userSteps, timeStepMatched);
        return true;
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

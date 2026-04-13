using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using OtpNet;
using QRCoder;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class TotpService
{
    private readonly IDataProtector _protector;
    private readonly ILogger<TotpService> _logger;

    // Per-user replay protection: userId -> (timeStepMatched -> placeholder)
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<long, byte>> _usedTimeSteps = new();

    public TotpService(IDataProtectionProvider dataProtectionProvider, ILogger<TotpService> logger)
    {
        _protector = dataProtectionProvider.CreateProtector("TwoFactorAuth.TotpSecret");
        _logger = logger;
    }

    /// <summary>
    /// Generates a new TOTP secret, returning the base32 secret, a QR code as base64 PNG, and the manual entry key.
    /// </summary>
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
    /// Encrypts a base32-encoded TOTP secret using data protection.
    /// </summary>
    public string EncryptSecret(string base32Secret)
    {
        return _protector.Protect(base32Secret);
    }

    /// <summary>
    /// Decrypts a previously encrypted TOTP secret.
    /// </summary>
    public string DecryptSecret(string encryptedSecret)
    {
        return _protector.Unprotect(encryptedSecret);
    }

    /// <summary>
    /// Validates a TOTP code against the given base32 secret, with replay prevention keyed by userId.
    /// </summary>
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

        // Replay prevention
        var userSteps = _usedTimeSteps.GetOrAdd(userId, _ => new ConcurrentDictionary<long, byte>());

        if (!userSteps.TryAdd(timeStepMatched, 0))
        {
            // This time step was already used for this user
            _logger.LogWarning("Replay attempt detected for user '{UserId}' at time step {TimeStep}", userId, timeStepMatched);
            return false;
        }

        // Clean up time steps older than 3 steps (90 seconds)
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

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class DeviceTokenService
{
    /// <summary>
    /// Creates a new trusted device token. Returns the raw (plaintext) token to send to the client
    /// and the TrustedDevice record (containing the hash) to persist.
    /// </summary>
    public (string token, TrustedDevice device) CreateDeviceToken(string deviceId, string deviceName)
    {
        var rawBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(rawBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        var tokenHash = HashToken(token);
        var now = DateTime.UtcNow;

        var device = new TrustedDevice
        {
            Id = Guid.NewGuid().ToString("N"),
            DeviceId = deviceId,
            DeviceName = deviceName,
            TokenHash = tokenHash,
            CreatedAt = now,
            LastUsedAt = now,
        };

        return (token, device);
    }

    /// <summary>
    /// Validates a submitted token against the list of trusted devices for a specific deviceId.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    public bool ValidateToken(
        string token,
        List<TrustedDevice> trustedDevices,
        string deviceId,
        out TrustedDevice? matchedDevice)
    {
        matchedDevice = null;

        var submittedHash = HashToken(token);
        var submittedHashBytes = Encoding.UTF8.GetBytes(submittedHash);

        foreach (var device in trustedDevices)
        {
            if (!string.Equals(device.DeviceId, deviceId, StringComparison.Ordinal))
            {
                continue;
            }

            var storedHashBytes = Encoding.UTF8.GetBytes(device.TokenHash);

            if (CryptographicOperations.FixedTimeEquals(submittedHashBytes, storedHashBytes))
            {
                matchedDevice = device;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns the SHA-256 hash of the token (UTF-8 encoded) as a base64 string.
    /// </summary>
    public static string HashToken(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var hashBytes = SHA256.HashData(bytes);
        return Convert.ToBase64String(hashBytes);
    }
}

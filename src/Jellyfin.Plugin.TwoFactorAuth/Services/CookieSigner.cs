using System.IO;
using System.Security.Cryptography;
using System.Text;
using MediaBrowser.Common.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// HMAC-SHA256 signing for the __2fa_trust cookie. Uses a persistent 32-byte key
/// stored alongside the TOTP encryption key so signatures survive restarts.
/// </summary>
public class CookieSigner
{
    private readonly byte[] _key;
    private readonly ILogger<CookieSigner> _logger;

    public CookieSigner(IApplicationPaths applicationPaths, ILogger<CookieSigner> logger)
    {
        _logger = logger;
        _key = LoadOrCreateKey(applicationPaths);
    }

    public string Sign(string payload)
    {
        using var hmac = new HMACSHA256(_key);
        var bytes = Encoding.UTF8.GetBytes(payload);
        return Convert.ToBase64String(hmac.ComputeHash(bytes))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public bool Verify(string payload, string signature)
    {
        var expected = Sign(payload);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(signature));
    }

    private byte[] LoadOrCreateKey(IApplicationPaths applicationPaths)
    {
        var pluginDir = Path.Combine(applicationPaths.PluginConfigurationsPath, "TwoFactorAuth");
        Directory.CreateDirectory(pluginDir);
        var keyPath = Path.Combine(pluginDir, "cookie.key");

        if (File.Exists(keyPath))
        {
            try
            {
                var bytes = File.ReadAllBytes(keyPath);
                if (bytes.Length == 32) return bytes;
                _logger.LogWarning("cookie.key is not 32 bytes — regenerating (all existing trust cookies will be invalidated)");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read cookie.key — regenerating");
            }
        }

        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(keyPath, key);
        try
        {
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // Windows / permission errors — best effort
        }

        _logger.LogInformation("Generated new persistent cookie signing key at {Path}", keyPath);
        return key;
    }
}

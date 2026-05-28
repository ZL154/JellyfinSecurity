using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class ConfigExportService
{
    private const int CurrentFormatVersion = 1;
    private const int PbkdfIterations = 600_000; // OWASP 2023 floor for PBKDF2-SHA256
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32; // AES-256

    private readonly UserTwoFactorStore _store;
    private readonly SecurityScoreService _score;
    private readonly ILogger<ConfigExportService> _logger;
    private readonly Func<PluginConfiguration> _configAccessor;

    public ConfigExportService(
        UserTwoFactorStore store,
        SecurityScoreService score,
        ILogger<ConfigExportService> logger)
        : this(store, score, logger, () => Plugin.Instance?.Configuration ?? new PluginConfiguration())
    {
    }

    internal ConfigExportService(
        UserTwoFactorStore store,
        SecurityScoreService score,
        ILogger<ConfigExportService> logger,
        Func<PluginConfiguration> configAccessor)
    {
        _store = store;
        _score = score;
        _logger = logger;
        _configAccessor = configAccessor;
    }

    public async Task<ExportEnvelope> BuildConfigOnlyExportAsync()
    {
        var live = _configAccessor();
        var redactedCfg = DeepCloneViaJson(live);
        var redacted = new List<string>();

        if (!string.IsNullOrEmpty(redactedCfg.SmtpPassword))
        {
            redactedCfg.SmtpPassword = string.Empty;
            redacted.Add("SmtpPassword");
        }
        if (!string.IsNullOrEmpty(redactedCfg.WebhookSecret))
        {
            redactedCfg.WebhookSecret = string.Empty;
            redacted.Add("WebhookSecret");
        }
        if (!string.IsNullOrEmpty(redactedCfg.WebhookEd25519PrivateKey))
        {
            redactedCfg.WebhookEd25519PrivateKey = string.Empty;
            redacted.Add("WebhookEd25519PrivateKey");
        }
        for (int i = 0; i < redactedCfg.OidcProviders.Count; i++)
        {
            if (!string.IsNullOrEmpty(redactedCfg.OidcProviders[i].ClientSecret))
            {
                redactedCfg.OidcProviders[i].ClientSecret = string.Empty;
                redacted.Add($"OidcProviders[{i}].ClientSecret");
            }
        }

        var history = await _score.GetHistoryAsync(365).ConfigureAwait(false);
        var payload = new ConfigExportPayload
        {
            Configuration = redactedCfg,
            ScoreHistory = new List<ScoreSnapshot>(history),
            RedactedFields = redacted
        };

        return new ExportEnvelope
        {
            FormatVersion = CurrentFormatVersion,
            ExportedAt = DateTime.UtcNow,
            PluginVersion = typeof(Plugin).Assembly.GetName().Version?.ToString() ?? "unknown",
            Encrypted = false,
            Payload = payload
        };
    }

    private static PluginConfiguration DeepCloneViaJson(PluginConfiguration source)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(source);
        return System.Text.Json.JsonSerializer.Deserialize<PluginConfiguration>(json)
               ?? new PluginConfiguration();
    }

    internal static string EncryptPayloadForTest(string plaintext, string passphrase)
        => EncryptPayload(plaintext, passphrase);

    internal static string DecryptPayloadForTest(string base64Ciphertext, string passphrase)
        => DecryptPayload(base64Ciphertext, passphrase);

    private static string EncryptPayload(string plaintext, string passphrase)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            System.Text.Encoding.UTF8.GetBytes(passphrase),
            salt,
            PbkdfIterations,
            HashAlgorithmName.SHA256,
            KeySize);

        var plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        var output = new byte[SaltSize + NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(salt, 0, output, 0, SaltSize);
        Buffer.BlockCopy(nonce, 0, output, SaltSize, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, output, SaltSize + NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, output, SaltSize + NonceSize + ciphertext.Length, TagSize);
        return Convert.ToBase64String(output);
    }

    private static string DecryptPayload(string base64Ciphertext, string passphrase)
    {
        byte[] blob;
        try { blob = Convert.FromBase64String(base64Ciphertext); }
        catch (FormatException ex) { throw new CryptographicException("Payload is not valid base64", ex); }

        if (blob.Length < SaltSize + NonceSize + TagSize)
            throw new CryptographicException("Payload too short");

        var salt = new byte[SaltSize];
        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var ciphertextLength = blob.Length - SaltSize - NonceSize - TagSize;
        var ciphertext = new byte[ciphertextLength];

        Buffer.BlockCopy(blob, 0, salt, 0, SaltSize);
        Buffer.BlockCopy(blob, SaltSize, nonce, 0, NonceSize);
        Buffer.BlockCopy(blob, SaltSize + NonceSize, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(blob, SaltSize + NonceSize + ciphertextLength, tag, 0, TagSize);

        var key = Rfc2898DeriveBytes.Pbkdf2(
            System.Text.Encoding.UTF8.GetBytes(passphrase),
            salt,
            PbkdfIterations,
            HashAlgorithmName.SHA256,
            KeySize);

        var plaintext = new byte[ciphertextLength];
        using var aes = new AesGcm(key, TagSize);
        try
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException ex) when (ex.GetType() != typeof(CryptographicException))
        {
            // Normalize subclass exceptions (e.g. AuthenticationTagMismatchException)
            // to the base CryptographicException so callers can catch a single type.
            throw new CryptographicException("Failed to decrypt payload (wrong passphrase or corrupted data)", ex);
        }
        return System.Text.Encoding.UTF8.GetString(plaintext);
    }
}

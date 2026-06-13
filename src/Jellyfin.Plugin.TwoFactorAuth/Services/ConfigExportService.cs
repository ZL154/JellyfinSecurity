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
        if (!string.IsNullOrEmpty(redactedCfg.GotifyAppToken))
        {
            redactedCfg.GotifyAppToken = string.Empty;
            redacted.Add("GotifyAppToken");
        }
        if (!string.IsNullOrEmpty(redactedCfg.NtfyTopic))
        {
            redactedCfg.NtfyTopic = string.Empty;
            redacted.Add("NtfyTopic");
        }
        for (int i = 0; i < redactedCfg.OidcProviders.Count; i++)
        {
            if (!string.IsNullOrEmpty(redactedCfg.OidcProviders[i].ClientSecret))
            {
                redactedCfg.OidcProviders[i].ClientSecret = string.Empty;
                redacted.Add($"OidcProviders[{i}].ClientSecret");
            }
        }

        // SECURITY [v2.5.9] (audit medium): the config-only export is
        // UNENCRYPTED and meant to be shareable (bug reports, backups). But
        // UserEmails is {userId, email} for every enrolled user, and
        // NotifyEmailAddresses are admin contact addresses — both PII that
        // must not ride along in a "safe to share" config. Strip them.
        if (redactedCfg.UserEmails.Count > 0)
        {
            redactedCfg.UserEmails = new();
            redacted.Add("UserEmails");
        }
        if (redactedCfg.NotifyEmailAddresses.Length > 0)
        {
            redactedCfg.NotifyEmailAddresses = System.Array.Empty<string>();
            redacted.Add("NotifyEmailAddresses");
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

    public async Task<ExportEnvelope> BuildFullExportAsync(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase) || passphrase.Length < 8)
            throw new ArgumentException("Passphrase must be at least 8 characters", nameof(passphrase));

        var live = _configAccessor();
        var users = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var history = await _score.GetHistoryAsync(365).ConfigureAwait(false);

        var payload = new FullExportPayload
        {
            Configuration = DeepCloneViaJson(live), // secrets NOT redacted
            ScoreHistory = new List<ScoreSnapshot>(history),
            Users = new List<UserTwoFactorData>(users)
        };

        var json = System.Text.Json.JsonSerializer.Serialize(payload);
        var ciphertext = EncryptPayload(json, passphrase);

        return new ExportEnvelope
        {
            FormatVersion = CurrentFormatVersion,
            ExportedAt = DateTime.UtcNow,
            PluginVersion = typeof(Plugin).Assembly.GetName().Version?.ToString() ?? "unknown",
            Encrypted = true,
            Payload = ciphertext
        };
    }

    public record ImportResult(bool Success, string? Error = null, IReadOnlyList<string>? Warnings = null);

    public async Task<ImportResult> ImportAsync(string envelopeJson, string? passphrase)
    {
        ExportEnvelope envelope;
        try
        {
            envelope = System.Text.Json.JsonSerializer.Deserialize<ExportEnvelope>(envelopeJson)
                       ?? throw new InvalidOperationException("Envelope deserialized as null");
        }
        catch (System.Text.Json.JsonException ex)
        {
            return new ImportResult(false, $"Malformed envelope: {ex.Message}");
        }

        if (envelope.FormatVersion != CurrentFormatVersion)
            throw new InvalidOperationException(
                $"Unknown export format version {envelope.FormatVersion} (this plugin supports {CurrentFormatVersion}).");

        var warnings = new List<string>();
        var currentPluginVersion = typeof(Plugin).Assembly.GetName().Version?.ToString() ?? "unknown";
        if (!string.Equals(envelope.PluginVersion, currentPluginVersion, StringComparison.Ordinal))
            warnings.Add($"Plugin version mismatch: export was made on {envelope.PluginVersion}, this is {currentPluginVersion}");

        if (envelope.Encrypted)
        {
            if (string.IsNullOrEmpty(passphrase))
                return new ImportResult(false, "Encrypted export requires a passphrase");

            string innerJson;
            try
            {
                var cipher = envelope.Payload?.ToString() ?? string.Empty;
                innerJson = DecryptPayload(cipher, passphrase);
            }
            catch (CryptographicException ex)
            {
                return new ImportResult(false, $"Failed to decrypt: {ex.Message}");
            }

            FullExportPayload? full;
            try { full = System.Text.Json.JsonSerializer.Deserialize<FullExportPayload>(innerJson); }
            catch (System.Text.Json.JsonException ex) { return new ImportResult(false, $"Decrypted payload malformed: {ex.Message}"); }
            if (full is null) return new ImportResult(false, "Decrypted payload was null");

            ApplyConfiguration(full.Configuration);
            if (full.Users.Count > 0)
            {
                foreach (var u in full.Users)
                {
                    await _store.SaveUserDataAsync(u).ConfigureAwait(false);
                }
                warnings.Add($"Imported {full.Users.Count} user record(s) — admin re-verification recommended");
            }
        }
        else
        {
            ConfigExportPayload? plain;
            try
            {
                // envelope.Payload arrives as JsonElement when deserialized via System.Text.Json default.
                var payloadJson = envelope.Payload is System.Text.Json.JsonElement je
                    ? je.GetRawText()
                    : System.Text.Json.JsonSerializer.Serialize(envelope.Payload);
                plain = System.Text.Json.JsonSerializer.Deserialize<ConfigExportPayload>(payloadJson);
            }
            catch (System.Text.Json.JsonException ex) { return new ImportResult(false, $"Payload malformed: {ex.Message}"); }
            if (plain is null) return new ImportResult(false, "Payload was null");

            ApplyConfiguration(plain.Configuration);
            if (plain.RedactedFields.Count > 0)
                warnings.Add($"Re-enter secrets after import: {string.Join(", ", plain.RedactedFields)}");
        }

        return new ImportResult(true, null, warnings);
    }

    private void ApplyConfiguration(PluginConfiguration imported)
    {
        var live = _configAccessor();
        var json = System.Text.Json.JsonSerializer.Serialize(imported);
        var clone = System.Text.Json.JsonSerializer.Deserialize<PluginConfiguration>(json);
        if (clone is null) throw new InvalidOperationException("Failed to materialize imported configuration");

        // SECURITY [v2.5.5] (Finding 14): validate untrusted import payload
        // BEFORE applying. A crafted export could otherwise set arbitrary
        // CIDRs (granting LAN-bypass to an attacker IP), point GeoIP DB
        // paths at sensitive files, switch OIDC DiscoveryUrl to http://,
        // or zero out numeric thresholds. We sanitize each field rather
        // than reject the whole import.
        SanitizeImportedConfig(clone);

        // Mutate the live config in place via reflection so any held reference to
        // Plugin.Instance.Configuration sees the new values immediately.
        foreach (var prop in typeof(PluginConfiguration).GetProperties(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
        {
            if (!prop.CanWrite) continue;
            prop.SetValue(live, prop.GetValue(clone));
        }

        Plugin.Instance?.SaveConfiguration();
        _logger.LogInformation("Plugin configuration applied from import");
    }

    private void SanitizeImportedConfig(PluginConfiguration c)
    {
        c.TrustedProxyCidrs = SanitizeCidrArray(c.TrustedProxyCidrs, "TrustedProxyCidrs");
        c.LanBypassCidrs = SanitizeCidrArray(c.LanBypassCidrs, "LanBypassCidrs");

        if (c.OidcProviders is { Count: > 0 })
        {
            foreach (var p in c.OidcProviders)
            {
                if (!string.IsNullOrEmpty(p.DiscoveryUrl)
                    && !p.DiscoveryUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("[2FA] Import sanitize: stripped non-HTTPS DiscoveryUrl on provider {Pid}: {Url}", p.Id, p.DiscoveryUrl);
                    p.DiscoveryUrl = string.Empty;
                    p.Enabled = false;
                }
            }
        }

        c.GeoIpAsnDbPath = SanitizePathOrClear(c.GeoIpAsnDbPath, "GeoIpAsnDbPath");
        c.GeoIpCountryDbPath = SanitizePathOrClear(c.GeoIpCountryDbPath, "GeoIpCountryDbPath");
        c.GeoIpCityDbPath = SanitizePathOrClear(c.GeoIpCityDbPath, "GeoIpCityDbPath");

        c.StepUpWindowSeconds = Math.Clamp(c.StepUpWindowSeconds, 60, 900);
        c.EmailOtpTtlSeconds = Math.Clamp(c.EmailOtpTtlSeconds, 60, 3600);
    }

    private string[] SanitizeCidrArray(string[]? src, string fieldName)
    {
        if (src is null || src.Length == 0) return Array.Empty<string>();
        var kept = new List<string>(src.Length);
        foreach (var cidr in src)
        {
            if (IsValidCidr(cidr)) kept.Add(cidr);
            else _logger.LogWarning("[2FA] Import sanitize: dropped invalid CIDR from {Field}: {Cidr}", fieldName, cidr);
        }
        return kept.ToArray();
    }

    private string SanitizePathOrClear(string? path, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        if (path.Contains("..", StringComparison.Ordinal)
            || path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal)
            || !System.IO.Path.IsPathFullyQualified(path)
            || !path.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("[2FA] Import sanitize: cleared unsafe path on {Field}: {Path}", fieldName, path);
            return string.Empty;
        }
        var lower = path.Replace('\\', '/').ToLowerInvariant();
        foreach (var bad in new[] { "/etc/", "/proc/", "/sys/", "/dev/", "/root/.ssh", "/run/secrets" })
        {
            if (lower.StartsWith(bad, StringComparison.Ordinal))
            {
                _logger.LogWarning("[2FA] Import sanitize: cleared sensitive path on {Field}: {Path}", fieldName, path);
                return string.Empty;
            }
        }
        return path;
    }

    private static bool IsValidCidr(string cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr)) return false;
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2) return false;
        if (!System.Net.IPAddress.TryParse(parts[0], out var ip)) return false;
        if (!int.TryParse(parts[1], out var prefix)) return false;
        var max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > max) return false;
        // SECURITY [v2.5.5] (N-A7): reject overly-broad CIDRs on import. A
        // crafted export with LanBypassCidrs:["0.0.0.0/0"] would otherwise
        // grant 2FA-bypass / trusted-proxy treatment to every IP on the
        // internet. /8 IPv4 minimum (covers /16, /24 etc.); /16 IPv6 minimum
        // (covers /48 etc.). Anything broader is a misconfiguration or an
        // attack.
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && prefix < 8) return false;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && prefix < 16) return false;
        return true;
    }
}

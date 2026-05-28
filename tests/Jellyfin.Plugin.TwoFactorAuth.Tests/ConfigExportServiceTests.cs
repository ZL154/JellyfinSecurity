using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class ExportEnvelopeDtosTests
{
    [Fact]
    public void ExportEnvelope_DefaultsAreSane()
    {
        var env = new ExportEnvelope
        {
            FormatVersion = 1,
            ExportedAt = DateTime.UtcNow,
            PluginVersion = "2.5.0",
            Encrypted = false,
            Payload = new ConfigExportPayload()
        };
        Assert.Equal(1, env.FormatVersion);
        Assert.False(env.Encrypted);
        Assert.NotNull(env.Payload);
    }

    [Fact]
    public void ConfigExportPayload_HasRedactionMarkers()
    {
        var p = new ConfigExportPayload
        {
            Configuration = new(),
            ScoreHistory = new List<ScoreSnapshot>(),
            RedactedFields = new List<string> { "SmtpPassword", "WebhookSecret" }
        };
        Assert.Contains("SmtpPassword", p.RedactedFields);
        Assert.Contains("WebhookSecret", p.RedactedFields);
    }
}

public static class ConfigExportTestHarness
{
    public static ConfigExportService Build(out PluginConfiguration cfg)
    {
        var paths = TestApplicationPaths.Create();
        var store = new UserTwoFactorStore(paths);
        var stats = Substitute.For<StatsService>(store, Substitute.For<MediaBrowser.Controller.Library.IUserManager>());
        var scoreLogger = Substitute.For<ILogger<SecurityScoreService>>();
        var localCfg = new PluginConfiguration();
        var score = new SecurityScoreService(store, stats, paths, scoreLogger, () => localCfg);
        cfg = localCfg;
        var exportLogger = Substitute.For<ILogger<ConfigExportService>>();
        return new ConfigExportService(store, score, exportLogger, () => localCfg);
    }
}

public class ConfigExportRedactionTests
{
    [Fact]
    public async Task ConfigOnlyExport_StripsSecretFields()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        cfg.GotifyAppToken = "gotify-token";
        cfg.NtfyTopic = "ntfy-secret-topic";
        cfg.SmtpPassword = "smtp-secret";
        cfg.WebhookSecret = "webhook-secret";
        cfg.WebhookEd25519PrivateKey = "ed25519-secret";
        cfg.OidcProviders.Add(new OidcProvider { Id = "google", ClientSecret = "client-secret" });

        var env = await svc.BuildConfigOnlyExportAsync();
        var payload = (ConfigExportPayload)env.Payload;

        Assert.Equal(string.Empty, payload.Configuration.SmtpPassword);
        Assert.Equal(string.Empty, payload.Configuration.WebhookSecret);
        Assert.Equal(string.Empty, payload.Configuration.WebhookEd25519PrivateKey);
        Assert.Equal(string.Empty, payload.Configuration.GotifyAppToken);
        Assert.Equal(string.Empty, payload.Configuration.NtfyTopic);
        Assert.Single(payload.Configuration.OidcProviders);
        Assert.Equal(string.Empty, payload.Configuration.OidcProviders[0].ClientSecret);

        Assert.Contains("SmtpPassword", payload.RedactedFields);
        Assert.Contains("WebhookSecret", payload.RedactedFields);
        Assert.Contains("WebhookEd25519PrivateKey", payload.RedactedFields);
        Assert.Contains("GotifyAppToken", payload.RedactedFields);
        Assert.Contains("NtfyTopic", payload.RedactedFields);
        Assert.Contains("OidcProviders[0].ClientSecret", payload.RedactedFields);

        Assert.False(env.Encrypted);
        Assert.Equal(1, env.FormatVersion);
    }

    [Fact]
    public async Task ConfigOnlyExport_PreservesNonSecretFields()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        cfg.EnforcementScope = EnforcementScope.All;
        cfg.IpBanEnabled = true;
        cfg.IpBanDurationHours = 48;
        cfg.SmtpHost = "smtp.example.com";
        cfg.SmtpPort = 587;
        cfg.SmtpUsername = "admin@example.com";

        var env = await svc.BuildConfigOnlyExportAsync();
        var payload = (ConfigExportPayload)env.Payload;

        Assert.Equal(EnforcementScope.All, payload.Configuration.EnforcementScope);
        Assert.True(payload.Configuration.IpBanEnabled);
        Assert.Equal(48, payload.Configuration.IpBanDurationHours);
        Assert.Equal("smtp.example.com", payload.Configuration.SmtpHost);
        Assert.Equal(587, payload.Configuration.SmtpPort);
        Assert.Equal("admin@example.com", payload.Configuration.SmtpUsername);
    }
}

public class PassphraseCryptoTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        const string passphrase = "correct-horse-battery-staple";
        const string plaintext = "{\"hello\":\"world\"}";

        var ciphertext = ConfigExportService.EncryptPayloadForTest(plaintext, passphrase);
        Assert.NotEqual(plaintext, ciphertext);

        var roundTripped = ConfigExportService.DecryptPayloadForTest(ciphertext, passphrase);
        Assert.Equal(plaintext, roundTripped);
    }

    [Fact]
    public void Decrypt_WrongPassphrase_ThrowsCryptographicException()
    {
        const string passphrase = "right-pass";
        const string plaintext = "{\"hello\":\"world\"}";
        var ciphertext = ConfigExportService.EncryptPayloadForTest(plaintext, passphrase);
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            ConfigExportService.DecryptPayloadForTest(ciphertext, "wrong-pass"));
    }

    [Fact]
    public void EncryptedOutput_IsBase64()
    {
        var ciphertext = ConfigExportService.EncryptPayloadForTest("hello", "passpass");
        Assert.Matches("^[A-Za-z0-9+/]+={0,2}$", ciphertext);
        Assert.True(ciphertext.Length >= 60);
    }
}

public class FullExportTests
{
    [Fact]
    public async Task FullExport_IsEncryptedEnvelope()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        cfg.SmtpPassword = "secret-pw";
        var env = await svc.BuildFullExportAsync("passpass");
        Assert.True(env.Encrypted);
        Assert.IsType<string>(env.Payload);
        var b64 = (string)env.Payload;
        Assert.Matches("^[A-Za-z0-9+/]+={0,2}$", b64);
    }

    [Fact]
    public async Task FullExport_DecryptsBackToConfigAndUsers()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        cfg.SmtpPassword = "smtp-secret";
        cfg.OidcProviders.Add(new OidcProvider { Id = "google", ClientSecret = "client-secret" });

        var env = await svc.BuildFullExportAsync("passpass");
        var decryptedJson = ConfigExportService.DecryptPayloadForTest((string)env.Payload, "passpass");
        var payload = System.Text.Json.JsonSerializer.Deserialize<FullExportPayload>(decryptedJson)!;

        // Secrets ARE present in full export
        Assert.Equal("smtp-secret", payload.Configuration.SmtpPassword);
        Assert.Equal("client-secret", payload.Configuration.OidcProviders[0].ClientSecret);
    }

    [Fact]
    public async Task FullExport_ShortPassphrase_Throws()
    {
        var svc = ConfigExportTestHarness.Build(out _);
        await Assert.ThrowsAsync<ArgumentException>(() => svc.BuildFullExportAsync("short"));
    }
}

public class ImportTests
{
    [Fact]
    public async Task Import_UnknownFormatVersion_Throws()
    {
        var svc = ConfigExportTestHarness.Build(out _);
        var bad = System.Text.Json.JsonSerializer.Serialize(new ExportEnvelope
        {
            FormatVersion = 999,
            ExportedAt = DateTime.UtcNow,
            PluginVersion = "2.5.0",
            Encrypted = false,
            Payload = new ConfigExportPayload()
        });
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.ImportAsync(bad, passphrase: null));
        Assert.Contains("format", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Import_ConfigOnly_AppliesSettings()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        cfg.EnforcementScope = EnforcementScope.Optional;

        var newCfg = new PluginConfiguration { EnforcementScope = EnforcementScope.All };
        var envelope = System.Text.Json.JsonSerializer.Serialize(new ExportEnvelope
        {
            FormatVersion = 1,
            ExportedAt = DateTime.UtcNow,
            PluginVersion = "2.5.0",
            Encrypted = false,
            Payload = new ConfigExportPayload { Configuration = newCfg }
        });

        var result = await svc.ImportAsync(envelope, passphrase: null);
        Assert.True(result.Success);
        Assert.Equal(EnforcementScope.All, cfg.EnforcementScope);
    }

    [Fact]
    public async Task Import_EncryptedWithWrongPassphrase_Fails()
    {
        var svc = ConfigExportTestHarness.Build(out _);
        var env = await svc.BuildFullExportAsync("rightpass");
        var json = System.Text.Json.JsonSerializer.Serialize(env);

        var result = await svc.ImportAsync(json, passphrase: "wrongpass");
        Assert.False(result.Success);
        Assert.Contains("decrypt", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Import_MalformedJson_Fails()
    {
        var svc = ConfigExportTestHarness.Build(out _);
        var result = await svc.ImportAsync("{not-json", passphrase: null);
        Assert.False(result.Success);
    }
}

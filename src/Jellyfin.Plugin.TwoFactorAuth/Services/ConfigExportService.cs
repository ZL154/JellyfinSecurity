using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class ConfigExportService
{
    private const int CurrentFormatVersion = 1;

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
}

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
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

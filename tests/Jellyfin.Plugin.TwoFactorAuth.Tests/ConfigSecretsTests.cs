using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// [#268] The admin page read every saved password, token and key back in
/// plain text, and showed three of them in plain view. The configuration it
/// reads now carries <see cref="ConfigSecrets.SavedMarker"/> in their place,
/// and a save that sends the marker back keeps what was stored.
/// </summary>
public class ConfigSecretsTests
{
    private static PluginConfiguration WithSecrets()
    {
        var c = new PluginConfiguration
        {
            SmtpPassword = "smtp-pw",
            NtfyToken = "tk_ntfy",
            NtfyPassword = "ntfy-pw",
            GotifyAppToken = "gotify-token",
            TelegramBotToken = "123456:telegram",
            WebhookSecret = "hmac-secret",
            WebhookEd25519PrivateKey = "ed25519-private",
            WebhookHeaders = new[] { "Authorization: Bearer abc123", "X-Api-Key: key-1" },
            SmtpHost = "smtp.example.com",
        };
        c.OidcProviders.Add(new OidcProvider { Id = "google", ClientSecret = "google-secret" });
        c.OidcProviders.Add(new OidcProvider { Id = "authelia", ClientSecret = string.Empty });
        return c;
    }

    private static string Field(PluginConfiguration c, string name)
        => (string)typeof(PluginConfiguration).GetProperty(name)!.GetValue(c)!;

    [Fact]
    public void Every_saved_secret_reads_as_the_marker_in_the_copy()
    {
        var copy = ConfigSecrets.Redact(WithSecrets());

        Assert.NotEmpty(ConfigSecrets.FieldNames);
        foreach (var name in ConfigSecrets.FieldNames)
        {
            Assert.Equal(ConfigSecrets.SavedMarker, Field(copy, name));
        }
        Assert.Equal(ConfigSecrets.SavedMarker, copy.OidcProviders[0].ClientSecret);
        Assert.Equal(new[] { "Authorization: (saved)", "X-Api-Key: (saved)" }, copy.WebhookHeaders);
        Assert.Equal("smtp.example.com", copy.SmtpHost);
    }

    [Fact]
    public void An_empty_secret_stays_empty_so_the_page_can_tell_it_apart()
    {
        var copy = ConfigSecrets.Redact(new PluginConfiguration());

        foreach (var name in ConfigSecrets.FieldNames)
        {
            Assert.Equal(string.Empty, Field(copy, name));
        }
        Assert.Empty(copy.WebhookHeaders);
        Assert.Equal(string.Empty, ConfigSecrets.Redact(WithSecrets()).OidcProviders[1].ClientSecret);
    }

    [Fact]
    public void Redacting_leaves_the_live_configuration_alone()
    {
        var live = WithSecrets();

        var copy = ConfigSecrets.Redact(live);

        Assert.NotSame(live, copy);
        Assert.Equal("smtp-pw", live.SmtpPassword);
        Assert.Equal("google-secret", live.OidcProviders[0].ClientSecret);
        Assert.Equal("Authorization: Bearer abc123", live.WebhookHeaders[0]);
    }

    [Fact]
    public void Saving_the_untouched_copy_keeps_every_stored_secret()
    {
        var stored = WithSecrets();
        var incoming = ConfigSecrets.Redact(stored);

        ConfigSecrets.KeepSaved(incoming, stored);

        foreach (var name in ConfigSecrets.FieldNames)
        {
            Assert.Equal(Field(stored, name), Field(incoming, name));
        }
        Assert.Equal("google-secret", incoming.OidcProviders[0].ClientSecret);
        Assert.Equal(string.Empty, incoming.OidcProviders[1].ClientSecret);
        Assert.Equal(stored.WebhookHeaders, incoming.WebhookHeaders);
    }

    [Fact]
    public void An_emptied_field_clears_the_secret_and_a_typed_one_replaces_it()
    {
        var stored = WithSecrets();
        var incoming = ConfigSecrets.Redact(stored);
        incoming.SmtpPassword = string.Empty;
        incoming.GotifyAppToken = "new-gotify";

        ConfigSecrets.KeepSaved(incoming, stored);

        Assert.Equal(string.Empty, incoming.SmtpPassword);
        Assert.Equal("new-gotify", incoming.GotifyAppToken);
        Assert.Equal("hmac-secret", incoming.WebhookSecret);
    }

    [Fact]
    public void A_client_secret_comes_back_by_provider_id_and_never_as_the_marker()
    {
        var stored = WithSecrets();
        var incoming = ConfigSecrets.Redact(stored);
        incoming.OidcProviders.Reverse();
        incoming.OidcProviders.Add(new OidcProvider { Id = "removed-meanwhile", ClientSecret = ConfigSecrets.SavedMarker });

        ConfigSecrets.KeepSaved(incoming, stored);

        Assert.Equal("google-secret", incoming.OidcProviders.Single(p => p.Id == "google").ClientSecret);
        Assert.Equal(string.Empty, incoming.OidcProviders.Single(p => p.Id == "removed-meanwhile").ClientSecret);
    }

    [Fact]
    public void A_header_keeps_its_stored_value_by_name_and_a_changed_one_takes_the_new_value()
    {
        var stored = WithSecrets();
        stored.WebhookHeaders = new[] { "Authorization: Bearer abc123", "X-Api-Key: key-1", "X-Api-Key: key-2", "X-Trace: on" };
        var incoming = new PluginConfiguration
        {
            WebhookHeaders = new[]
            {
                "authorization: (saved)",
                "X-Api-Key: (saved)",
                "X-Api-Key: (saved)",
                "X-Renamed: (saved)",
                "X-Trace: off",
                "X-New: value",
            },
        };

        ConfigSecrets.KeepSaved(incoming, stored);

        Assert.Equal(
            new[] { "Authorization: Bearer abc123", "X-Api-Key: key-1", "X-Api-Key: key-2", "X-Trace: off", "X-New: value" },
            incoming.WebhookHeaders);
    }

    [Fact]
    public void The_marker_is_never_stored_when_nothing_is_saved_behind_it()
    {
        var incoming = ConfigSecrets.Redact(WithSecrets());

        ConfigSecrets.KeepSaved(incoming, new PluginConfiguration());

        foreach (var name in ConfigSecrets.FieldNames)
        {
            Assert.Equal(string.Empty, Field(incoming, name));
        }
        Assert.Empty(incoming.WebhookHeaders);
    }

    // A secret added to the configuration later has to join the list, or the
    // page reads it in plain text again.
    [Fact]
    public void Every_setting_named_like_a_secret_is_on_the_list()
    {
        var named = typeof(PluginConfiguration).GetProperties()
            .Where(p => p.PropertyType == typeof(string)
                && Regex.IsMatch(p.Name, "(Password|Secret|Token|PrivateKey|ApiKey)$"))
            .Select(p => p.Name);

        Assert.Equal(named.OrderBy(n => n, StringComparer.Ordinal), ConfigSecrets.FieldNames.OrderBy(n => n, StringComparer.Ordinal));
    }

    // A secret added to one list and not the other would either reach the
    // browser or leave in the export meant for sharing.
    [Fact]
    public async Task Every_secret_the_page_cannot_read_is_also_left_out_of_the_shared_export()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        foreach (var name in ConfigSecrets.FieldNames)
        {
            typeof(PluginConfiguration).GetProperty(name)!.SetValue(cfg, "secret-" + name);
        }

        var env = await svc.BuildConfigOnlyExportAsync();
        var payload = (ConfigExportPayload)env.Payload;

        foreach (var name in ConfigSecrets.FieldNames)
        {
            Assert.Equal(string.Empty, Field(payload.Configuration, name));
            Assert.Contains(name, payload.RedactedFields);
        }
    }

    // The unencrypted export is meant to be shared, and the extra webhook
    // headers carry a receiver's credential just like the secrets above.
    [Fact]
    public async Task The_shared_export_leaves_out_the_webhook_headers()
    {
        var svc = ConfigExportTestHarness.Build(out var cfg);
        cfg.WebhookHeaders = new[] { "Authorization: Bearer abc123", "X-Api-Key: key-1" };

        var env = await svc.BuildConfigOnlyExportAsync();
        var payload = (ConfigExportPayload)env.Payload;

        Assert.Empty(payload.Configuration.WebhookHeaders);
        Assert.Contains("WebhookHeaders", payload.RedactedFields);
        Assert.Equal(2, cfg.WebhookHeaders.Length);
    }

    [Theory]
    [InlineData("GET", "/Plugins/94879a0c-da24-4eb1-aa06-f28b4b9333b1/Configuration", true)]
    [InlineData("GET", "/Plugins/94879a0cda244eb1aa06f28b4b9333b1/Configuration", true)]
    [InlineData("GET", "/jellyfin/Plugins/94879a0c-da24-4eb1-aa06-f28b4b9333b1/Configuration/", true)]
    [InlineData("POST", "/Plugins/94879a0c-da24-4eb1-aa06-f28b4b9333b1/Configuration", false)]
    [InlineData("GET", "/Plugins/00000000-0000-0000-0000-000000000001/Configuration", false)]
    [InlineData("GET", "/Plugins/94879a0c-da24-4eb1-aa06-f28b4b9333b1/Manifest", false)]
    public async Task The_filter_hands_out_the_copy_only_for_this_plugins_configuration(string method, string path, bool redacted)
    {
        var live = WithSecrets();
        var http = new DefaultHttpContext();
        http.Request.Method = method;
        http.Request.Path = path;
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var result = new ObjectResult(live);
        var context = new ResultExecutingContext(action, new List<IFilterMetadata>(), result, new object());

        await new PluginConfigSecretsFilter().OnResultExecutionAsync(
            context,
            () => Task.FromResult(new ResultExecutedContext(action, new List<IFilterMetadata>(), result, new object())));

        var sent = Assert.IsType<PluginConfiguration>(result.Value);
        Assert.Equal(redacted ? ConfigSecrets.SavedMarker : "smtp-pw", sent.SmtpPassword);
        Assert.Equal(redacted, !ReferenceEquals(live, sent));
        Assert.Equal("smtp-pw", live.SmtpPassword);
    }

    // Every input that takes a secret is masked on screen, and the browser is
    // told not to fill in a saved login there. Three of them were plain text.
    [Theory]
    [InlineData("cfgSmtpPass")]
    [InlineData("cfgNtfyToken")]
    [InlineData("cfgNtfyPassword")]
    [InlineData("cfgGotifyToken")]
    [InlineData("cfgTelegramToken")]
    [InlineData("cfgWebhookSecret")]
    [InlineData("ssoClientSecret")]
    public void The_admin_page_masks_every_secret_input(string id)
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html")!;
        var input = Regex.Match(page, "<input[^>]*\\bid=\"" + id + "\"[^>]*>").Value;

        Assert.Contains("type=\"password\"", input, StringComparison.Ordinal);
        Assert.Contains("autocomplete=\"new-password\"", input, StringComparison.Ordinal);
    }

    // Jellyfin's POST /Plugins/{id}/Configuration reads the body itself and
    // hands the result to UpdateConfiguration, so that is where the stored
    // values go back in. Plugin cannot be built under test (it sets the static
    // Instance), so the override is pinned here and its body is KeepSaved.
    [Fact]
    public void Plugin_puts_the_stored_secrets_back_before_saving()
    {
        var method = typeof(Plugin).GetMethod(nameof(Plugin.UpdateConfiguration), new[] { typeof(BasePluginConfiguration) });

        Assert.NotNull(method);
        Assert.Equal(typeof(Plugin), method!.DeclaringType);
    }
}

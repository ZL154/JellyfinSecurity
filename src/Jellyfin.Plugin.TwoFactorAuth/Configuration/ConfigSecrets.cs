using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Jellyfin.Plugin.TwoFactorAuth.Configuration;

/// <summary>
/// [#268] The secrets in <see cref="PluginConfiguration"/> are write only for
/// the browser. The copy the admin page reads through Jellyfin's
/// GET /Plugins/{id}/Configuration (<see cref="Services.PluginConfigSecretsFilter"/>)
/// carries <see cref="SavedMarker"/> in place of every saved password, token
/// and key, and a save that sends the marker back keeps the stored value
/// (<see cref="Plugin.UpdateConfiguration"/>). An emptied field clears the
/// secret and anything else replaces it, so the page saves as it always did
/// without ever holding a saved secret.
/// </summary>
internal static class ConfigSecrets
{
    /// <summary>What a saved secret reads as in the copy the browser gets.</summary>
    public const string SavedMarker = "(saved)";

    // One entry per top-level secret, read and written through the same pair
    // so hiding and restoring cannot drift apart. The config-only export
    // strips the same names; ConfigSecretsTests holds the two lists together.
    private static readonly (string Name, Func<PluginConfiguration, string> Get, Action<PluginConfiguration, string> Set)[] Fields =
    {
        (nameof(PluginConfiguration.SmtpPassword), c => c.SmtpPassword, (c, v) => c.SmtpPassword = v),
        (nameof(PluginConfiguration.NtfyToken), c => c.NtfyToken, (c, v) => c.NtfyToken = v),
        (nameof(PluginConfiguration.NtfyPassword), c => c.NtfyPassword, (c, v) => c.NtfyPassword = v),
        (nameof(PluginConfiguration.GotifyAppToken), c => c.GotifyAppToken, (c, v) => c.GotifyAppToken = v),
        (nameof(PluginConfiguration.TelegramBotToken), c => c.TelegramBotToken, (c, v) => c.TelegramBotToken = v),
        (nameof(PluginConfiguration.WebhookSecret), c => c.WebhookSecret, (c, v) => c.WebhookSecret = v),
        (nameof(PluginConfiguration.WebhookEd25519PrivateKey), c => c.WebhookEd25519PrivateKey, (c, v) => c.WebhookEd25519PrivateKey = v),
    };

    /// <summary>The top-level secret properties, by name. Each SSO client
    /// secret and the value of each extra webhook header are hidden too.</summary>
    public static IEnumerable<string> FieldNames => Fields.Select(f => f.Name);

    /// <summary>
    /// A copy of <paramref name="live"/> for the browser, in which every saved
    /// secret, each SSO client secret and the value of each extra webhook
    /// header read <see cref="SavedMarker"/>. An empty secret stays empty, so
    /// the page can still tell an unset one apart. The live configuration is
    /// left alone.
    /// </summary>
    public static PluginConfiguration Redact(PluginConfiguration live)
    {
        // The same round trip ConfigExportService uses for its copy.
        var copy = JsonSerializer.Deserialize<PluginConfiguration>(JsonSerializer.Serialize(live))
            ?? new PluginConfiguration();

        foreach (var (_, get, set) in Fields)
        {
            if (!string.IsNullOrEmpty(get(copy)))
            {
                set(copy, SavedMarker);
            }
        }

        foreach (var provider in copy.OidcProviders ?? new List<Models.OidcProvider>())
        {
            if (!string.IsNullOrEmpty(provider.ClientSecret))
            {
                provider.ClientSecret = SavedMarker;
            }
        }

        copy.WebhookHeaders = (copy.WebhookHeaders ?? Array.Empty<string>()).Select(MaskHeader).ToArray();
        return copy;
    }

    /// <summary>
    /// Puts the stored value back wherever <paramref name="incoming"/> still
    /// carries <see cref="SavedMarker"/>, before it replaces
    /// <paramref name="stored"/>. A client secret comes back by provider id
    /// and a header value by header name. A marker with nothing saved behind
    /// it becomes empty, and such a header is dropped, so the marker itself is
    /// never stored.
    /// </summary>
    public static void KeepSaved(PluginConfiguration incoming, PluginConfiguration stored)
    {
        foreach (var (_, get, set) in Fields)
        {
            if (string.Equals(get(incoming), SavedMarker, StringComparison.Ordinal))
            {
                set(incoming, get(stored));
            }
        }

        foreach (var provider in incoming.OidcProviders ?? new List<Models.OidcProvider>())
        {
            if (!string.Equals(provider.ClientSecret, SavedMarker, StringComparison.Ordinal))
            {
                continue;
            }

            var saved = stored.OidcProviders?.FirstOrDefault(p => string.Equals(p.Id, provider.Id, StringComparison.Ordinal));
            provider.ClientSecret = saved?.ClientSecret ?? string.Empty;
        }

        incoming.WebhookHeaders = RestoreHeaders(incoming.WebhookHeaders, stored.WebhookHeaders);
    }

    // Name and value split the way NotificationService.ParseCustomHeaders
    // reads them, so every line it would send has its value hidden. A line it
    // would skip is never sent and is left as it is.
    private static bool TrySplitHeader(string? line, out string name, out string value)
    {
        name = string.Empty;
        value = string.Empty;
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        var idx = line.IndexOf(':', StringComparison.Ordinal);
        if (idx <= 0)
        {
            return false;
        }

        name = line[..idx].Trim();
        value = line[(idx + 1)..].Trim();
        return name.Length > 0 && value.Length > 0;
    }

    private static string MaskHeader(string line)
        => TrySplitHeader(line, out var name, out _) ? name + ": " + SavedMarker : line;

    private static string[] RestoreHeaders(string[]? incoming, string[]? stored)
    {
        // Each stored line goes back once and in order, so two headers with
        // the same name each get their own value.
        var unused = new List<string>(stored ?? Array.Empty<string>());
        var result = new List<string>();
        foreach (var line in incoming ?? Array.Empty<string>())
        {
            if (!TrySplitHeader(line, out var name, out var value)
                || !string.Equals(value, SavedMarker, StringComparison.Ordinal))
            {
                result.Add(line);
                continue;
            }

            var index = unused.FindIndex(s => TrySplitHeader(s, out var savedName, out _)
                && string.Equals(savedName, name, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                result.Add(unused[index]);
                unused.RemoveAt(index);
            }
        }

        return result.ToArray();
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// The address this server is reachable at from outside, for the links the
/// plugin hands to someone else: the OIDC <c>redirect_uri</c> an IdP has
/// registered, the pairing QR a phone scans, the password reset link in an
/// email.
///
/// [#216] Those links were all derived from the incoming request. That is
/// correct behind a reverse proxy, where the forwarded headers carry the
/// public name, and wrong for a client that reaches Jellyfin directly on the
/// LAN: a smart TV connects to 192.168.x.y, no proxy is in the path, no header
/// exists to read, and the link comes out pointing at a private address the
/// IdP rejects and a phone outside the network cannot open. No proxy setting
/// can fix that, because the proxy never sees the request. The server has to
/// be told its public address.
///
/// Resolution order, first hit wins:
///   1. The plugin's own PublicBaseUrl, for deployments where nothing else is
///      right.
///   2. Jellyfin's published server URI, which is where an admin already
///      declares this ("external" first, then "all"). Most servers that are
///      published under a domain have it set, so they need no new setting.
///   3. Nothing, and the caller keeps its existing request-derived behaviour.
/// </summary>
public class ExternalUrlResolver
{
    private readonly IServerConfigurationManager _serverConfig;
    private readonly ILogger<ExternalUrlResolver> _logger;

    public ExternalUrlResolver(
        IServerConfigurationManager serverConfig,
        ILogger<ExternalUrlResolver> logger)
    {
        _serverConfig = serverConfig;
        _logger = logger;
    }

    /// <summary>The configured public base ("https://host" or
    /// "https://host/jellyfin", never a trailing slash), or null when the
    /// admin has declared nothing and the caller should fall back to the
    /// request.</summary>
    public string? Resolve()
    {
        var fromPlugin = Normalize(Plugin.Instance?.Configuration?.PublicBaseUrl);
        if (fromPlugin is not null)
        {
            return fromPlugin;
        }

        try
        {
            var network = _serverConfig.GetNetworkConfiguration();
            return Normalize(PickPublished(network?.PublishedServerUriBySubnet));
        }
        catch (Exception ex)
        {
            // Reading Jellyfin's own configuration must never break a sign-in;
            // the request-derived fallback still produces a usable link on a
            // directly-reachable server.
            _logger.LogDebug(ex, "[2FA] Could not read Jellyfin's published server URI");
            return null;
        }
    }

    /// <summary>Picks the entry that describes the outside world from
    /// Jellyfin's <c>PublishedServerUriBySubnet</c>. Entries are
    /// "&lt;subnet&gt;=&lt;uri&gt;" pairs; only the two that mean "everyone
    /// else" are usable here, because a subnet-specific URI is by definition
    /// not the address an IdP or a phone on mobile data would use. "external"
    /// wins over "all" when both are present, being the more specific
    /// statement of the two.</summary>
    internal static string? PickPublished(IReadOnlyList<string>? entries)
    {
        if (entries is null || entries.Count == 0)
        {
            return null;
        }

        string? all = null;
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            var split = entry.Split('=', 2);
            if (split.Length != 2) continue;

            var key = split[0].Trim();
            var value = split[1].Trim();
            if (value.Length == 0) continue;

            if (string.Equals(key, "external", StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }

            if (all is null && string.Equals(key, "all", StringComparison.OrdinalIgnoreCase))
            {
                all = value;
            }
        }

        return all;
    }

    /// <summary>Accepts an absolute http(s) URL and returns "scheme://host[:port][/path]"
    /// with no trailing slash, or null for anything unusable. Query strings,
    /// fragments, credentials and non-http schemes are refused rather than
    /// silently trimmed: a link built from a half-understood value would fail
    /// at the IdP with no clue why.</summary>
    internal static string? Normalize(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        if (!Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return null;
        }

        var origin = uri.GetLeftPart(UriPartial.Authority);
        var path = uri.AbsolutePath.TrimEnd('/');
        return path.Length <= 1 ? origin : origin + path;
    }
}

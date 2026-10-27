using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#298] Rules for signing in the user a trusted reverse proxy names
/// in a header (NetBird's X-NetBird-User, Remote-User, ...). Everything that
/// decides whether to believe the header lives here, apart from the request,
/// so it can be tested as written.
///
/// SECURITY: the header is only believed from the proxy's own address, taken
/// from the raw TCP peer that the first plugin middleware records. Jellyfin's
/// forwarded-headers handling (KnownProxies) can rewrite the connection
/// address before the controllers run, and the X-Forwarded-For walk reports
/// the client, so neither may decide who is allowed to assert identity.</summary>
internal static class HeaderSignIn
{
    /// <summary>Label the bridge token carries, so the audit row and the logs
    /// name the proxy sign-in.</summary>
    internal const string BridgeProviderId = "trusted-proxy";

    internal const string RawPeerItem = "TwoFactorAuth.RawPeer";

    private const int MaxUserLength = 256;

    /// <summary>Recorded by the first plugin middleware, before anything in
    /// the pipeline can rewrite the connection address.</summary>
    internal static void RememberRawPeer(HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address is not null && address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        context.Items[RawPeerItem] = address?.ToString();
    }

    /// <summary>The recorded raw peer, or null when none was recorded: then
    /// nothing is trusted.</summary>
    internal static string? RawPeer(HttpContext context)
        => context.Items.TryGetValue(RawPeerItem, out var value) ? value as string : null;

    internal static bool FromTrustedProxy(string? rawPeer, IReadOnlyCollection<string>? proxyCidrs)
    {
        if (string.IsNullOrEmpty(rawPeer) || proxyCidrs is null)
        {
            return false;
        }

        foreach (var entry in proxyCidrs)
        {
            var cidr = entry?.Trim();
            if (!string.IsNullOrEmpty(cidr) && IsNarrowEnough(cidr) && BypassEvaluator.IsIpInCidr(rawPeer, cidr))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The same floor the config import enforces: /8 for IPv4, /16
    /// for IPv6. A bare address is a single host.</summary>
    private static bool IsNarrowEnough(string cidr)
    {
        var slash = cidr.IndexOf('/', StringComparison.Ordinal);
        var host = slash < 0 ? cidr : cidr[..slash];
        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (slash < 0)
        {
            return true;
        }

        if (!int.TryParse(cidr[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
        {
            return false;
        }

        return address.AddressFamily == AddressFamily.InterNetwork ? prefix >= 8 : prefix >= 16;
    }

    /// <summary>Whether the browser marked this request as coming from another
    /// site (Sec-Fetch-Site anything but same-origin).
    ///
    /// SECURITY: a proxy that knows the user by the connection rather than by
    /// a cookie names them on every request from their machine, including one
    /// a script on another site sends from their browser; were Jellyfin's CORS
    /// policy to let that script read the answer, it would walk away with the
    /// bridge token. The login page's own call is same-origin. Without the
    /// header (an older browser, or not a browser at all) the request is
    /// judged on the proxy address alone.</summary>
    internal static bool FromAnotherSite(StringValues secFetchSite)
        => secFetchSite.Count > 0
            && !string.Equals(secFetchSite[0], "same-origin", StringComparison.OrdinalIgnoreCase);

    /// <summary>The single user the header names, trimmed. Null when the
    /// header is missing, repeated, empty, too long, or carries a control
    /// character or a comma (a proxy that appends would otherwise pass on a
    /// name the client chose).</summary>
    internal static string? NamedUser(StringValues values)
    {
        if (values.Count != 1)
        {
            return null;
        }

        var value = values[0]?.Trim();
        if (string.IsNullOrEmpty(value) || value.Length > MaxUserLength)
        {
            return null;
        }

        return value.Any(c => char.IsControl(c) || c == ',') ? null : value;
    }

    internal static string[] NamedGroups(StringValues values)
        => SplitList(string.Join(',', values.Where(v => v is not null)));

    /// <summary>True when no groups are required, or the user is in one of them.</summary>
    internal static bool InAllowedGroup(string allowedGroups, IReadOnlyCollection<string> groups)
    {
        var allowed = SplitList(allowedGroups);
        return allowed.Length == 0 || groups.Any(g => allowed.Contains(g, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Jellyfin usernames to try, in order: the named user itself;
    /// then, for an email in a domain the administrator listed, the part
    /// before the @. Nothing a user can set on their own account is used.</summary>
    internal static IReadOnlyList<string> UsernameCandidates(string named, string emailDomains)
    {
        var candidates = new List<string> { named };
        var at = named.LastIndexOf('@');
        if (at > 0 && at < named.Length - 1
            && SplitList(emailDomains).Contains(named[(at + 1)..], StringComparer.OrdinalIgnoreCase))
        {
            candidates.Add(named[..at]);
        }

        return candidates;
    }

    /// <summary>Why the matched account may not sign in through the proxy, or
    /// null when it may. A disabled account never may; an administrator only
    /// when the administrator turned that on, and the groups header never
    /// grants it.</summary>
    internal static string? Refusal(bool isDisabled, bool isAdministrator, bool allowAdministrators)
    {
        if (isDisabled)
        {
            return "This account is disabled.";
        }

        return isAdministrator && !allowAdministrators
            ? "Administrator accounts can't sign in through the proxy on this server."
            : null;
    }

    /// <summary>Whether the login page should try the proxy sign-in for this
    /// request: the feature is on, the request came through the proxy, and the
    /// proxy named a user.</summary>
    internal static bool Available(PluginConfiguration cfg, string? rawPeer, IHeaderDictionary headers)
    {
        if (!cfg.HeaderSignInEnabled || string.IsNullOrWhiteSpace(cfg.HeaderSignInUserHeader))
        {
            return false;
        }

        return FromTrustedProxy(rawPeer, cfg.HeaderSignInProxyCidrs)
            && NamedUser(headers[cfg.HeaderSignInUserHeader.Trim()]) is not null;
    }

    /// <summary>The feature is on and the request carries the user header,
    /// but it did not come from a listed proxy address. Worth a log line: the
    /// usual cause is a proxy that reaches Jellyfin from an address missing
    /// from the list, and nothing else would say which one.</summary>
    internal static bool NamedFromUnlistedAddress(PluginConfiguration cfg, string? rawPeer, IHeaderDictionary headers)
    {
        if (!cfg.HeaderSignInEnabled || string.IsNullOrWhiteSpace(cfg.HeaderSignInUserHeader))
        {
            return false;
        }

        return headers.ContainsKey(cfg.HeaderSignInUserHeader.Trim())
            && !FromTrustedProxy(rawPeer, cfg.HeaderSignInProxyCidrs);
    }

    private static string[] SplitList(string? list)
        => (list ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

using System;
using System.Net;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#244] App passwords are for apps that cannot show the plugin's 2FA
/// challenge (Seerr, Swiftfin, the TV apps). The Jellyfin web interface in a
/// browser can show it, and an app password typed there signed in with no
/// second factor and every right the account has, admin settings included.
/// The web interface is told apart by the client name it sends, which a
/// caller holding the app password could change, so this closes the ordinary
/// path rather than drawing a hard boundary.
/// </summary>
internal static class AppPasswordClientPolicy
{
    /// <summary>What jellyfin-web sends when no native shell replaces it
    /// (src/components/apphost.js). Jellyfin's own apps that wrap the web
    /// interface send their own names ("Jellyfin for Android", "Jellyfin
    /// Desktop", "Jellyfin for Tizen", "Jellyfin for WebOS").</summary>
    internal const string WebInterfaceClient = "Jellyfin Web";

    /// <summary>The client name as Jellyfin records it for the session: the
    /// Client key of the standard Authorization header, then of
    /// X-Emby-Authorization, URL-decoded the way Jellyfin's
    /// AuthorizationContext decodes it (jellyfin-web sends
    /// "Jellyfin%20Web"), with the X-Emby-Client header as a last resort.</summary>
    internal static string? ResolveClientName(string? authorization, string? xEmbyAuthorization, string? xEmbyClient)
    {
        var raw = TwoFactorAuthProvider.ParseEmbyAuth(authorization, "Client")
            ?? TwoFactorAuthProvider.ParseEmbyAuth(xEmbyAuthorization, "Client")
            ?? xEmbyClient;
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var name = WebUtility.UrlDecode(raw).Trim();
        return name.Length == 0 ? null : name;
    }

    /// <summary>True when an app password must not sign this client in.</summary>
    internal static bool IsRefused(string? clientName)
        => string.Equals(clientName?.Trim(), WebInterfaceClient, StringComparison.OrdinalIgnoreCase);
}

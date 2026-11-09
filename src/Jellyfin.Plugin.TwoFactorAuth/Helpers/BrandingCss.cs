using System;
using System.Text.Json;

namespace Jellyfin.Plugin.TwoFactorAuth.Helpers;

/// <summary>[#348] Puts the server's custom CSS (Dashboard, Branding) on the
/// plugin's standalone pages. Those pages never load Jellyfin's index.html,
/// so neither that CSS nor anything injected into index.html reaches
/// them.</summary>
internal static class BrandingCss
{
    /// <summary>Returns <paramref name="html"/> with a script at the end of the
    /// body that appends a style element holding <paramref name="css"/> to the
    /// head, after the page's own styles, so a custom rule wins over a built-in
    /// rule of the same specificity. Jellyfin Web applies the same text the
    /// same way: a style element added by script.</summary>
    /// <remarks>A style element written into the markup would hold the page
    /// while an @import in the CSS loads: in the head nothing is painted, and
    /// at the end of the body the browser stops parsing there, so the scripts
    /// waiting for DOMContentLoaded never run. Themes are often an @import
    /// from a CDN, and a browser that cannot reach it would get a sign-in page
    /// that never works. A style element added by script blocks nothing.</remarks>
    public static string AddToPage(string html, string? css)
    {
        if (string.IsNullOrWhiteSpace(css))
        {
            return html;
        }

        var bodyEnd = html.LastIndexOf("</body>", StringComparison.Ordinal);
        if (bodyEnd < 0)
        {
            return html;
        }

        // The CSS goes in as a JSON string. The default encoder writes <, >,
        // &, quotes and every non-ASCII character as \uXXXX, so nothing in it
        // can close the script, start a comment or tag, or end the string.
        return html.Insert(
            bodyEnd,
            "<script>(function () { var s = document.createElement('style'); s.id = 'tfa-branding-css'; s.textContent = "
            + JsonSerializer.Serialize(css)
            + "; document.head.appendChild(s); })();</script>\n");
    }
}

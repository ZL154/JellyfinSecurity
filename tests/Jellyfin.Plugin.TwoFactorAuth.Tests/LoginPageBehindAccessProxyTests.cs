using System;
using System.Linq;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#251] The plugin's pages sent some requests without the page's
/// cookies. Behind an access layer that needs a session cookie (forward auth,
/// Cloudflare Access), those requests got the layer's sign-in page instead: the
/// login page silently dropped to its default layout, the reset link failed at
/// submit, and the OIDC set-password page sent the user back to sign-in.</summary>
public class LoginPageBehindAccessProxyTests
{
    [Fact]
    public void No_page_of_the_plugin_sends_requests_without_the_pages_cookies()
    {
        var pages = typeof(Plugin).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith("Jellyfin.Plugin.TwoFactorAuth.Pages.", StringComparison.Ordinal)
                        && (n.EndsWith(".html", StringComparison.Ordinal) || n.EndsWith(".js", StringComparison.Ordinal)))
            .ToList();

        Assert.Contains("Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js", pages);
        Assert.Contains("Jellyfin.Plugin.TwoFactorAuth.Pages.password-reset.html", pages);
        Assert.Contains("Jellyfin.Plugin.TwoFactorAuth.Pages.setpassword.html", pages);
        foreach (var page in pages)
        {
            var content = ResourceReader.ReadEmbeddedText(page);
            Assert.NotNull(content);
            Assert.False(content.Contains("credentials: 'omit'", StringComparison.Ordinal), page + " omits cookies");
        }
    }

    [Fact]
    public void A_public_config_the_login_page_cannot_read_is_reported_in_the_console()
    {
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");
        Assert.NotNull(script);

        Assert.Contains("fetch(serverUrl('TwoFactorAuth/public-config'))", script);
        Assert.Contains("if (!r.ok) throw new Error('HTTP ' + r.status);", script);
        Assert.Contains("(r.redirected ? ', redirected to ' + r.url : '')", script);
        Assert.Contains("console.warn('[2FA] Could not read TwoFactorAuth/public-config (", script);
    }
}

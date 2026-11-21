using System;
using System.Linq;
using System.Net;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#251] The plugin's pages sent some requests without the page's
/// cookies. Behind an access layer that needs a session cookie (forward auth,
/// Cloudflare Access), those requests got the layer's sign-in page instead: the
/// login page silently dropped to its default layout, the reset link failed at
/// submit, and the OIDC set-password page sent the user back to sign-in.</summary>
[Collection("SignInPolicy")]
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

        Assert.Contains("serverUrl('TwoFactorAuth/public-config')", script);
        Assert.Contains("if (!r.ok) throw new Error('HTTP ' + r.status);", script);
        Assert.Contains("(r.redirected ? ', redirected to ' + r.url : '')", script);
        Assert.Contains("console.warn('[2FA] Could not read TwoFactorAuth/public-config (", script);
    }

    [Theory]
    [InlineData("203.0.113.10", true, true, false, true)]
    [InlineData("10.20.0.8", true, true, true, false)]
    [InlineData("10.20.0.8", true, true, false, true)]
    [InlineData("192.0.2.8", true, true, false, false)]
    [InlineData("203.0.113.10", false, true, false, false)]
    [InlineData("203.0.113.10", true, false, false, false)]
    public void Blocking_script_and_public_config_agree_for_the_request(
        string address, bool enabled, bool disablePasswordLogin, bool allowLan, bool expected)
    {
        using var fixture = new SignInPolicyFixture();
        fixture.Config.Enabled = enabled;
        fixture.Config.DisablePasswordLogin = disablePasswordLogin;
        fixture.Config.AllowPasswordLoginOnLan = allowLan;
        fixture.Config.LanBypassCidrs = ["10.20.0.0/16"];
        fixture.Config.PasswordLoginExemptCidrs = ["192.0.2.0/24"];
        var controller = new TwoFactorAuthController(
            store: null!, challengeStore: null!, totpService: null!, emailOtpService: null!,
            deviceTokenService: null!, devicePairingService: null!, notificationService: null!,
            sessionManager: null!, userManager: null!, cookieSigner: null!, rateLimiter: null!,
            recoveryCodes: null!, appPasswords: null!, pendingPairings: null!, deviceManager: null!,
            sessionTerm: null!, passkeys: null!, passkeyChallenges: null!, diagnostics: null!,
            stats: null!, userExport: null!, recoveryPdf: null!, ipBans: null!, allowlist: null!,
            stepUp: null!, scoreService: null!, configExport: null!, onboardingProofs: null!,
            externalUrls: null!, signInObserver: null!, logger: NullLogger<TwoFactorAuthController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
        };
        controller.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse(address);

        var script = Assert.IsType<ContentResult>(controller.GetInjectScript());
        Assert.StartsWith($"window.__tfaPasswordLoginDisabled = {(expected ? "true" : "false")};", script.Content);
        Assert.Contains("no-store", controller.Response.Headers.CacheControl.ToString(), StringComparison.Ordinal);
        var config = Assert.IsType<OkObjectResult>(controller.GetPublicConfig());
        Assert.Equal(expected, JsonSerializer.SerializeToElement(config.Value).GetProperty("passwordLoginDisabled").GetBoolean());
    }
}

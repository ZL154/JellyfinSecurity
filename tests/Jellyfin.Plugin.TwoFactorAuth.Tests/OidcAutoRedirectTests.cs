using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#297] OIDC auto-redirect: off by default, carried to the anonymous
/// login-page listing only for providers whose button shows, and wired through
/// the admin page and the login-page script.</summary>
public class OidcAutoRedirectTests
{
    [Fact]
    public void NewProvidersDoNotRedirect()
    {
        Assert.False(new OidcProvider().AutoRedirect);
    }

    [Fact]
    public void PublicListing_CarriesTheOption_ForProvidersWhoseButtonShows()
    {
        var rows = PublicRows(
            new OidcProvider { Id = "authentik", DisplayName = "Authentik", AutoRedirect = true },
            new OidcProvider { Id = "google", DisplayName = "Google" },
            new OidcProvider { Id = "hidden", DisplayName = "Hidden", AutoRedirect = true, ShowLoginButton = false },
            new OidcProvider { Id = "off", DisplayName = "Off", AutoRedirect = true, Enabled = false });

        var listed = rows.Select(r => (r.GetProperty("id").GetString() ?? string.Empty, r.GetProperty("autoRedirect").GetBoolean()));

        // The redirect reuses the provider's own button, so a provider whose
        // button is hidden or that is switched off is not listed at all.
        Assert.Equal(new[] { ("authentik", true), ("google", false) }, listed);
    }

    [Fact]
    public void PublicListing_StillCarriesNoAdminOnlyField()
    {
        var row = PublicRows(new OidcProvider
        {
            Id = "authentik",
            DisplayName = "Authentik",
            ClientId = "jellyfin",
            ClientSecret = "secret",
            DiscoveryUrl = "https://idp.example/.well-known/openid-configuration",
            AutoRedirect = true,
        }).Single();

        var names = row.EnumerateObject().Select(p => p.Name).OrderBy(n => n);

        Assert.Equal(
            new[] { "autoRedirect", "buttonIconUrl", "buttonText", "displayName", "enabled", "id" },
            names);
    }

    [Fact]
    public void AdminPage_ExposesTheOption_AndScriptRoundTripsIt()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);

        Assert.Contains("id=\"ssoAutoRedirect\"", page);
        Assert.Contains("tfa.admin.sso.opt_auto_redirect", page);
        Assert.Contains("tfa.admin.sso.opt_auto_redirect_help", page);

        // Read back into the form, and sent on save. A control wired only one
        // way silently discards the admin's choice.
        Assert.Contains("prov.autoRedirect", script);
        Assert.Contains("AutoRedirect:", script);
    }

    [Fact]
    public void InjectScript_RedirectsThroughTheDecision_AndRemembersASignOut()
    {
        var inject = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(inject);

        Assert.Contains("function oidcAutoRedirectTarget(s)", inject);
        Assert.Contains("oidcAutoRedirectTarget({", inject);
        // The opt-out a person can type to reach the password form.
        Assert.Contains("'oidcAuto'", inject);
        // Replacing the login page keeps Back from landing on a page that
        // would redirect again.
        Assert.Contains("window.location.replace(", inject);
        // A real sign-out is remembered for the tab, inside the one hook that
        // only fires on the user's own sign-out.
        Assert.Contains("tfaRememberSignOut()", inject);
    }

    private static JsonElement[] PublicRows(params OidcProvider[] providers)
    {
        var json = JsonSerializer.Serialize(SecurityController.PublicProviderRows(providers));
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToArray();
    }
}

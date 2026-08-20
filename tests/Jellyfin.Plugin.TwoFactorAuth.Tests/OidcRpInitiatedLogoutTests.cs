using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#134] RP-Initiated Logout: URL composition, the https-only guard
/// on both the OP-supplied endpoint and the admin-supplied return URL, and the
/// admin-page contract for the new provider options.</summary>
public class OidcRpInitiatedLogoutTests
{
    [Fact]
    public void EndSessionUrl_CarriesClientId_AndOmitsIdTokenHint()
    {
        var url = OidcService.BuildEndSessionUrl(
            "https://idp.example/realms/master/protocol/openid-connect/logout",
            "jellyfin",
            postLogoutRedirectUri: null);

        Assert.Equal(
            "https://idp.example/realms/master/protocol/openid-connect/logout?client_id=jellyfin",
            url);
        // The plugin never retains an id_token, so it must never claim to.
        Assert.DoesNotContain("id_token_hint", url);
    }

    [Fact]
    public void EndSessionUrl_AppendsToAnExistingQueryInsteadOfClobberingIt()
    {
        var url = OidcService.BuildEndSessionUrl(
            "https://idp.example/logout?tenant=acme",
            "jellyfin",
            postLogoutRedirectUri: null);

        Assert.Equal("https://idp.example/logout?tenant=acme&client_id=jellyfin", url);
    }

    [Fact]
    public void EndSessionUrl_EscapesTheClientId()
    {
        var url = OidcService.BuildEndSessionUrl(
            "https://idp.example/logout",
            "a b&c=d",
            postLogoutRedirectUri: null);

        Assert.Equal("https://idp.example/logout?client_id=a%20b%26c%3Dd", url);
    }

    [Fact]
    public void EndSessionUrl_SendsPostLogoutRedirectUriOnlyWhenConfigured()
    {
        var without = OidcService.BuildEndSessionUrl("https://idp.example/logout", "jf", null);
        Assert.DoesNotContain("post_logout_redirect_uri", without);

        var with = OidcService.BuildEndSessionUrl(
            "https://idp.example/logout", "jf", "https://jf.example.com/TwoFactorAuth/Oidc/LoggedOut");
        Assert.Contains(
            "post_logout_redirect_uri=https%3A%2F%2Fjf.example.com%2FTwoFactorAuth%2FOidc%2FLoggedOut",
            with);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    // An OP that publishes nothing usable must degrade to a local sign-out,
    // never to a navigation somewhere unexpected.
    [InlineData("/realms/master/logout")]
    [InlineData("http://idp.example/logout")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    [InlineData("not a url at all")]
    public void EndSessionUrl_IsNullUnlessTheEndpointIsAbsoluteHttps(string? endpoint)
    {
        Assert.Null(OidcService.BuildEndSessionUrl(endpoint, "jellyfin", null));
    }

    [Theory]
    [InlineData("http://jf.example.com/back")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/relative/path")]
    public void EndSessionUrl_DropsAReturnUrlThatIsNotAbsoluteHttps(string redirect)
    {
        var url = OidcService.BuildEndSessionUrl("https://idp.example/logout", "jf", redirect);

        Assert.NotNull(url);
        Assert.DoesNotContain("post_logout_redirect_uri", url);
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("http://jf.example.com/back", "")]
    [InlineData("javascript:alert(1)", "")]
    [InlineData("/TwoFactorAuth/Oidc/LoggedOut", "")]
    [InlineData("https://jf.example.com/TwoFactorAuth/Oidc/LoggedOut", "https://jf.example.com/TwoFactorAuth/Oidc/LoggedOut")]
    public void SanitizePostLogoutRedirectUri_KeepsOnlyAbsoluteHttps(string? input, string expected)
    {
        Assert.Equal(expected, SecurityController.SanitizePostLogoutRedirectUri(input));
    }

    [Fact]
    public void SanitizePostLogoutRedirectUri_TrimsSurroundingWhitespace()
    {
        Assert.Equal(
            "https://jf.example.com/back",
            SecurityController.SanitizePostLogoutRedirectUri("  https://jf.example.com/back  "));
    }

    [Fact]
    public void AdminPage_ExposesTheProviderOptions_AndScriptRoundTripsThem()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);

        Assert.Contains("id=\"ssoRpLogout\"", page);
        Assert.Contains("id=\"ssoRpLogoutRedirect\"", page);
        Assert.Contains("tfa.admin.sso.opt_rp_logout", page);
        Assert.Contains("tfa.admin.sso.desc_rp_logout_redirect", page);

        // Read back into the form, and sent on save. A control wired only one
        // way silently discards the admin's choice.
        Assert.Contains("prov.rpInitiatedLogoutEnabled", script);
        Assert.Contains("prov.rpInitiatedLogoutRedirectUri", script);
        Assert.Contains("RpInitiatedLogoutEnabled:", script);
        Assert.Contains("RpInitiatedLogoutRedirectUri:", script);
    }

    [Fact]
    public void InjectScript_HandsOffToTheIdpOnlyOnARealSignOut()
    {
        var inject = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(inject);

        // The hook is ApiClient.logout, not the /Sessions/Logout request, so it
        // cannot race the token revocation the fetch/XHR patches sit on.
        Assert.Contains("tfaWrapLogoutForRpLogout", inject);
        Assert.Contains("TwoFactorAuth/Oidc/EndSession/", inject);

        // Reopening the account picker is not a sign-out and must not send the
        // user to the IdP.
        Assert.Contains("tfaSuppressRpLogout", inject);
    }

    [Fact]
    public void EndSessionUrl_DropsAFragmentSoClientIdStillReachesTheProvider()
    {
        // Appending after a fragment leaves client_id client-side, and without
        // id_token_hint client_id is the only thing identifying the RP.
        var url = OidcService.BuildEndSessionUrl(
            "https://idp.example/logout#section", "jf", null);

        Assert.Equal("https://idp.example/logout?client_id=jf", url);
        Assert.DoesNotContain("#", url);
    }

    [Theory]
    [InlineData("https://idp.example/logout\r\nX-Injected: 1")]
    [InlineData("https://idp.example/logout\nX-Injected: 1")]
    [InlineData("https://idp.example/logout\r")]
    public void EndSessionUrl_NeverEmitsControlCharacters(string endpoint)
    {
        // Uri.TryCreate accepts these. Handing the raw string to Redirect()
        // makes Kestrel throw on the Location header, so somebody who clicked
        // Sign out gets a 500 instead of getting signed out.
        var url = OidcService.BuildEndSessionUrl(endpoint, "jf", null);

        Assert.NotNull(url);
        Assert.All(url, c => Assert.False(char.IsControl(c)));
    }

    [Fact]
    public void EndSessionUrl_StillKeepsAQueryTheProviderPublishes()
    {
        // The fragment fix must not cost us the tenanted-OP query case.
        var url = OidcService.BuildEndSessionUrl(
            "https://idp.example/logout?tenant=acme#frag", "jf", null);

        Assert.Equal("https://idp.example/logout?tenant=acme&client_id=jf", url);
    }

    [Fact]
    public void SanitizePostLogoutRedirectUri_DoesNotRewriteWhatTheAdminRegistered()
    {
        // The IdP matches post_logout_redirect_uri against the registered value
        // exactly, so decoding or otherwise canonicalising it can only turn a
        // correct configuration into a rejected one.
        const string encoded = "https://jf.example.com/back?next=a%20b";
        Assert.Equal(encoded, SecurityController.SanitizePostLogoutRedirectUri(encoded));

        const string bareOrigin = "https://jf.example.com";
        Assert.Equal(bareOrigin, SecurityController.SanitizePostLogoutRedirectUri(bareOrigin));
    }

    [Theory]
    [InlineData("Jellyfin.Plugin.TwoFactorAuth.Pages.login.html")]
    [InlineData("Jellyfin.Plugin.TwoFactorAuth.Pages.challenge.html")]
    public void LocalSignInPages_DisarmTheRpLogoutMarker(string resource)
    {
        // A password or 2FA sign-in in a browser that previously used SSO must
        // not inherit that session's marker. Otherwise its sign-out ends an IdP
        // session belonging to a different login, and on a shared browser to a
        // different person.
        var page = ResourceReader.ReadEmbeddedText(resource);

        Assert.NotNull(page);
        Assert.Contains("localStorage.removeItem('__tfa_rp_logout')", page);
    }
}

using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class AdminPageContractTests
{
    [Fact]
    public void Audit_ui_defaults_to_newest_and_sorts_a_copy()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);
        Assert.Contains("id=\"auditSortOrder\"", page);
        Assert.Contains("<option value=\"desc\"", page);
        Assert.Contains("var auditSortOrder = 'desc';", script);
        Assert.Contains("return entries.slice().sort(", script);
        Assert.Contains("orderedAudit(allAudit).forEach", script);
    }

    [Fact]
    public void SetPassword_page_exposes_account_and_server_side_logout()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.setpassword.html");

        Assert.NotNull(page);
        Assert.Contains("id=\"accountName\"", page);
        Assert.Contains("id=\"cancelLogout\"", page);
        Assert.Contains("../TwoFactorAuth/SetPassword/Logout", page);
        Assert.Contains("requireSymbol", page);
        Assert.Contains("id=\"form\" hidden", page);
        Assert.Contains("form.hidden = false", page);
        Assert.Contains("window.location.replace('../web/index.html#/login')", page);
        Assert.Contains("r.status === 401 || r.status === 403", page);
        Assert.Contains("../TwoFactorAuth/Oidc/OnboardingValidationBegin", page);
        Assert.Contains("X-JellyfinSecurity-Onboarding-Proof", page);
        Assert.Contains("oidc-proof", page);
        Assert.Contains("else if (token) beginSessionValidation();", page);
        Assert.DoesNotContain("Continue to Jellyfin for now", page);
    }

    [Fact]
    public void Challenge_page_shows_the_challenge_bound_account_for_every_method()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.challenge.html");

        Assert.NotNull(page);
        Assert.Contains("id=\"challengeAccount\"", page);
        Assert.Contains("tfa.challenge.signing_in_as", page);
        Assert.Contains("info.Username || info.username", page);
        Assert.Contains("accountIndicator.hidden = !username", page);
        Assert.DoesNotContain("showEnrollmentRequired(info.Username", page);
        Assert.DoesNotContain("tfa.challenge.setup_required_for", page);
    }

    [Theory]
    [InlineData(false, "/jellyfin/web/index.html")]
    [InlineData(true, "/jellyfin/TwoFactorAuth/SetPassword")]
    public void Oidc_browser_bridge_keeps_every_runtime_path_below_BaseUrl(
        bool mustSetPassword,
        string expectedLanding)
    {
        var paths = SecurityController.BuildOidcBridgePaths(
            requestPathBase: string.Empty,
            requestPath: "/jellyfin/TwoFactorAuth/Oidc/Callback/keycloak",
            mustSetPassword: mustSetPassword);

        Assert.Equal("/jellyfin", paths.BasePath);
        Assert.Equal("/jellyfin/Users/AuthenticateByName", paths.AuthenticatePath);
        Assert.Equal(expectedLanding, paths.LandingPath);
        Assert.Equal("/jellyfin/web/index.html#!/login.html", paths.LoginPath);
    }

    [Fact]
    public void Dashboard_navigation_targets_visible_drawer_and_clones_native_row()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(script);
        Assert.Contains("getClientRects().length > 0", script);
        Assert.Contains("anchor.cloneNode(true)", script);
        Assert.Contains("existing.parentElement === parent", script);
        Assert.Contains("existing.previousElementSibling === anchor", script);
        Assert.DoesNotContain(
            "if (document.getElementById(DASHBOARD_NAV_ID)) return;",
            script);
        Assert.Contains("syncDashboardNavLanguage", script);
        Assert.Contains("attributeFilter: ['lang']", script);
    }

    [Fact]
    public void Trusted_device_token_survives_cookie_loss_on_stock_and_standalone_login()
    {
        var injectedScript = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");
        var loginPage = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.login.html");

        Assert.NotNull(injectedScript);
        Assert.NotNull(loginPage);
        Assert.Contains("twofactor_device_token", injectedScript);
        Assert.Contains("X-TwoFactor-Token", injectedScript);
        Assert.Contains("twofactor_device_token", loginPage);
        Assert.Contains("X-TwoFactor-Token", loginPage);
        Assert.Contains("X-TwoFactor-Device-Token", loginPage);
    }

    [Fact]
    public void Native_auth_rewrites_the_canonical_authorization_device_identity()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(script);
        Assert.Contains("rewriteAuthorizationDeviceId", script);
        Assert.Contains("rewriteHeader('Authorization')", script);
        Assert.Contains("rewriteHeader('X-Emby-Authorization')", script);
        Assert.Contains("__tfa_authHeaders", script);
        Assert.Contains("lower === 'authorization' || lower === 'x-emby-authorization'", script);
    }

    [Fact]
    public void Pending_challenge_does_not_override_explicit_user_selection()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(script);
        Assert.Contains("function isExplicitLoginRoute()", script);

        var pendingCheck = script.IndexOf("function isTfaPending()", StringComparison.Ordinal);
        var loginEscape = script.IndexOf(
            "if (isExplicitLoginRoute())",
            pendingCheck,
            StringComparison.Ordinal);
        var pendingRead = script.IndexOf(
            "sessionStorage.getItem(TFA_PENDING_KEY)",
            pendingCheck,
            StringComparison.Ordinal);

        Assert.True(pendingCheck >= 0);
        Assert.True(loginEscape > pendingCheck);
        Assert.True(pendingRead > loginEscape);
    }

    [Fact]
    public void Native_pending_session_logs_out_before_opening_stock_user_picker()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(script);

        var redirect = script.IndexOf("function redirectToTfaPortal()", StringComparison.Ordinal);
        var nativeClient = script.IndexOf("if (inEmbeddedWebView()", redirect, StringComparison.Ordinal);
        var canonicalLogout = script.IndexOf("window.ApiClient.logout()", nativeClient, StringComparison.Ordinal);
        var stockPicker = script.IndexOf(
            "serverUrl('web/index.html#/login')",
            nativeClient,
            StringComparison.Ordinal);
        var standalonePortal = script.IndexOf(
            "serverUrl('TwoFactorAuth/Login')",
            Math.Max(canonicalLogout, stockPicker),
            StringComparison.Ordinal);

        Assert.True(redirect >= 0);
        Assert.True(nativeClient > redirect);
        Assert.True(canonicalLogout > nativeClient);
        Assert.True(stockPicker > nativeClient);
        Assert.True(standalonePortal > canonicalLogout);
        Assert.True(standalonePortal > stockPicker);
    }

}

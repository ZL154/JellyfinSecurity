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
    public void Telegram_and_alert_emails_are_settings_and_channels_on_the_admin_page()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);
        // #259: the bot token is a masked box; both Telegram boxes are read and
        // saved through lookups that keep the server's values when an older
        // cached admin.html lacks them; and the test button counts Telegram and
        // the alert emails as channels and saves them before sending.
        Assert.Contains("type=\"password\" id=\"cfgTelegramToken\"", page);
        Assert.Contains("id=\"cfgTelegramChat\"", page);
        Assert.Contains("data-i18n-key=\"tfa.admin.settings.alert_emails_note\"", page);
        Assert.Contains("if (telegramTokenLoadEl) telegramTokenLoadEl.value = c.TelegramBotToken || '';", script);
        Assert.Contains("if (telegramTokenSaveEl) c.TelegramBotToken = telegramTokenSaveEl.value.trim();", script);
        Assert.Contains("&& !(telegramToken && telegramChat) && alertEmails.length === 0) {", script);
        Assert.Contains("c.NotifyEmailAddresses = alertEmails;", script);
        // The SMTP boxes are read in one place, which Save Settings and both
        // test buttons call, so the three cannot drift apart.
        var smtpFromSave = "c.SmtpFromAddress = page.querySelector('#cfgSmtpFrom').value.trim();";
        Assert.Equal(1, script!.Split(smtpFromSave).Length - 1);
        Assert.Equal(3, script.Split("applySmtpFields(c);").Length - 1);
    }

    [Fact]
    public void Both_test_buttons_save_what_is_on_screen_through_the_step_up_prompt()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(script);
        // #259: the server sends the SMTP test with the saved settings, and the
        // button sent it without saving, so a test run before Save Settings
        // used the last-saved values (or none) and only said to check the
        // server log. Both test buttons now save the boxes first, and through
        // stepUpFetch like Save Settings: ApiClient.updatePluginConfiguration
        // turns the step-up filter's 403 into a plain failure, with no prompt.
        var smtpTest = ClickHandler(script!, "#btnTestSmtp");
        var notifyTest = ClickHandler(script, "#btnTestWebhook");
        foreach (var handler in new[] { smtpTest, notifyTest })
        {
            Assert.Contains("applySmtpFields(c);", handler);
            Assert.Contains("return savePluginConfig(c);", handler);
            Assert.Contains("if (!r.ok) return Promise.reject(r);", handler);
            Assert.DoesNotContain("updatePluginConfiguration", handler);
        }

        Assert.True(smtpTest.IndexOf("savePluginConfig(c)", StringComparison.Ordinal)
            < smtpTest.IndexOf("'TwoFactorAuth/TestSmtp'", StringComparison.Ordinal));
        Assert.Contains("_tr('tfa.admin.settings.saving_sending', 'Saving + sending…')", smtpTest);
        Assert.Contains("return savePluginConfig(c).then(function(r) {", ClickHandler(script, "#btnSaveSettings"));
        Assert.Contains("return stepUpFetch('Plugins/' + pluginId + '/Configuration', {", script);
    }

    // A button's click handler, from its addEventListener to the next one.
    private static string ClickHandler(string script, string id)
    {
        var head = "page.querySelector('" + id + "').addEventListener('click', function() {";
        var start = script.IndexOf(head, StringComparison.Ordinal);
        Assert.True(start >= 0, id + " has no click handler");
        var end = script.IndexOf(".addEventListener(", start + head.Length, StringComparison.Ordinal);
        return end < 0 ? script[start..] : script[start..end];
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
        Assert.Equal("/jellyfin/web/index.html#/login", paths.LoginPath);
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
    public void Admin_step_up_modal_offers_the_emailed_code_and_a_passkey()
    {
        // #194: the modal accepted a typed TOTP or recovery code and nothing
        // else, so an admin whose factor is email OTP or a passkey could never
        // clear the gate. The modal now reuses the self-service step-up
        // endpoints and hands StepUp/Verify either a code or the passkey token.
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var english = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.translations.en.json");

        Assert.NotNull(script);
        Assert.NotNull(page);
        Assert.NotNull(english);

        Assert.Contains("function promptStepUpProof()", script);
        Assert.Contains("TwoFactorAuth/StepUp/UserPasskeyBegin", script);
        Assert.Contains("TwoFactorAuth/StepUp/UserPasskeyVerify", script);
        Assert.Contains("TwoFactorAuth/StepUp/UserEmailSend", script);
        Assert.Contains("proof.stepUpToken ? { StepUpToken: proof.stepUpToken } : { Code: proof.code }", script);
        Assert.DoesNotContain("promptStepUpCode()", script);

        Assert.Contains("id=\"tfa-stepup-passkey\"", page);
        Assert.Contains("id=\"tfa-stepup-email\"", page);
        Assert.Contains("id=\"tfa-stepup-status\"", page);

        foreach (var key in new[] { "tfa.admin.modal.use_passkey", "tfa.admin.modal.send_email", "tfa.admin.modal.email_sent", "tfa.admin.modal.email_failed", "tfa.admin.modal.passkey_failed", "tfa.admin.modal.err_https" })
        {
            Assert.Contains("\"" + key + "\"", english);
        }
    }

    [Fact]
    public void InApp_oidc_completion_merges_credentials_with_manual_connection_mode()
    {
        // #172. The in-app OIDC completion replaced the whole credential
        // store with one entry in connection mode 1 (Remote) and no
        // RemoteAddress. Jellyfin 10.11 reconnected and rewrote the mode
        // before anything read it; the Jellyfin 12 router reads it first,
        // the ApiClient constructor throws, and an app never leaves the
        // splash screen. The browser bridge page got the merge in v2.5.21;
        // this pins the same shape on the path only apps use.
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(script);
        Assert.Contains("var TFA_CONNECTION_MODE_MANUAL = 2;", script);
        Assert.DoesNotContain("LastConnectionMode: 1", script);
        Assert.DoesNotContain("JSON.stringify({ Servers: [server] })", script);

        var complete = script.IndexOf("function completeWithBridgeToken(", StringComparison.Ordinal);
        var merge = script.IndexOf("existing.LastConnectionMode = TFA_CONNECTION_MODE_MANUAL;", complete, StringComparison.Ordinal);
        var insert = script.IndexOf("LastConnectionMode: TFA_CONNECTION_MODE_MANUAL", complete, StringComparison.Ordinal);
        var pendingCleared = script.IndexOf("clearTfaPending();", merge, StringComparison.Ordinal);
        var reload = script.IndexOf("window.location.href = serverUrl('web/index.html');", merge, StringComparison.Ordinal);

        Assert.True(complete >= 0);
        Assert.True(merge > complete);
        Assert.True(insert > complete);
        Assert.True(pendingCleared > merge);
        Assert.True(reload > pendingCleared);
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

    [Fact]
    public void User_email_box_saves_on_change_through_the_step_up_prompt()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(script);
        // #263: the Users tab saved each email box on blur through
        // ApiClient.updatePluginConfiguration, which turned the step-up
        // filter's 403 into an unhandled rejection. With step-up covering
        // config changes the edit was dropped and nothing showed on screen.
        var start = script!.IndexOf("body.querySelectorAll('.tfa-email').forEach(", StringComparison.Ordinal);
        Assert.True(start >= 0, "the Users tab has no email box handler");
        var end = script.IndexOf("\n                }\n", start, StringComparison.Ordinal);
        Assert.True(end > start);
        var handler = script[start..end];

        Assert.Contains("input.addEventListener('change', function() {", handler);
        Assert.DoesNotContain("'blur'", handler);
        Assert.DoesNotContain("updatePluginConfiguration", handler);
        Assert.Contains("stepUpFetch('Plugins/' + pluginId + '/Configuration', {", handler);
        Assert.Contains("if (!r.ok) return Promise.reject(r);", handler);
        Assert.Contains("input.defaultValue = input.value;", handler);
        Assert.Contains("input.value = saved;", handler);
        Assert.Contains("failureMessage(err).then(function(why) {", handler);
        Assert.Contains("_tr('tfa.admin.common.save_failed', 'Save failed') + (why ? ': ' + why : '')", handler);
    }

    [Fact]
    public void Admin_helpers_and_the_provider_form_go_through_the_step_up_prompt()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(script);
        // #198 (and #148 before it): the OIDC provider routes are gated by
        // StepUpGuard(ConfigChange) on the server, but the form used a raw fetch,
        // so the 403 + stepUpRequired answer surfaced as a bare "Save failed"
        // and the delete button did nothing. Everything the admin page sends
        // now goes through the step-up aware fetch.
        Assert.DoesNotContain("fetch(ApiClient.serverAddress() + '/TwoFactorAuth/Oidc/Providers", script.Replace("stepUpFetch(", string.Empty));
        Assert.Contains("stepUpFetch(ApiClient.serverAddress() + '/TwoFactorAuth/Oidc/Providers/' + encodeURIComponent(ssoEditingId)", script);
        Assert.Contains("stepUpFetch(ApiClient.serverAddress() + '/TwoFactorAuth/Oidc/Providers',", script);
        Assert.DoesNotContain("return fetch(ApiClient.serverAddress() + '/' + path", script);
        Assert.Contains("return stepUpFetch(path, { headers: getHeaders() })", script);
        Assert.Contains("return stepUpFetch(path, { method: 'POST', headers: getHeaders()", script);
        Assert.Contains("return stepUpFetch(path, { method: 'DELETE', headers: getHeaders() })", script);

        // The status line and the alerts carry the server's reason.
        Assert.Contains("function failureMessage(err)", script);
        Assert.Contains("_tr('tfa.admin.common.save_failed', 'Save failed') + (why ? ': ' + why : '')", script);
        Assert.Contains("encodeURIComponent(b.dataset.ssoDel)).then(loadSso).catch(", script);
        Assert.Contains("{ enabled: btn.dataset.next === 'true' }).then(loadUsers).catch(", script);
    }

    [Fact]
    public void Geo_settings_and_a_factor_left_out_of_the_score_reach_the_admin_page()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);
        // #258: both boxes exist, are read and saved through lookups that keep
        // the server's value when an older cached admin.html lacks them, and a
        // factor whose status is "na" shows its note instead of "0 / 0".
        Assert.Contains("id=\"cfgSuspiciousEnabled\"", page);
        Assert.Contains("data-i18n-key=\"tfa.admin.settings.suspicious_enabled_help\"", page);
        Assert.Contains("id=\"cfgGeoExternal\"", page);
        Assert.Contains("data-i18n-key=\"tfa.admin.settings.geo_external_help\"", page);
        Assert.Contains("if (suspiciousEl) suspiciousEl.checked = c.SuspiciousLoginEnabled !== false;", script);
        Assert.Contains("if (geoExternalEl) geoExternalEl.checked = c.GeoProtectionHandledExternally === true;", script);
        Assert.Contains(": (c.SuspiciousLoginEnabled !== false);", script);
        Assert.Contains(": (c.GeoProtectionHandledExternally === true);", script);
        Assert.Contains("const notCounted = f.status === 'na';", script);
        Assert.Contains("escapeHtml(_tr(f.noteKey, f.note || ''))", script);
        Assert.Contains("_tr('tfa.admin.posture_all_counted_full',", script);
    }

    [Fact]
    public void The_settings_page_has_no_script_tag_that_needs_a_synchronous_request()
    {
        // #307: Jellyfin's dashboard inserts this page with jQuery, which fetches
        // every <script src> in it with a synchronous XMLHttpRequest. Behind
        // Jellyfin's nginx example (Permissions-Policy sync-xhr=()) the browser
        // refused both, and the page never loaded its data.
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");

        Assert.NotNull(page);
        Assert.DoesNotMatch(new System.Text.RegularExpressions.Regex(@"<script\b[^>]*\ssrc\s*="), page);
    }

    [Fact]
    public void The_settings_page_loads_its_translations_before_its_script()
    {
        // The page script reads window.tfaI18n, so the two load in this order;
        // async = false keeps a dynamically added script in insertion order.
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");

        Assert.NotNull(page);
        Assert.Contains("['../TwoFactorAuth/tfa-i18n', '../TwoFactorAuth/admin-script'].forEach(", page);
        Assert.Contains("script.async = false;", page);
        Assert.Contains("document.head.appendChild(script);", page);
    }
}

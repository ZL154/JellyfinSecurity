using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [v2.5.10] (issue #55) Surfaces account lockout at the LOGIN step so the user
/// sees a clear "temporarily locked" message instead of Jellyfin's generic
/// "Invalid username or password".
///
/// The provider (TwoFactorAuthProvider) enforces the lockout by throwing an
/// AuthenticationException, but Jellyfin's ExceptionMiddleware strips the
/// message in production and returns a generic 401 ("Error processing
/// request."), so the web client can't distinguish a lockout from a wrong
/// password. This middleware checks lockout for the submitted username on
/// POST /Users/AuthenticateByName and, when locked, short-circuits with a
/// recognizable 401 JSON body ({"accountLocked":true,...}). inject.js detects
/// that marker (the same way it detects twoFactorRequired) and shows a toast.
///
/// Fails OPEN: any error in the pre-check lets the request flow to the normal
/// pipeline, so a bug here can never block legitimate logins. IsLockedOutAsync
/// honours the admin exemption, so an exempt administrator is never blocked.
/// </summary>
public class LockoutMessageMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly OidcLoginTokenStore _bridgeTokens;
    private readonly ILogger<LockoutMessageMiddleware> _logger;

    public LockoutMessageMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        IUserManager userManager,
        OidcLoginTokenStore bridgeTokens,
        ILogger<LockoutMessageMiddleware> logger)
    {
        _next = next;
        _store = store;
        _userManager = userManager;
        _bridgeTokens = bridgeTokens;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var config = Plugin.Instance?.Configuration;

        // Only instrument Jellyfin's password sign-in endpoints. Everything
        // else flows straight through untouched.
        if (!TryMatchPasswordAuthEndpoint(context, out var routeUserId) || config?.Enabled != true)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Read the submitted credentials once (best-effort; nulls = unreadable
        // body → behave as a pass-through). The two endpoints carry them
        // differently: AuthenticateByName posts a JSON body, while the obsolete
        // by-id form takes ?pw= and names the account by route GUID instead of
        // by username.
        string? username;
        string? password;
        Jellyfin.Database.Implementations.Entities.User? user;
        if (routeUserId != Guid.Empty)
        {
            // StringValues.ToString() joins duplicates with ',', which can only
            // ever differ from what Jellyfin's model binder resolves in the
            // direction of NOT matching a real password or a real bridge token
            // -- i.e. it fails closed, never open.
            var queryPw = context.Request.Query["pw"].ToString();
            password = string.IsNullOrEmpty(queryPw) ? null : queryPw;
            user = ResolveUserByIdSafe(routeUserId);
            username = user?.Username;
        }
        else
        {
            (username, password) = await PeekCredentialsAsync(context.Request).ConfigureAwait(false);
            user = ResolveUserSafe(username);
        }

        // 0. EMPTY-PASSWORD GATE [v2.5.10] (issue #68, CWabbity). The provider
        //    enforces BlockEmptyPasswordLogin too, but ONLY for plugin-routed
        //    users (OIDC/passkey). Normal default-provider users never reach it,
        //    so a null-hash account could still be signed into with a blank
        //    password via this endpoint. Enforce it here for EVERY sign-in. OIDC
        //    bridge tokens are non-empty, so this never blocks SSO.
        if (config.BlockEmptyPasswordLogin && string.IsNullOrWhiteSpace(password))
        {
            _logger.LogWarning("[2FA] Login refused: empty password blocked (BlockEmptyPasswordLogin) for '{User}'.", username ?? "(unknown)");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Signing in with an empty password is not allowed. Please enter your password.\",\"emptyPasswordBlocked\":true}")
                .ConfigureAwait(false);
            return;
        }

        // 0b. DISABLE-PASSWORD-LOGIN GATE [v2.5.11] (issue #69, ZEROX7). When the
        //     admin has turned off password sign-in, refuse it here so only
        //     OIDC/SSO + Quick Connect remain. Three things are NEVER blocked:
        //     (a) OIDC bridge tokens — SSO completes via this same endpoint with
        //         a one-time token as the "password", so a token this server
        //         actually minted is let through. (Quick Connect uses a
        //         different endpoint entirely and is never matched here.)
        //         [v2.5.22] This asks the store (IsKnownBridgeToken) rather than
        //         testing the "oidcbr_" prefix. The prefix test meant any user
        //         could opt out of this server-wide policy simply by choosing a
        //         password that starts with that string.
        //     (b) the configured escape hatches (admin / LAN / exempt CIDRs).
        //     The plugin's own /TwoFactorAuth/Login page is unaffected either way.
        if (config.DisablePasswordLogin
            && !_bridgeTokens.IsKnownBridgeToken(password)
            && !IsPasswordLoginExempt(context, config, user))
        {
            _logger.LogWarning("[2FA] Password sign-in refused (DisablePasswordLogin) for '{User}'.", username ?? "(unknown)");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Password sign-in is disabled on this server. Please sign in with your identity provider.\",\"passwordLoginDisabled\":true}")
                .ConfigureAwait(false);
            return;
        }

        // 1. PRE-CHECK: a locked account is refused BEFORE the password is even
        //    checked, with a recognizable body so inject.js can show a
        //    "temporarily locked" message (Jellyfin strips the provider's
        //    AuthenticationException message in production). IsLockedOutAsync
        //    honours the admin exemption, so an exempt admin is never blocked.
        if (user is not null && await IsLockedSafeAsync(user.Id).ConfigureAwait(false))
        {
            _logger.LogWarning("[2FA] Login refused for locked account '{User}'.", user.Username);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Your account is temporarily locked due to too many failed sign-in attempts. Please try again later.\",\"accountLocked\":true}")
                .ConfigureAwait(false);
            return;
        }

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (MediaBrowser.Controller.Authentication.AuthenticationException)
        {
            // Bad credentials surface as a thrown AuthenticationException here
            // when this middleware sits INSIDE Jellyfin's exception handler
            // (the common ordering). Record the failed attempt, then let it
            // propagate so the normal 401 is produced. We do NOT also run the
            // status-based branch below in this case (we re-throw), so there's
            // no double count.
            if (user is not null)
            {
                try
                {
                    await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[2FA] lockout record (exception path) failed (non-fatal)");
                }
            }

            throw;
        }

        // 2. POST: record the outcome so the per-account lockout actually tracks
        //    PASSWORD attempts. The plugin's IAuthenticationProvider is NOT
        //    invoked for users on Jellyfin's default password provider (only
        //    OIDC/passkey users are routed to it), so this middleware is the
        //    single universal hook for "wrong password -> lockout". This branch
        //    covers pipeline orderings where the auth failure arrives as a 401
        //    status rather than a thrown exception. Admin accounts are exempt
        //    inside RecordFailedAttemptAsync (the counter still increments for
        //    visibility, but LockoutEnd is never set).
        if (user is null)
        {
            return;
        }

        try
        {
            var status = context.Response.StatusCode;
            if (status is >= 200 and < 300)
            {
                await _store.ResetFailedAttemptsAsync(user.Id).ConfigureAwait(false);
            }
            else if (status == StatusCodes.Status401Unauthorized)
            {
                await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] lockout record/reset after login failed (non-fatal)");
        }
    }

    /// <summary>[v2.5.11] (#69) true when password login should still be allowed
    /// for this request despite DisablePasswordLogin — via the admin, LAN, or
    /// explicit-CIDR escape hatches. Fails OPEN (returns true) on any error so a
    /// bug here can never lock everyone out of password sign-in.</summary>
    private bool IsPasswordLoginExempt(HttpContext context, PluginConfiguration config, Jellyfin.Database.Implementations.Entities.User? user)
    {
        try
        {
            // Admin escape hatch (toggleable).
            if (config.AllowAdminPasswordLogin && user is not null
                && user.HasPermission(PermissionKind.IsAdministrator))
            {
                return true;
            }

            var clientIp = BypassEvaluator.ResolveClientIp(context);
            if (string.IsNullOrEmpty(clientIp))
            {
                return false;
            }

            // LAN escape hatch (toggleable) — "disable for remote users only".
            if (config.AllowPasswordLoginOnLan && config.LanBypassCidrs is { Length: > 0 })
            {
                foreach (var cidr in config.LanBypassCidrs)
                {
                    if (BypassEvaluator.IsIpInCidr(clientIp, cidr))
                    {
                        return true;
                    }
                }
            }

            // Explicit exempt CIDRs.
            if (config.PasswordLoginExemptCidrs is { Length: > 0 })
            {
                foreach (var cidr in config.PasswordLoginExemptCidrs)
                {
                    if (BypassEvaluator.IsIpInCidr(clientIp, cidr))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] password-login-exempt check threw; allowing the request");
            return true;
        }
    }

    /// <summary>Jellyfin's obsolete by-id password endpoint:
    /// POST /Users/{userId}/Authenticate?pw=... . Tolerates a configured Jellyfin
    /// BaseUrl prefix, which 10.11.x leaves in Request.Path, and both the dashed
    /// (36-char) and undashed (32-char) GUID forms that Guid.TryParse — and
    /// therefore ASP.NET's :guid route constraint — accept.</summary>
    private static readonly Regex ObsoleteByIdAuthPath = new(
        @"/Users/([0-9a-fA-F-]{32,36})/Authenticate$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    /// <summary>[v2.5.22] True when this request is one of Jellyfin's TWO
    /// password sign-in endpoints. <paramref name="routeUserId"/> comes back as
    /// the route GUID on the obsolete by-id form and Guid.Empty on
    /// AuthenticateByName, which is how the caller knows where to read the
    /// submitted password from.
    ///
    /// SECURITY: matching only AuthenticateByName left a real hole, not a
    /// theoretical one. Jellyfin's UserController still routes
    /// POST /Users/{userId}/Authenticate?pw=..., it carries no [Authorize]
    /// exactly like AuthenticateByName, and it reaches the same authentication
    /// code as an in-process METHOD call — so no path-matching middleware ever
    /// sees a second request. Everything enforced here (DisablePasswordLogin,
    /// BlockEmptyPasswordLogin, and per-account lockout INCLUDING the failure
    /// counter, which for default-provider users has no other hook) was skipped
    /// on it, leaving an unthrottled and unaudited password-guessing path. It is
    /// [ApiExplorerSettings(IgnoreApi = true)] so it never shows up in the
    /// OpenAPI document, and GET /Users/Public hands out the GUIDs it needs
    /// anonymously.
    ///
    /// Quick Connect is deliberately NOT matched: it is not password sign-in and
    /// has to keep working while DisablePasswordLogin is on.</summary>
    internal static bool TryMatchPasswordAuthEndpoint(HttpContext context, out Guid routeUserId)
    {
        routeUserId = Guid.Empty;
        return HttpMethods.IsPost(context.Request.Method)
            && TryMatchPasswordAuthPath(context.Request.Path.Value, out routeUserId);
    }

    /// <summary>Path-only half, split out so the routing contract can be tested
    /// without standing up an HttpContext.</summary>
    internal static bool TryMatchPasswordAuthPath(string? rawPath, out Guid routeUserId)
    {
        routeUserId = Guid.Empty;
        var path = (rawPath ?? string.Empty).TrimEnd('/');
        if (path.EndsWith("/Users/AuthenticateByName", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var match = ObsoleteByIdAuthPath.Match(path);
        return match.Success && Guid.TryParse(match.Groups[1].Value, out routeUserId);
    }

    private async Task<bool> IsLockedSafeAsync(Guid userId)
    {
        try
        {
            return await _store.IsLockedOutAsync(userId).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Fail OPEN — never block a login because the lockout check threw.
            _logger.LogDebug(ex, "[2FA] lockout pre-check threw; passing the request through");
            return false;
        }
    }

    private Jellyfin.Database.Implementations.Entities.User? ResolveUserByIdSafe(Guid userId)
    {
        try
        {
            return _userManager.GetUserById(userId);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] could not resolve attempted login user by id; passing through");
            return null;
        }
    }

    private Jellyfin.Database.Implementations.Entities.User? ResolveUserSafe(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        try
        {
            return _userManager.GetUserByName(username);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] could not resolve attempted login user; passing through");
            return null;
        }
    }

    /// <summary>Read the JSON body's Username + Pw without consuming it for the
    /// downstream pipeline (EnableBuffering + rewind). Returns (null, null) on
    /// any error or an unexpectedly large body — callers treat that as a
    /// pass-through.</summary>
    private static async Task<(string? Username, string? Password)> PeekCredentialsAsync(HttpRequest request)
    {
        try
        {
            // The auth payload is tiny; refuse to buffer anything unexpectedly large.
            if (request.ContentLength is > 8192)
            {
                return (null, null);
            }

            request.EnableBuffering();
            string body;
            using (var reader = new StreamReader(
                request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
            {
                body = await reader.ReadToEndAsync().ConfigureAwait(false);
            }

            request.Body.Position = 0;

            if (string.IsNullOrWhiteSpace(body))
            {
                return (null, null);
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return (null, null);
            }

            return (
                GetString(doc.RootElement, "Username", "username", "Name", "name"),
                GetString(doc.RootElement, "Pw", "Password", "pw", "password"));
        }
        catch
        {
            return (null, null);
        }
    }

    private static string? GetString(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
            {
                return el.GetString();
            }
        }

        return null;
    }
}

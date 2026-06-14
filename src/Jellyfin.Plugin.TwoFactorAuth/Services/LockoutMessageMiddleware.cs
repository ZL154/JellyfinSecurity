using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
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
    private readonly ILogger<LockoutMessageMiddleware> _logger;

    public LockoutMessageMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        IUserManager userManager,
        ILogger<LockoutMessageMiddleware> logger)
    {
        _next = next;
        _store = store;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only instrument the username/password login endpoint. Everything else
        // flows straight through untouched.
        if (!IsAuthenticateByName(context) || Plugin.Instance?.Configuration?.Enabled != true)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Resolve the account being signed in to (best-effort; null = unknown
        // username or unreadable body → behave as a no-op pass-through).
        var user = await ResolveAttemptedUserAsync(context).ConfigureAwait(false);

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

    private static bool IsAuthenticateByName(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            return false;
        }

        var path = (context.Request.Path.Value ?? string.Empty).TrimEnd('/');
        return path.EndsWith("/Users/AuthenticateByName", StringComparison.OrdinalIgnoreCase);
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

    private async Task<Jellyfin.Database.Implementations.Entities.User?> ResolveAttemptedUserAsync(HttpContext context)
    {
        try
        {
            // The auth payload is tiny; refuse to buffer anything unexpectedly large.
            if (context.Request.ContentLength is > 8192)
            {
                return null;
            }

            var username = await PeekUsernameAsync(context.Request).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(username))
            {
                return null;
            }

            return _userManager.GetUserByName(username);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] could not resolve attempted login user; passing through");
            return null;
        }
    }

    /// <summary>Read the JSON body's username without consuming it for the
    /// downstream pipeline (EnableBuffering + rewind).</summary>
    private static async Task<string?> PeekUsernameAsync(HttpRequest request)
    {
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
            return null;
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var name in new[] { "Username", "username", "Name", "name" })
        {
            if (doc.RootElement.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
            {
                return el.GetString();
            }
        }

        return null;
    }
}

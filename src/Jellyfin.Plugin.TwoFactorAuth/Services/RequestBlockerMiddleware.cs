using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Blocks authenticated requests from users who logged in without completing 2FA.
/// Returns 401 so Jellyfin clients fall back to re-authentication.
/// Our own /TwoFactorAuth/* paths are always allowed through so users can reach /Login.
///
/// Since we run before Jellyfin's auth middleware in the pipeline, we invoke
/// authentication manually via context.AuthenticateAsync to get the user claims.
/// </summary>
public class RequestBlockerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ChallengeStore _challengeStore;
    private readonly ILogger<RequestBlockerMiddleware> _logger;

    public RequestBlockerMiddleware(
        RequestDelegate next,
        ChallengeStore challengeStore,
        ILogger<RequestBlockerMiddleware> logger)
    {
        _next = next;
        _challengeStore = challengeStore;
        _logger = logger;
    }

    // Specific endpoints needed for a blocked user to complete 2FA — must NOT be blocked.
    // We deliberately do NOT exempt the entire /TwoFactorAuth/* prefix; admin endpoints
    // under that prefix require admin auth and should also be blocked while mid-2FA.
    private static readonly string[] AlwaysAllowedPaths = new[]
    {
        "/TwoFactorAuth/Login",
        "/TwoFactorAuth/Setup",
        "/TwoFactorAuth/Authenticate",
        "/TwoFactorAuth/Verify",
        "/TwoFactorAuth/Email/Send",
        "/TwoFactorAuth/Challenge",
        "/TwoFactorAuth/inject.js",
        "/TwoFactorAuth/PairConfirm",
    };

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        foreach (var allowed in AlwaysAllowedPaths)
        {
            if (path.Equals(allowed, StringComparison.OrdinalIgnoreCase))
            {
                await _next(context).ConfigureAwait(false);
                return;
            }
        }

        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Only care about requests carrying Jellyfin auth — skip unauthenticated ones
        if (!HasAuthCredentials(context))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Ask Jellyfin's CustomAuthentication handler to resolve claims for this request
        Guid userId = Guid.Empty;
        try
        {
            var authResult = await context.AuthenticateAsync("CustomAuthentication").ConfigureAwait(false);
            if (authResult.Succeeded && authResult.Principal is not null)
            {
                var claim = authResult.Principal.FindFirst("Jellyfin-UserId")
                    ?? authResult.Principal.FindFirst(ClaimTypes.NameIdentifier);
                if (claim is not null)
                {
                    Guid.TryParse(claim.Value, out userId);
                }
            }
        }
        catch
        {
            // Jellyfin auth failed — not our concern, let the real pipeline handle it
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Identify the session by access token (present on every authenticated
        // request) rather than device-id header (absent on most Jellyfin Web
        // requests). Diagnostic run confirmed headerDeviceId=null on every
        // subsequent request after login.
        var token = context.Request.Headers["X-Emby-Token"].FirstOrDefault()
            ?? context.Request.Query["api_key"].FirstOrDefault();

        if (userId != Guid.Empty && !string.IsNullOrEmpty(token) && _challengeStore.IsTokenBlocked(token))
        {
            _logger.LogInformation("[2FA] BLOCKED {Path} user={UserId} (token-scoped) — 2FA not completed",
                path, userId);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Two-factor authentication required. Visit /TwoFactorAuth/Login to complete sign in.\"}"
            ).ConfigureAwait(false);
            return;
        }

        // When a 2FA-verified user approves a Quick Connect code on this device,
        // the INCOMING (TV) session has a different deviceId. Use a single-consume
        // user-scoped flag so the next SessionStarted for this user gets through.
        if (userId != Guid.Empty && path.Contains("/QuickConnect/Authorize", StringComparison.OrdinalIgnoreCase))
        {
            _challengeStore.MarkQuickConnectPending(userId);
            _logger.LogInformation("[2FA] QuickConnect authorize by {UserId} — one-shot allow for incoming session", userId);
        }

        await _next(context).ConfigureAwait(false);
    }

    private static bool HasAuthCredentials(HttpContext ctx)
    {
        var token = ctx.Request.Headers["X-Emby-Token"].FirstOrDefault();
        if (!string.IsNullOrEmpty(token)) return true;

        var apiKeyQ = ctx.Request.Query["api_key"].FirstOrDefault()
            ?? ctx.Request.Query["ApiKey"].FirstOrDefault();
        if (!string.IsNullOrEmpty(apiKeyQ)) return true;

        // X-Emby-Authorization is a metadata header carrying Client=, Device=,
        // DeviceId=, Version= even on UNAUTHENTICATED login attempts. Only
        // count it if it actually contains a token=... segment.
        var embyAuth = ctx.Request.Headers["X-Emby-Authorization"].FirstOrDefault()
            ?? ctx.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(embyAuth)
            && embyAuth.IndexOf("Token=", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return true;
        }

        return false;
    }
}

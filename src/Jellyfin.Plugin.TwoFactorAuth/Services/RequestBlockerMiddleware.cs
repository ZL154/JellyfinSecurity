using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Blocks authenticated requests from users who logged in without completing 2FA.
/// Returns 401 so Jellyfin clients fall back to re-authentication.
/// Our own /TwoFactorAuth/* paths are always allowed through so users can reach /Login.
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

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        // Never block our own plugin paths — user needs these to complete 2FA
        if (path.StartsWith("/TwoFactorAuth", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Only block if the plugin is enabled
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Check if request carries authenticated user claims
        var userIdClaim = context.User?.FindFirst("Jellyfin-UserId")
            ?? context.User?.FindFirst(ClaimTypes.NameIdentifier);
        if (userIdClaim is null || !Guid.TryParse(userIdClaim.Value, out var userId))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (_challengeStore.IsUserBlocked(userId))
        {
            _logger.LogInformation("[2FA] Blocking request to {Path} for 2FA-locked user {UserId}", path, userId);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"message\":\"2FA verification required. Visit /TwoFactorAuth/Login\"}").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }
}

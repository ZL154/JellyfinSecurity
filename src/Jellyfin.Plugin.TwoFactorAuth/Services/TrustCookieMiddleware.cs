using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// On every login-related request, checks for the per-device __2fa_trust cookie.
/// If valid, marks the user as pre-verified so the SessionStarted event handler
/// allows the session through without prompting for 2FA.
/// </summary>
public class TrustCookieMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly CookieSigner _cookieSigner;
    private readonly ILogger<TrustCookieMiddleware> _logger;

    public TrustCookieMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        CookieSigner cookieSigner,
        ILogger<TrustCookieMiddleware> logger)
    {
        _next = next;
        _store = store;
        _challengeStore = challengeStore;
        _cookieSigner = cookieSigner;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var isAuthPath = path.EndsWith("/AuthenticateByName", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/AuthenticateWithQuickConnect", StringComparison.OrdinalIgnoreCase)
            // QuickConnect approval: user authenticates the request on a 2FA-verified device,
            // so we honor the trust cookie to mark the user pre-verified for the new session.
            || path.Contains("/QuickConnect/Authorize", StringComparison.OrdinalIgnoreCase);

        if (!isAuthPath)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var cookie = context.Request.Cookies["__2fa_trust"];
        if (string.IsNullOrEmpty(cookie))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        try
        {
            var parts = cookie.Split('.');
            if (parts.Length != 3 || !Guid.TryParse(parts[0], out var userId))
            {
                await _next(context).ConfigureAwait(false);
                return;
            }

            if (!_cookieSigner.Verify($"{parts[0]}.{parts[1]}", parts[2]))
            {
                _logger.LogInformation("[2FA] Trust cookie signature mismatch for {UserId} — ignoring", userId);
                await _next(context).ConfigureAwait(false);
                return;
            }

            var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
            var trustRecord = userData.TrustedDevices.FirstOrDefault(t => t.Id == parts[1]);
            if (trustRecord is null)
            {
                _logger.LogInformation("[2FA] Trust cookie references revoked record {Id}", parts[1]);
                await _next(context).ConfigureAwait(false);
                return;
            }

            if (trustRecord.CreatedAt < DateTime.UtcNow.AddDays(-30))
            {
                _logger.LogInformation("[2FA] Trust cookie expired (>30 days) for {UserId}", userId);
                await _next(context).ConfigureAwait(false);
                return;
            }

            _logger.LogInformation("[2FA] Valid trust cookie for {UserId} — pre-verifying session", userId);
            _challengeStore.MarkUserPreVerified(userId);
            _challengeStore.UnblockUser(userId);

            trustRecord.LastUsedAt = DateTime.UtcNow;
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Trust cookie validation failed");
        }

        await _next(context).ConfigureAwait(false);
    }
}

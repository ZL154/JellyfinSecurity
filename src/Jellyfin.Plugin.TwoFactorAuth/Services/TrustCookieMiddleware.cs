using System.Security.Cryptography;
using System.Text;
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
    private static readonly byte[] SigningKey = Encoding.UTF8.GetBytes("TwoFactorAuth.CookieSign.v1");

    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly ILogger<TrustCookieMiddleware> _logger;

    public TrustCookieMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        ILogger<TrustCookieMiddleware> logger)
    {
        _next = next;
        _store = store;
        _challengeStore = challengeStore;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Cheap path filter — only do work for login-related requests
        var path = context.Request.Path.Value ?? string.Empty;
        var isAuthPath = path.EndsWith("/AuthenticateByName", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/AuthenticateWithQuickConnect", StringComparison.OrdinalIgnoreCase);

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
            if (parts.Length != 3) { await _next(context).ConfigureAwait(false); return; }

            if (!Guid.TryParse(parts[0], out var userId))
            {
                await _next(context).ConfigureAwait(false);
                return;
            }

            // Verify HMAC signature
            var payload = $"{parts[0]}.{parts[1]}";
            var expected = ComputeHmac(payload);
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(parts[2]),
                Encoding.UTF8.GetBytes(expected)))
            {
                _logger.LogInformation("[2FA] Trust cookie signature mismatch for {UserId}", userId);
                await _next(context).ConfigureAwait(false);
                return;
            }

            // Verify the trust record still exists in user data and is recent
            var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
            var trustRecord = userData.TrustedDevices.FirstOrDefault(t => t.Id == parts[1]);
            if (trustRecord is null)
            {
                _logger.LogInformation("[2FA] Trust cookie for revoked record — not honoring");
                await _next(context).ConfigureAwait(false);
                return;
            }

            if (trustRecord.CreatedAt < DateTime.UtcNow.AddDays(-30))
            {
                _logger.LogInformation("[2FA] Trust cookie expired (>30 days)");
                await _next(context).ConfigureAwait(false);
                return;
            }

            _logger.LogInformation("[2FA] Valid trust cookie for {UserId} — pre-verifying session", userId);
            _challengeStore.MarkUserPreVerified(userId);
            _challengeStore.UnblockUser(userId);

            // Bump LastUsedAt
            trustRecord.LastUsedAt = DateTime.UtcNow;
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Trust cookie validation failed");
        }

        await _next(context).ConfigureAwait(false);
    }

    private static string ComputeHmac(string value)
    {
        using var hmac = new HMACSHA256(SigningKey);
        var bytes = Encoding.UTF8.GetBytes(value);
        return Convert.ToBase64String(hmac.ComputeHash(bytes))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}

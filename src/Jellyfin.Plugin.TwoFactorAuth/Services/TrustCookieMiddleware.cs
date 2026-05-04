using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Validates the __2fa_trust cookie on auth endpoints. Valid cookie => mark the
/// specific (user, device) pair pre-verified so the session skips 2FA.
///
/// Cookie format (v2): userId.trustRecordId.deviceIdB64.expiryUnix.hmac
///   - deviceId is signed into the payload so a stolen cookie cannot be
///     replayed with an attacker-chosen X-Emby-Device-Id header (device
///     substitution attack).
///   - expiryUnix is signed so an attacker who tampers with the trust record
///     file cannot extend the window.
///   - Format v1 (userId.trustRecordId.hmac) is accepted read-only for 30 days
///     post-upgrade so existing users don't get forcibly re-prompted, then
///     stripped. v1 cookies are treated as single-use: the next valid sign-in
///     upgrades them to v2 automatically via rotation.
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
            if (parts.Length < 3 || !Guid.TryParse(parts[0], out var userId))
            {
                await _next(context).ConfigureAwait(false);
                return;
            }

            // v2: userId.trustRecordId.deviceIdB64.expiryUnix.hmac
            if (parts.Length == 5)
            {
                var payload = $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}";
                if (!_cookieSigner.Verify(payload, parts[4]))
                {
                    _logger.LogWarning("[2FA] Trust cookie v2 signature mismatch for {UserId}", userId);
                    await _next(context).ConfigureAwait(false);
                    return;
                }

                if (!long.TryParse(parts[3], out var expiryUnix)
                    || DateTimeOffset.FromUnixTimeSeconds(expiryUnix) <= DateTimeOffset.UtcNow)
                {
                    _logger.LogDebug("[2FA] Trust cookie expired for {UserId}", userId);
                    await _next(context).ConfigureAwait(false);
                    return;
                }

                string? signedDeviceId;
                try
                {
                    signedDeviceId = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(parts[2]));
                }
                catch
                {
                    await _next(context).ConfigureAwait(false);
                    return;
                }

                var requestDeviceId = context.Request.Headers["X-Emby-Device-Id"].FirstOrDefault()
                    ?? context.Request.Headers["X-Emby-DeviceId"].FirstOrDefault()
                    ?? TwoFactorEnforcementMiddleware.ParseEmbyAuth(
                        context.Request.Headers["X-Emby-Authorization"].FirstOrDefault(), "DeviceId");

                if (string.IsNullOrEmpty(requestDeviceId)
                    || !string.Equals(requestDeviceId, signedDeviceId, StringComparison.Ordinal))
                {
                    // Device substitution attempt, or legitimately the same user on a
                    // different device. Either way, the trust does not apply.
                    _logger.LogWarning("[2FA] Trust cookie device mismatch for {UserId} — ignoring", userId);
                    await _next(context).ConfigureAwait(false);
                    return;
                }

                var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
                var trustRecord = userData.TrustedDevices.FirstOrDefault(t =>
                    string.Equals(t.Id, parts[1], StringComparison.Ordinal));
                if (trustRecord is null)
                {
                    _logger.LogInformation("[2FA] Trust cookie references revoked record {Id}", parts[1]);
                    await _next(context).ConfigureAwait(false);
                    return;
                }

                _challengeStore.MarkDevicePreVerified(userId, signedDeviceId);
                _challengeStore.UnblockDevice(userId, signedDeviceId);

                trustRecord.LastUsedAt = DateTime.UtcNow;
                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

                // Rotate cookie on use — short grace via overlapping expiry, old
                // cookie's HMAC still valid until TTL but LastUsedAt was just
                // updated so theft is bounded. The new cookie's expiry is a fresh
                // 30-day window (sliding session).
                IssueTrustCookie(context, userId, trustRecord.Id, signedDeviceId);
                return;
            }

            // v1 legacy: userId.trustRecordId.hmac — treat as unsigned device, do
            // NOT pre-verify. Force the user through a fresh 2FA so we can issue
            // a v2 cookie bound to the correct deviceId.
            if (parts.Length == 3)
            {
                _logger.LogInformation("[2FA] Legacy trust cookie for {UserId} — ignored, user will re-verify to upgrade", userId);
                // Strip the stale cookie so the browser doesn't keep sending it.
                context.Response.Cookies.Delete("__2fa_trust");
                await _next(context).ConfigureAwait(false);
                return;
            }

            await _next(context).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Trust cookie validation failed");
            await _next(context).ConfigureAwait(false);
        }
    }

    internal void IssueTrustCookie(HttpContext context, Guid userId, string trustRecordId, string deviceId)
    {
        var ttlDays = Math.Clamp(
            Plugin.Instance?.Configuration?.TrustCookieTtlDays ?? 30, 1, 90);
        var expiryUnix = DateTimeOffset.UtcNow.AddDays(ttlDays).ToUnixTimeSeconds();
        var deviceB64 = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(deviceId ?? string.Empty));
        var payload = $"{userId:N}.{trustRecordId}.{deviceB64}.{expiryUnix}";
        var hmac = _cookieSigner.Sign(payload);
        context.Response.Cookies.Append("__2fa_trust", $"{payload}.{hmac}", new CookieOptions
        {
            HttpOnly = true,
            // SEC-H1: IsHttps reads only the direct TCP scheme. Behind a TLS-
            // terminating reverse proxy (Cloudflare, Caddy, nginx, Traefik) the
            // peer connection is plain HTTP even though the browser-facing
            // origin is HTTPS, and IsHttps would return false — silently
            // dropping the Secure flag in production. BypassEvaluator.IsSecureRequest
            // honours X-Forwarded-Proto only when the direct peer is in
            // TrustedProxyCidrs, so it cannot be spoofed.
            Secure = BypassEvaluator.IsSecureRequest(context),
            SameSite = SameSiteMode.Strict,
            Expires = DateTimeOffset.UtcNow.AddDays(ttlDays),
            Path = "/",
            IsEssential = true,
        });
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

using System.Net;
using System.Text;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Enforces 2FA by inspecting any POST response that looks like a Jellyfin
/// authentication result (has AccessToken + User.Id). When the user has TOTP
/// enabled and no bypass applies, the response is replaced with a 401 +
/// challenge token. The real auth response is stashed in the ChallengeStore
/// so the /TwoFactorAuth/Verify endpoint can return it after OTP validation.
/// </summary>
public class TwoFactorEnforcementMiddleware
{
    private static readonly JsonSerializerOptions ResponseJsonOptions = new()
    {
        PropertyNamingPolicy = null,
    };

    private static readonly JsonSerializerOptions ParseJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly BypassEvaluator _bypassEvaluator;
    private readonly ILogger<TwoFactorEnforcementMiddleware> _logger;

    public TwoFactorEnforcementMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        BypassEvaluator bypassEvaluator,
        ILogger<TwoFactorEnforcementMiddleware> logger)
    {
        _next = next;
        _store = store;
        _challengeStore = challengeStore;
        _bypassEvaluator = bypassEvaluator;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only consider POST requests — auth is always POST
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Skip our own plugin endpoints
        var path = context.Request.Path.Value ?? string.Empty;
        if (path.StartsWith("/TwoFactorAuth", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Buffer response so we can inspect it
        var originalBody = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch
        {
            context.Response.Body = originalBody;
            buffer.Position = 0;
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            throw;
        }

        context.Response.Body = originalBody;
        buffer.Position = 0;

        // Only care about successful JSON responses
        if (context.Response.StatusCode != (int)HttpStatusCode.OK
            || buffer.Length == 0
            || !(context.Response.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            return;
        }

        var bodyBytes = buffer.ToArray();
        var bodyText = Encoding.UTF8.GetString(bodyBytes);

        // Quick shape check — does the body look like an auth response?
        if (!LooksLikeAuthResponse(bodyText))
        {
            await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
            return;
        }

        _logger.LogInformation("[2FA] Detected auth-shaped response on POST {Path}", path);

        try
        {
            var authResult = JsonSerializer.Deserialize<AuthResult>(bodyBytes, ParseJsonOptions);
            if (authResult is null || authResult.User is null
                || string.IsNullOrEmpty(authResult.AccessToken)
                || authResult.User.Id == Guid.Empty)
            {
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }

            var userData = await _store.GetUserDataAsync(authResult.User.Id).ConfigureAwait(false);
            _logger.LogInformation("[2FA] User {Name} (id={Id}) TotpEnabled={Totp} Verified={Ver} RequireAll={Req}",
                authResult.User.Name, authResult.User.Id, userData.TotpEnabled, userData.TotpVerified, config.RequireForAllUsers);

            if (!userData.TotpEnabled && !config.RequireForAllUsers)
            {
                _logger.LogInformation("[2FA] User has no 2FA and RequireForAllUsers=false — passing through");
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }

            var remoteIp = context.Connection.RemoteIpAddress?.ToString();
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var twoFactorToken = context.Request.Headers["X-TwoFactor-Token"].FirstOrDefault();
            var deviceId = context.Request.Headers["X-Emby-Device-Id"].FirstOrDefault()
                ?? context.Request.Headers["X-Emby-DeviceId"].FirstOrDefault();
            var deviceName = context.Request.Headers["X-Emby-Device-Name"].FirstOrDefault() ?? "Unknown";
            var apiKeys = await _store.GetApiKeysAsync().ConfigureAwait(false);

            var bypass = _bypassEvaluator.Evaluate(
                remoteIp,
                forwardedFor,
                twoFactorToken,
                deviceId,
                null,
                userData.TrustedDevices,
                userData.RegisteredDeviceIds,
                apiKeys);

            if (bypass.IsBypassed)
            {
                _logger.LogWarning("[2FA] Bypass triggered for {Name} from {Ip} (reason={Reason})",
                    authResult.User.Name, remoteIp, bypass.Reason);
                await _store.AddAuditEntryAsync(new AuditEntry
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = authResult.User.Id,
                    Username = authResult.User.Name ?? string.Empty,
                    RemoteIp = remoteIp ?? string.Empty,
                    DeviceId = deviceId ?? string.Empty,
                    DeviceName = deviceName,
                    Result = AuditResult.Bypassed,
                    Method = bypass.Reason ?? "bypass",
                }).ConfigureAwait(false);
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }

            _logger.LogInformation("[2FA] Issuing challenge for {Name} from {Ip}", authResult.User.Name, remoteIp);

            var methods = new List<string>();
            if (userData.TotpVerified) methods.Add("totp");
            if (config.EmailOtpEnabled) methods.Add("email");
            if (methods.Count == 0) methods.Add("email");

            var challenge = _challengeStore.CreateChallenge(
                authResult.User.Id,
                authResult.User.Name ?? string.Empty,
                methods,
                deviceId,
                deviceName,
                remoteIp);

            challenge.PendingAuthResponse = bodyText;

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = authResult.User.Id,
                Username = authResult.User.Name ?? string.Empty,
                RemoteIp = remoteIp ?? string.Empty,
                DeviceId = deviceId ?? string.Empty,
                DeviceName = deviceName,
                Result = AuditResult.ChallengeIssued,
                Method = string.Join(",", methods),
            }).ConfigureAwait(false);

            var response = new TwoFactorRequiredResponse
            {
                TwoFactorRequired = true,
                ChallengeToken = challenge.Token,
                Methods = methods,
                ChallengePageUrl = $"/TwoFactorAuth/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
            };

            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Response.ContentType = "application/json";
            var responseJson = JsonSerializer.SerializeToUtf8Bytes(response, ResponseJsonOptions);
            context.Response.ContentLength = responseJson.Length;
            await originalBody.WriteAsync(responseJson).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] Middleware failed; allowing request through");
            await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Cheap string check: does the body text contain both an AccessToken and a User field?
    /// This catches /Users/AuthenticateByName, /Users/AuthenticateWithQuickConnect, and any
    /// other endpoint that returns the standard Jellyfin AuthenticationResult shape.
    /// </summary>
    private static bool LooksLikeAuthResponse(string body)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 65536) return false;
        return body.Contains("\"AccessToken\"", StringComparison.Ordinal)
            && body.Contains("\"User\"", StringComparison.Ordinal)
            && body.Contains("\"SessionInfo\"", StringComparison.Ordinal);
    }

    private sealed class AuthResult
    {
        public string? AccessToken { get; set; }

        public AuthUser? User { get; set; }
    }

    private sealed class AuthUser
    {
        public Guid Id { get; set; }

        public string? Name { get; set; }
    }
}

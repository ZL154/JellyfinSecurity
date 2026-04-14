using System.Net;
using System.Text;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class TwoFactorEnforcementMiddleware
{
    private const string AuthPath = "/Users/AuthenticateByName";

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
        // Diagnostic: log EVERY POST request so we can find the auth endpoint
        if (HttpMethods.IsPost(context.Request.Method))
        {
            _logger.LogInformation("[2FA-DIAG] POST {Path}", context.Request.Path.Value ?? "(empty)");
        }

        if (!IsAuthRequest(context))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        _logger.LogInformation("[2FA] Intercepted auth request from {Ip} (XFF: {Xff})",
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            context.Request.Headers["X-Forwarded-For"].FirstOrDefault() ?? "(none)");

        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled)
        {
            _logger.LogInformation("[2FA] Plugin disabled in config — passing through");
            await _next(context).ConfigureAwait(false);
            return;
        }

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

        if (context.Response.StatusCode != (int)HttpStatusCode.OK)
        {
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            return;
        }

        try
        {
            var bodyBytes = buffer.ToArray();
            var authResult = ParseAuthResult(bodyBytes);
            if (authResult is null || authResult.User is null || string.IsNullOrEmpty(authResult.AccessToken))
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
                _logger.LogWarning("[2FA] Bypass triggered for {Name} from {Ip} (reason={Reason}) — login allowed without 2FA",
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

            _logger.LogInformation("[2FA] Issuing challenge for {Name} from {Ip} (methods={Methods})",
                authResult.User.Name, remoteIp, string.Join(",", new[] { userData.TotpVerified ? "totp" : null, config.EmailOtpEnabled ? "email" : null }.Where(s => s != null)));

            var methods = new List<string>();
            if (userData.TotpVerified)
            {
                methods.Add("totp");
            }

            if (config.EmailOtpEnabled)
            {
                methods.Add("email");
            }

            if (methods.Count == 0)
            {
                methods.Add("email");
            }

            var challenge = _challengeStore.CreateChallenge(
                authResult.User.Id,
                authResult.User.Name ?? string.Empty,
                methods,
                deviceId,
                deviceName,
                remoteIp);

            challenge.PendingAuthResponse = Encoding.UTF8.GetString(bodyBytes);

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
            _logger.LogError(ex, "2FA enforcement middleware failed; allowing request through");
            buffer.Position = 0;
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
        }
    }

    private static bool IsAuthRequest(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            return false;
        }

        var path = context.Request.Path.Value;
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        // Match /Users/AuthenticateByName with optional /api prefix, case-insensitive
        return path.EndsWith("/Users/AuthenticateByName", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/Users/authenticate", StringComparison.OrdinalIgnoreCase);
    }

    private static AuthResult? ParseAuthResult(byte[] body)
    {
        try
        {
            return JsonSerializer.Deserialize<AuthResult>(body, ParseJsonOptions);
        }
        catch
        {
            return null;
        }
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

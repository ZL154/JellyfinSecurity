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
    private readonly AppPasswordService _appPasswordService;
    private readonly PendingPairingService _pendingPairings;
    private readonly RateLimiter _rateLimiter;
    private readonly ILogger<TwoFactorEnforcementMiddleware> _logger;

    public TwoFactorEnforcementMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        BypassEvaluator bypassEvaluator,
        AppPasswordService appPasswordService,
        PendingPairingService pendingPairings,
        RateLimiter rateLimiter,
        ILogger<TwoFactorEnforcementMiddleware> logger)
    {
        _next = next;
        _store = store;
        _challengeStore = challengeStore;
        _bypassEvaluator = bypassEvaluator;
        _appPasswordService = appPasswordService;
        _pendingPairings = pendingPairings;
        _rateLimiter = rateLimiter;
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

        // Buffer the REQUEST body so we can re-read the submitted password later
        // (only matters for AuthenticateByName-style endpoints; harmless elsewhere).
        // EnableBuffering lets ASP.NET re-read the body downstream after we peek.
        // Handles both Content-Length and chunked-encoded bodies up to 64KB.
        string? submittedPassword = null;
        var isJsonPost = context.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) ?? false;
        var knownLength = context.Request.ContentLength;
        var sizeFeasible = knownLength is null || (knownLength > 0 && knownLength < 65536);
        if (isJsonPost && sizeFeasible)
        {
            context.Request.EnableBuffering(bufferThreshold: 65536);
            try
            {
                var buf = new byte[65536];
                var totalRead = 0;
                int read;
                while (totalRead < buf.Length
                    && (read = await context.Request.Body.ReadAsync(buf, totalRead, buf.Length - totalRead).ConfigureAwait(false)) > 0)
                {
                    totalRead += read;
                }
                context.Request.Body.Position = 0;

                if (totalRead > 0 && totalRead < buf.Length)
                {
                    using var doc = JsonDocument.Parse(buf.AsMemory(0, totalRead));
                    if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        if (doc.RootElement.TryGetProperty("Pw", out var pw) && pw.ValueKind == JsonValueKind.String)
                            submittedPassword = pw.GetString();
                        else if (doc.RootElement.TryGetProperty("pw", out var pwLc) && pwLc.ValueKind == JsonValueKind.String)
                            submittedPassword = pwLc.GetString();
                        else if (doc.RootElement.TryGetProperty("Password", out var p) && p.ValueKind == JsonValueKind.String)
                            submittedPassword = p.GetString();
                        else if (doc.RootElement.TryGetProperty("password", out var pLc) && pLc.ValueKind == JsonValueKind.String)
                            submittedPassword = pLc.GetString();
                    }
                }
            }
            catch
            {
                // Bad/non-JSON/oversized body — ignore, proceed without password extraction.
                try { context.Request.Body.Position = 0; } catch { /* best effort */ }
            }
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

            // Paired-device bypass: TV/native client whose DeviceId the user
            // already approved (via QR pairing OR by approving a pending request).
            if (!string.IsNullOrEmpty(deviceId))
            {
                var paired = userData.PairedDevices.FirstOrDefault(p =>
                    string.Equals(p.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
                if (paired is not null)
                {
                    // Atomic update of LastUsedAt to avoid lost-update vs. concurrent
                    // Setup-page edits adding/revoking devices for the same user.
                    var capturedRemoteIp = remoteIp ?? string.Empty;
                    var capturedDeviceId = deviceId;
                    await _store.MutateAsync(authResult.User.Id, ud =>
                    {
                        var p = ud.PairedDevices.FirstOrDefault(x =>
                            string.Equals(x.DeviceId, capturedDeviceId, StringComparison.OrdinalIgnoreCase));
                        if (p is not null)
                        {
                            p.LastUsedAt = DateTime.UtcNow;
                            p.LastIp = capturedRemoteIp;
                        }
                    }).ConfigureAwait(false);
                    await _store.AddAuditEntryAsync(new AuditEntry
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = authResult.User.Id,
                        Username = authResult.User.Name ?? string.Empty,
                        RemoteIp = remoteIp ?? string.Empty,
                        DeviceId = deviceId,
                        DeviceName = deviceName,
                        Result = AuditResult.Bypassed,
                        Method = "paired_device",
                    }).ConfigureAwait(false);
                    _logger.LogInformation("[2FA] Paired device match for {Name} (device={Device}) — bypassing 2FA",
                        authResult.User.Name, paired.DeviceName);
                    await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                    return;
                }
            }

            // App-password bypass: user submitted a generated app password instead
            // of (or as) the regular password. We verify against PBKDF2 hashes.
            // Rate-limited to prevent brute force through the Jellyfin auth endpoint.
            if (!string.IsNullOrEmpty(submittedPassword) && userData.AppPasswords.Count > 0)
            {
                var apIp = remoteIp ?? "unknown";
                var apRl = _rateLimiter.CheckAndRecord("mw_ap:" + apIp, 10, TimeSpan.FromMinutes(1));
                Models.AppPassword? matchedAp = null;
                if (apRl.allowed)
                {
                    matchedAp = _appPasswordService.FindMatch(submittedPassword, userData.AppPasswords);
                }
                if (matchedAp is not null)
                {
                    var matchedId = matchedAp.Id;
                    var capturedDeviceIdAp = deviceId ?? string.Empty;
                    var capturedDeviceNameAp = deviceName;
                    await _store.MutateAsync(authResult.User.Id, ud =>
                    {
                        var ap = ud.AppPasswords.FirstOrDefault(x => x.Id == matchedId);
                        if (ap is not null)
                        {
                            ap.LastUsedAt = DateTime.UtcNow;
                            ap.LastDeviceId = capturedDeviceIdAp;
                            ap.LastDeviceName = capturedDeviceNameAp;
                        }
                    }).ConfigureAwait(false);
                    await _store.AddAuditEntryAsync(new AuditEntry
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = authResult.User.Id,
                        Username = authResult.User.Name ?? string.Empty,
                        RemoteIp = remoteIp ?? string.Empty,
                        DeviceId = deviceId ?? string.Empty,
                        DeviceName = deviceName,
                        Result = AuditResult.Bypassed,
                        Method = "app_password:" + matchedAp.Label,
                    }).ConfigureAwait(false);
                    _logger.LogInformation("[2FA] App password '{Label}' matched for {Name} — bypassing 2FA",
                        matchedAp.Label, authResult.User.Name);
                    await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                    return;
                }
            }

            // No bypass path matched. Record this attempt as a pending pairing
            // so the user can approve the device from their Setup page.
            if (!string.IsNullOrEmpty(deviceId))
            {
                var appName = context.Request.Headers["X-Emby-Client"].FirstOrDefault()
                    ?? ParseClientFromAuthHeader(context.Request.Headers["X-Emby-Authorization"].FirstOrDefault())
                    ?? "Unknown";
                _pendingPairings.Record(authResult.User.Id, deviceId, deviceName, appName, remoteIp ?? string.Empty);
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
            _logger.LogError(ex, "[2FA] Middleware failed on auth-shaped response; failing closed (503)");
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.ContentType = "application/json";
            await originalBody.WriteAsync(
                Encoding.UTF8.GetBytes("{\"message\":\"2FA service error. Contact your administrator.\"}")).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Match by both path AND response shape to avoid false positives.
    /// Path: known Jellyfin auth endpoints. Shape: AccessToken + User + SessionInfo present.
    /// No size cap on the path check; size cap on body parse only as a sanity bound.
    /// </summary>
    private static bool LooksLikeAuthResponse(string body)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 1_000_000) return false;
        return body.Contains("\"AccessToken\"", StringComparison.Ordinal)
            && body.Contains("\"User\"", StringComparison.Ordinal)
            && body.Contains("\"SessionInfo\"", StringComparison.Ordinal);
    }

    private static string? ParseClientFromAuthHeader(string? header)
    {
        if (string.IsNullOrEmpty(header)) return null;
        var idx = header.IndexOf("Client=", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var rest = header.Substring(idx + "Client=".Length).TrimStart('"');
        var end = rest.IndexOfAny(new[] { ',', '"' });
        return end > 0 ? rest.Substring(0, end) : rest;
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

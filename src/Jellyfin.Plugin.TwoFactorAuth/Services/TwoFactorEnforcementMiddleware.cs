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

        // Restrict activation to actual Jellyfin auth endpoints AND to responses
        // that structurally look like auth results. Prevents false positives on
        // admin APIs that return lists of users/sessions.
        if (!IsAuthPath(path) || !LooksLikeAuthResponse(bodyText))
        {
            await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
            return;
        }

        _logger.LogDebug("[2FA] Detected auth-shaped response on POST {Path}", path);

        try
        {
            var authResult = JsonSerializer.Deserialize<AuthResult>(bodyBytes, ParseJsonOptions);
            var userGuid = authResult?.User?.IdGuid ?? Guid.Empty;
            if (authResult is null || authResult.User is null
                || string.IsNullOrEmpty(authResult.AccessToken)
                || userGuid == Guid.Empty)
            {
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }

            var userData = await _store.GetUserDataAsync(userGuid).ConfigureAwait(false);
            _logger.LogDebug("[2FA] User {Name} (id={Id}) TotpEnabled={Totp} Verified={Ver} RequireAll={Req}",
                authResult.User.Name, userGuid, userData.TotpEnabled, userData.TotpVerified, config.RequireForAllUsers);

            if (!userData.TotpEnabled && !config.RequireForAllUsers)
            {
                _logger.LogDebug("[2FA] User has no 2FA and RequireForAllUsers=false — passing through");
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }

            var remoteIp = context.Connection.RemoteIpAddress?.ToString();
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var twoFactorToken = context.Request.Headers["X-TwoFactor-Token"].FirstOrDefault();
            // Jellyfin web/Tizen clients don't always send X-Emby-Device-Id
            // as a dedicated header — they pack it inside X-Emby-Authorization
            // as `DeviceId="..."`. Without parsing that we fail to match the
            // paired-device list for those clients, and they get challenged
            // despite having been approved (this bit Samsung TV specifically).
            var authHeader = context.Request.Headers["X-Emby-Authorization"].FirstOrDefault();
            var deviceId = context.Request.Headers["X-Emby-Device-Id"].FirstOrDefault()
                ?? context.Request.Headers["X-Emby-DeviceId"].FirstOrDefault()
                ?? ParseEmbyAuth(authHeader, "DeviceId");
            var deviceName = context.Request.Headers["X-Emby-Device-Name"].FirstOrDefault()
                ?? ParseEmbyAuth(authHeader, "Device")
                ?? "Unknown";

            // Samsung Tizen Jellyfin Web over Cloudflare+Caddy doesn't reliably
            // send X-Emby-Device-Id OR a parseable X-Emby-Authorization — so
            // deviceId comes up null and we can't check paired/registered
            // bypasses. Fallback: Jellyfin's auth RESPONSE body (which we
            // already parsed into authResult) contains SessionInfo.DeviceId,
            // which is the authoritative value Jellyfin assigned this session.
            if (string.IsNullOrEmpty(deviceId))
            {
                try
                {
                    using var authDoc = JsonDocument.Parse(bodyBytes);
                    if (authDoc.RootElement.TryGetProperty("SessionInfo", out var si))
                    {
                        if (si.TryGetProperty("DeviceId", out var did) && did.ValueKind == JsonValueKind.String)
                        {
                            deviceId = did.GetString();
                        }
                        if (string.Equals(deviceName, "Unknown", StringComparison.Ordinal)
                            && si.TryGetProperty("DeviceName", out var dn) && dn.ValueKind == JsonValueKind.String)
                        {
                            deviceName = dn.GetString() ?? "Unknown";
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[2FA] Could not fallback-parse SessionInfo.DeviceId from auth body");
                }
            }

            // SessionStarted handler runs on a parallel code path that sees the
            // authoritative SessionInfo.DeviceId — for clients that don't send
            // X-Emby-Authorization (Samsung Tizen), it's the only path that can
            // match a paired device. If it already decided to allow this token,
            // don't overwrite the response with a challenge. Since the two
            // paths race on the same request, briefly poll for the approval
            // flag (~500ms total) before deciding to challenge. Single-consume
            // so a stale approval can't be reused on a subsequent request.
            // PERF-P2: WaitForApprovalAsync replaces the 50ms × 10-tick polling
            // loop. The previous loop forced every successful login to pay
            // 50–500ms of artificial latency. Now we register a TaskCompletionSource
            // that ApproveToken signals immediately on completion. Cap at 500ms
            // for fail-safety (matches the previous worst case).
            var approved = await _challengeStore
                .WaitForApprovalAsync(authResult.AccessToken, userGuid, deviceId, TimeSpan.FromMilliseconds(500))
                .ConfigureAwait(false);
            if (approved)
            {
                _logger.LogDebug("[2FA] Token pre-approved by event handler — passing auth response through for {Name}",
                    authResult.User.Name);
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }
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
                    UserId = userGuid,
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
            // DeviceIdMatches normalises UA-hash deviceIds so Tizen webview
            // pairings survive app restarts.
            if (!string.IsNullOrWhiteSpace(deviceId))
            {
                var paired = userData.PairedDevices.FirstOrDefault(p =>
                    BypassEvaluator.DeviceIdMatches(p.DeviceId, deviceId));
                if (paired is not null)
                {
                    // Atomic update of LastUsedAt to avoid lost-update vs. concurrent
                    // Setup-page edits adding/revoking devices for the same user.
                    var capturedRemoteIp = remoteIp ?? string.Empty;
                    var capturedDeviceId = deviceId;
                    await _store.MutateAsync(userGuid, ud =>
                    {
                        var p = ud.PairedDevices.FirstOrDefault(x =>
                            BypassEvaluator.DeviceIdMatches(x.DeviceId, capturedDeviceId));
                        if (p is not null)
                        {
                            p.LastUsedAt = DateTime.UtcNow;
                            p.LastIp = capturedRemoteIp;
                        }
                    }).ConfigureAwait(false);
                    await _store.AddAuditEntryAsync(new AuditEntry
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = userGuid,
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
                var apIp = RateLimiter.ClientKey(context);
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
                    await _store.MutateAsync(userGuid, ud =>
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
                        UserId = userGuid,
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
                _pendingPairings.Record(userGuid, deviceId, deviceName, appName, remoteIp ?? string.Empty);
            }

            _logger.LogInformation("[2FA] Issuing challenge for {Name} from {Ip}", authResult.User.Name, remoteIp);

            var methods = new List<string>();
            // v1.4: emergency lockout sets ForceRecoveryOnNextLogin to true.
            // Strip TOTP and passkey from the available methods until the user
            // consumes a recovery code OR an email OTP — that's the contract
            // the user-facing button promises ("recovery code required to sign
            // in"). The flag is cleared in the controller's Verify path on
            // successful recovery.
            if (userData.ForceRecoveryOnNextLogin)
            {
                methods.Add("recovery");
                if (config.EmailOtpEnabled) methods.Add("email");
            }
            else
            {
                if (userData.TotpVerified) methods.Add("totp");
                if (userData.Passkeys.Count > 0) methods.Add("passkey");
                if (config.EmailOtpEnabled) methods.Add("email");
            }
            if (methods.Count == 0) methods.Add("email");

            var challenge = _challengeStore.CreateChallenge(
                userGuid,
                authResult.User.Name ?? string.Empty,
                methods,
                deviceId,
                deviceName,
                remoteIp);

            challenge.PendingAuthResponse = bodyText;

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = userGuid,
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
    /// Match by both path AND response shape to avoid false positives — any other
    /// 200 JSON response that happens to contain the substrings would otherwise
    /// get routed into the 2FA challenge flow.
    /// </summary>
    private static bool IsAuthPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        // Anchor match to the path ROOT — previously used `Contains` which
        // matched any nested path segment containing /Users/AuthenticateByName
        // (e.g. a third-party plugin's /Plugins/X/PassThrough/Users/AuthenticateByName
        // would trigger challenge injection on an unrelated response).
        return System.Text.RegularExpressions.Regex.IsMatch(
            path,
            @"^/Users/(AuthenticateByName|AuthenticateWithQuickConnect|[0-9a-fA-F-]{32,36}/Authenticate)(\?|/|$)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    private static bool LooksLikeAuthResponse(string body)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 1_000_000) return false;
        return body.Contains("\"AccessToken\"", StringComparison.Ordinal)
            && body.Contains("\"User\"", StringComparison.Ordinal)
            && body.Contains("\"SessionInfo\"", StringComparison.Ordinal);
    }

    private static string? ParseClientFromAuthHeader(string? header)
        => ParseEmbyAuth(header, "Client");

    /// <summary>Parse a key (Client, Device, DeviceId, Version, Token) from the
    /// X-Emby-Authorization header. Format: `MediaBrowser Client="Foo",
    /// Device="Bar", DeviceId="abc", Version="1.0", Token="..."`.</summary>
    internal static string? ParseEmbyAuth(string? header, string key)
    {
        if (string.IsNullOrEmpty(header) || string.IsNullOrEmpty(key)) return null;
        var needle = key + "=";
        var idx = header.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        // Make sure we matched a word boundary — ", Client=" not "XClient=".
        if (idx > 0)
        {
            var prev = header[idx - 1];
            if (prev != ',' && prev != ' ') return null;
        }
        var rest = header.Substring(idx + needle.Length);
        if (rest.StartsWith("\"", StringComparison.Ordinal))
        {
            // Quoted: read until the next unescaped quote
            var end = rest.IndexOf('"', 1);
            return end > 0 ? rest.Substring(1, end - 1) : null;
        }
        // Unquoted: read until comma or end
        var comma = rest.IndexOf(',');
        return (comma > 0 ? rest.Substring(0, comma) : rest).Trim();
    }

    private sealed class AuthResult
    {
        public string? AccessToken { get; set; }

        public AuthUser? User { get; set; }
    }

    private sealed class AuthUser
    {
        // Jellyfin serializes user Ids as 32-char hex (no dashes). System.Text.Json
        // won't coerce that into Guid, so we keep it as a string and parse on demand.
        public string? Id { get; set; }

        public string? Name { get; set; }

        public Guid IdGuid => Guid.TryParseExact(Id, "N", out var g)
            ? g
            : (Guid.TryParse(Id, out var d) ? d : Guid.Empty);
    }
}

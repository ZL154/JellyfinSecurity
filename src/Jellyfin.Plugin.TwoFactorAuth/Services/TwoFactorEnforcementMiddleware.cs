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
    private readonly IpBanService _ipBans;
    private readonly IpAllowlistService _allowlist;
    private readonly HibpService _hibp;
    private readonly ILogger<TwoFactorEnforcementMiddleware> _logger;

    public TwoFactorEnforcementMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        BypassEvaluator bypassEvaluator,
        AppPasswordService appPasswordService,
        PendingPairingService pendingPairings,
        RateLimiter rateLimiter,
        IpBanService ipBans,
        IpAllowlistService allowlist,
        HibpService hibp,
        ILogger<TwoFactorEnforcementMiddleware> logger)
    {
        _next = next;
        _store = store;
        _challengeStore = challengeStore;
        _bypassEvaluator = bypassEvaluator;
        _appPasswordService = appPasswordService;
        _pendingPairings = pendingPairings;
        _rateLimiter = rateLimiter;
        _ipBans = ipBans;
        _allowlist = allowlist;
        _hibp = hibp;
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

        // SEC v2.4 M3: gate the 64KB request body allocation on path match
        // BEFORE doing it. Previously this allocation happened on every JSON
        // POST regardless of path, which meant any plugin admin endpoint or
        // Library/Scan-style call paid the cost AND was a memory-amplification
        // DoS vector. IsAuthPath was already authoritative downstream; just
        // hoisting it up.
        if (!IsAuthPath(path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Issue #35 phase-3 (v2.4.10.1): override Accept-Encoding to "identity"
        // for auth-path requests so any downstream response-compression
        // middleware (Jellyfin's own gzip, ASP.NET's ResponseCompression,
        // etc.) skips this response. Our middleware reads the response body
        // via a buffered MemoryStream after _next() returns; if that body
        // arrives gzip-encoded, all substring checks and JSON deserialization
        // fail silently (binary noise contains no "AccessToken" /
        // "accessToken" / "access_token", and Deserialize<AuthResult> throws).
        // FsxShader2012's v2.4.10 logs showed all three substring flags
        // False even with OrdinalIgnoreCase matching — gzip is the leading
        // hypothesis. Forcing identity encoding for the request makes the
        // response uncompressed regardless of upstream client preference.
        // Cost: auth response goes ~600 bytes gzipped → ~2000 bytes plain.
        // Negligible. Scoped to auth paths only.
        context.Request.Headers["Accept-Encoding"] = "identity";

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
                    && (read = await context.Request.Body.ReadAsync(buf.AsMemory(totalRead, buf.Length - totalRead)).ConfigureAwait(false)) > 0)
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
            // Issue #35 diagnostic: surface the skip reason so bug reports
            // immediately show why the intercept didn't fire on an auth path.
            // Debug level — happens on legitimate non-200 auth failures too
            // (wrong password) and we don't want to spam Info logs.
            _logger.LogDebug(
                "[2FA] Auth path {Path} but skipping response intercept (status={Status} bodyLen={Len} contentType={CT})",
                path, context.Response.StatusCode, buffer.Length, context.Response.ContentType);
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            return;
        }

        var bodyBytes = buffer.ToArray();
        var bodyText = Encoding.UTF8.GetString(bodyBytes);

        // Path is already pre-validated at the top (SEC v2.4 M3). Only check
        // response shape here — prevents false positives on third-party admin
        // APIs that happen to return JSON bodies containing the literal
        // substrings.
        if (!LooksLikeAuthResponse(bodyText))
        {
            // Issue #35 diagnostic: this is the gate most likely to silently
            // miss when Jellyfin's auth response shape varies (other plugins
            // mutating it, chunked transfer caught mid-stream, schema drift).
            // Log at Information so it surfaces without needing Debug — but
            // only the substring-presence flags, NEVER the body itself (the
            // body contains AccessToken + user PII).
            // v2.4.10.1: expanded diagnostic for issue #35 — v2.4.10's
            // case-insensitive substring match didn't resolve FsxShader2012's
            // case (all three flags still False even with OrdinalIgnoreCase).
            // We now also log:
            //   * first 8 bytes as hex — identifies gzip (1f 8b), zlib (78 9c),
            //     brotli, HTML (3c 21 = "<!"), plain JSON (7b = "{"), or any
            //     binary marker the substring scan can't see through
            //   * Content-Encoding response header — direct evidence of
            //     gzip / br / deflate compression
            //   * First 100 chars of body as plain text — for a Jellyfin
            //     auth response, AccessToken is typically further into the
            //     JSON than the first 100 chars, so this reveals shape
            //     ({"User":{... vs {"data":{... vs <html>...) without
            //     leaking credentials. If the body is binary (gzipped),
            //     the chars render as control-character noise which is
            //     itself the diagnostic signal.
            // Also switched the substring checks to OrdinalIgnoreCase
            // (matching LooksLikeAuthResponse) so the log accurately
            // reports what the gate ACTUALLY checked — previously the log
            // used strict Ordinal which made "Has AccessToken: False"
            // ambiguous (could have been a casing mismatch).
            var firstBytes = bodyBytes.Length >= 8 ? bodyBytes[..8] : bodyBytes;
            var firstBytesHex = Convert.ToHexString(firstBytes);
            var previewLen = Math.Min(bodyText.Length, 100);
            var preview = bodyText[..previewLen]
                .Replace('\n', ' ')
                .Replace('\r', ' ');
            var contentEncoding = context.Response.Headers["Content-Encoding"].ToString();
            _logger.LogInformation(
                "[2FA] Auth path {Path} matched but response body didn't look like a Jellyfin auth response — pass-through. " +
                "Body length: {Len}. Has \"AccessToken\" (case-insensitive): {HasAT}. Has \"User\": {HasU}. Has \"SessionInfo\": {HasSI}. " +
                "Content-Encoding: '{Enc}'. Content-Type: '{CT}'. First 8 bytes (hex): {Hex}. First 100 chars: '{Preview}'. " +
                "If a 2FA-enabled user is stuck on login, see issue #35.",
                path,
                bodyText.Length,
                bodyText.Contains("\"AccessToken\"", StringComparison.OrdinalIgnoreCase),
                bodyText.Contains("\"User\"", StringComparison.OrdinalIgnoreCase),
                bodyText.Contains("\"SessionInfo\"", StringComparison.OrdinalIgnoreCase),
                string.IsNullOrEmpty(contentEncoding) ? "(none)" : contentEncoding,
                context.Response.ContentType ?? "(none)",
                firstBytesHex,
                preview);
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

            // v2.4: HIBP password-breach check. Opt-in (config.HibpEnabled).
            // Fire-and-forget so we don't block the auth response on an
            // external API call. The check is advisory only — on a hit we
            // log + write an audit entry so the admin can act on it. We
            // never block the user's login on HIBP because the password
            // was already validated by Jellyfin core; preventing sign-in
            // here would be a worse UX than telling them to rotate.
            if (config.HibpEnabled && !string.IsNullOrEmpty(submittedPassword))
            {
                var pwForHibp = submittedPassword;
                var hibpUsername = authResult.User.Name ?? string.Empty;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var count = await _hibp.CheckPasswordAsync(pwForHibp).ConfigureAwait(false);
                        if (count > 0)
                        {
                            _logger.LogWarning(
                                "[HIBP] User {Name} signed in with a password seen in {Count} known breaches",
                                hibpUsername, count);
                            try
                            {
                                await _store.AddAuditEntryAsync(new AuditEntry
                                {
                                    Timestamp = DateTime.UtcNow,
                                    UserId = userGuid,
                                    Username = hibpUsername,
                                    RemoteIp = string.Empty,
                                    DeviceId = string.Empty,
                                    DeviceName = string.Empty,
                                    Result = AuditResult.ConfigChanged,
                                    Method = "hibp_breach:" + count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                                }).ConfigureAwait(false);
                            }
                            catch (Exception auditEx)
                            {
                                _logger.LogDebug(auditEx, "[HIBP] failed to write audit entry");
                            }
                        }
                    }
                    catch (Exception hibpEx)
                    {
                        _logger.LogDebug(hibpEx, "[HIBP] background check failed (fail open)");
                    }
                });
            }

            var remoteIp = BypassEvaluator.ResolveClientIp(context) ?? context.Connection.RemoteIpAddress?.ToString();
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(remoteIp) && _ipBans.CheckBanned(remoteIp) is { } ban)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "application/json";
                var bannedJson = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    message = "This IP address is temporarily blocked.",
                    expiresAt = ban.ExpiresAt,
                }, ResponseJsonOptions);
                context.Response.ContentLength = bannedJson.Length;
                await originalBody.WriteAsync(bannedJson).ConfigureAwait(false);
                return;
            }

            if (!await _allowlist.IsAllowedAsync(userGuid, remoteIp).ConfigureAwait(false))
            {
                _ipBans.RecordFailure(remoteIp ?? string.Empty);
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "application/json";
                var refusedJson = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    message = "Sign-in is not allowed from this network.",
                }, ResponseJsonOptions);
                context.Response.ContentLength = refusedJson.Length;
                await originalBody.WriteAsync(refusedJson).ConfigureAwait(false);
                return;
            }

            // v2.4: honor EnforcementScope (Optional / Admins / All) instead
            // of the all-or-nothing RequireForAllUsers flag. ShouldEnforceFor
            // returns true when the policy says this specific user must have
            // 2FA enabled. The legacy RequireForAllUsers flag is honored
            // inside ShouldEnforceFor for backwards compat.
            //
            // v2.4.1: gate on TotpEnabled && TotpVerified, not TotpEnabled
            // alone. A user who clicked Begin Setup and navigated away has
            // TotpEnabled=true with no verified secret — treating that as
            // "has 2FA" lets the next sign-in fall through into a method
            // list that omits "totp" (TotpVerified is false), leaving the
            // user with an email-only challenge they may have no way to
            // satisfy. Rescues any pre-existing half-enrolled rows from
            // v2.4.0 too: they now pass through to no-2FA if policy allows.
            var isAdmin = authResult.User.Policy?.IsAdministrator ?? false;
            var hasRealTwoFactor = (userData.TotpEnabled && userData.TotpVerified)
                || userData.Passkeys.Count > 0;
            if (!hasRealTwoFactor && !config.ShouldEnforceFor(isAdmin))
            {
                _logger.LogDebug(
                    "[2FA] User {Name} has no 2FA and policy scope ({Scope}) does not require it — passing through",
                    authResult.User.Name, config.EnforcementScope);
                _ipBans.RecordSuccess(remoteIp ?? string.Empty);
                await originalBody.WriteAsync(bodyBytes).ConfigureAwait(false);
                return;
            }

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
                _ipBans.RecordSuccess(remoteIp ?? string.Empty);
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
                _ipBans.RecordSuccess(remoteIp ?? string.Empty);
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
                    _ipBans.RecordSuccess(remoteIp ?? string.Empty);
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
                        // SEC v2.4 L5: sanitize the user-supplied label so it
                        // can't poison the audit log Method field (e.g. a
                        // malicious admin labeling a password "paired_device"
                        // to disguise an app-password bypass as a paired
                        // device match).
                        Method = "app_password:" + SanitizeLabel(matchedAp.Label),
                    }).ConfigureAwait(false);
                    _logger.LogInformation("[2FA] App password '{Label}' matched for {Name} — bypassing 2FA",
                        matchedAp.Label, authResult.User.Name);
                    _ipBans.RecordSuccess(remoteIp ?? string.Empty);
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

            // v2.4: ShouldEnforceFor honors both the new EnforcementScope
            // (Optional / Admins / All) and the legacy RequireForAllUsers
            // flag. isAdmin was extracted from authResult.User.Policy above.
            var enrollmentRequired = config.ShouldEnforceFor(isAdmin)
                && !userData.TotpVerified
                && userData.Passkeys.Count == 0;
            var methods = new List<string>();
            // v1.4: emergency lockout sets ForceRecoveryOnNextLogin to true.
            // Strip TOTP and passkey from the available methods until the user
            // consumes a recovery code OR an email OTP — that's the contract
            // the user-facing button promises ("recovery code required to sign
            // in"). The flag is cleared in the controller's Verify path on
            // successful recovery.
            if (enrollmentRequired)
            {
                methods.Add("enroll");
            }
            else if (userData.ForceRecoveryOnNextLogin)
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
                remoteIp,
                enrollmentRequired);

            challenge.PendingAuthResponse = bodyText;
            _challengeStore.BlockToken(authResult.AccessToken);

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
                EnrollmentRequired = enrollmentRequired,
                ChallengePageUrl = $"/TwoFactorAuth/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
                EnrollmentPageUrl = $"/TwoFactorAuth/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
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
            @"(?:^|/+)Users/(AuthenticateByName|AuthenticateWithQuickConnect|[0-9a-fA-F-]{32,36}/Authenticate)(\?|/|$)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    /// <summary>SEC v2.4 L5: sanitize a user-supplied label before it's
    /// concatenated into the audit log Method field. Strips colons (the
    /// Method-delimiter), strips ASCII control chars, caps length so a
    /// malicious admin can't pad the field with bogus content.</summary>
    private static string SanitizeLabel(string? label)
    {
        if (string.IsNullOrEmpty(label)) return string.Empty;
        var sb = new System.Text.StringBuilder(Math.Min(label.Length, 32));
        foreach (var c in label)
        {
            if (sb.Length >= 32) break;
            if (c < 0x20 || c == 0x7F) continue; // control chars
            if (c == ':') continue;              // method delimiter
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Quick substring-based sniff to decide whether a response body looks
    /// like a Jellyfin auth result. Returns true if all three signature keys
    /// (AccessToken, User, SessionInfo) appear, case-insensitively.
    ///
    /// SEC v2.4 L6: require all three substrings so third-party plugin admin
    /// responses that happen to mention AccessToken and User in a different
    /// shape don't get pulled into the 2FA flow.
    ///
    /// v2.4.10 (issue #35): comparison is OrdinalIgnoreCase to match
    /// downstream JsonSerializer.Deserialize which uses
    /// PropertyNameCaseInsensitive=true. The PascalCase-only check missed
    /// camelCase responses (a reverse-proxy or response-wrapping middleware
    /// in some users' pipelines rewrites the Jellyfin auth result with
    /// camelCase keys). Case-insensitive matching covers both stock Jellyfin
    /// PascalCase and the wrapped/rewritten camelCase variant without
    /// loosening the three-key requirement.
    /// </summary>
    internal static bool LooksLikeAuthResponse(string body)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 1_000_000) return false;
        return body.Contains("\"AccessToken\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"User\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"SessionInfo\"", StringComparison.OrdinalIgnoreCase);
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

        // v2.4: parsed so the middleware can honor EnforcementScope.Admins
        // without a separate UserManager round-trip. Jellyfin's auth response
        // body includes the full Policy object.
        public AuthUserPolicy? Policy { get; set; }

        public Guid IdGuid => Guid.TryParseExact(Id, "N", out var g)
            ? g
            : (Guid.TryParse(Id, out var d) ? d : Guid.Empty);
    }

    private sealed class AuthUserPolicy
    {
        public bool IsAdministrator { get; set; }
    }
}

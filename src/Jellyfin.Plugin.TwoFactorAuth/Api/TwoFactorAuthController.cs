using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Data.Queries;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Api;

[ApiController]
[Route("TwoFactorAuth")]
[Produces(MediaTypeNames.Application.Json)]
public class TwoFactorAuthController : ControllerBase
{
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly TotpService _totpService;
    private readonly EmailOtpService _emailOtpService;
    private readonly DeviceTokenService _deviceTokenService;
    private readonly DevicePairingService _devicePairingService;
    private readonly NotificationService _notificationService;
    private readonly ISessionManager _sessionManager;
    private readonly IUserManager _userManager;
    private readonly CookieSigner _cookieSigner;
    private readonly RateLimiter _rateLimiter;
    private readonly RecoveryCodeService _recoveryCodes;
    private readonly AppPasswordService _appPasswords;
    private readonly PendingPairingService _pendingPairings;
    private readonly IDeviceManager _deviceManager;
    private readonly SessionTerminationService _sessionTerm;
    private readonly PasskeyService _passkeys;
    private readonly PasskeyChallengeStore _passkeyChallenges;
    private readonly DiagnosticsService _diagnostics;
    private readonly StatsService _stats;
    private readonly UserExportService _userExport;
    private readonly RecoveryCodePdfService _recoveryPdf;
    private readonly ILogger<TwoFactorAuthController> _logger;

    public TwoFactorAuthController(
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        TotpService totpService,
        EmailOtpService emailOtpService,
        DeviceTokenService deviceTokenService,
        DevicePairingService devicePairingService,
        NotificationService notificationService,
        ISessionManager sessionManager,
        IUserManager userManager,
        CookieSigner cookieSigner,
        RateLimiter rateLimiter,
        RecoveryCodeService recoveryCodes,
        AppPasswordService appPasswords,
        PendingPairingService pendingPairings,
        IDeviceManager deviceManager,
        SessionTerminationService sessionTerm,
        PasskeyService passkeys,
        PasskeyChallengeStore passkeyChallenges,
        DiagnosticsService diagnostics,
        StatsService stats,
        UserExportService userExport,
        RecoveryCodePdfService recoveryPdf,
        ILogger<TwoFactorAuthController> logger)
    {
        _store = store;
        _challengeStore = challengeStore;
        _totpService = totpService;
        _emailOtpService = emailOtpService;
        _deviceTokenService = deviceTokenService;
        _devicePairingService = devicePairingService;
        _notificationService = notificationService;
        _sessionManager = sessionManager;
        _userManager = userManager;
        _cookieSigner = cookieSigner;
        _rateLimiter = rateLimiter;
        _recoveryCodes = recoveryCodes;
        _appPasswords = appPasswords;
        _pendingPairings = pendingPairings;
        _deviceManager = deviceManager;
        _sessionTerm = sessionTerm;
        _passkeys = passkeys;
        _passkeyChallenges = passkeyChallenges;
        _diagnostics = diagnostics;
        _stats = stats;
        _userExport = userExport;
        _recoveryPdf = recoveryPdf;
        _logger = logger;
    }

    // -------------------------------------------------------------------------
    // Helper: get current authenticated user ID from JWT claims
    // -------------------------------------------------------------------------

    private Guid GetCurrentUserId()
    {
        var claim = User.FindFirst("Jellyfin-UserId");
        if (claim != null && Guid.TryParse(claim.Value, out var userId))
        {
            return userId;
        }

        throw new UnauthorizedAccessException();
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/Challenge — serves the standalone challenge HTML page
    // -------------------------------------------------------------------------

    [HttpGet("Challenge")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetChallengePage()
    {
        return ServeEmbeddedPage("challenge.html");
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/Setup — user-facing enrollment page
    // -------------------------------------------------------------------------

    [HttpGet("Setup")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetSetupPage()
    {
        return ServeEmbeddedPage("setup.html");
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/Login — dedicated 2FA-aware login page
    // -------------------------------------------------------------------------

    [HttpGet("Login")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetLoginPage()
    {
        return ServeEmbeddedPage("login.html");
    }

    // -------------------------------------------------------------------------
    // POST /TwoFactorAuth/Authenticate — username + password + TOTP code in one call
    // -------------------------------------------------------------------------

    [HttpPost("Authenticate")]
    [AllowAnonymous]
    public async Task<IActionResult> AuthenticateWithCode([FromBody] LoginWithCodeRequest req)
    {
        try
        {
            // Per-IP rate limit: 10 attempts per minute. Prevents online brute-force on
            // the OTP code space and on the username/password combo.
            var ip = RateLimiter.ClientKey(HttpContext);
            var rl = _rateLimiter.CheckAndRecord("auth:" + ip, 10, TimeSpan.FromMinutes(1));
            if (!rl.allowed)
            {
                Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString());
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
                    retryAfterSeconds = rl.retryAfterSeconds,
                });
            }

            if (req is null || string.IsNullOrEmpty(req.Username) || string.IsNullOrEmpty(req.Password))
            {
                return BadRequest(new { message = "Username and password are required." });
            }

            // SEC-L8: cap submitted credential field lengths. Jellyfin's auth
            // path runs PBKDF2 internally; an unbounded body lets an attacker
            // burn server CPU per request. 1KB password / 256B username covers
            // realistic upper bounds (long passphrases ~200 chars) while
            // killing the DoS vector.
            if (req.Password.Length > 1024
                || req.Username.Length > 256
                || (req.Code is not null && req.Code.Length > 64))
            {
                return BadRequest(new { message = "Field too long." });
            }

            _logger.LogInformation("[2FA] /Authenticate username={Name} codeProvided={Has}",
                req.Username, !string.IsNullOrEmpty(req.Code));

            var user = _userManager.GetUserByName(req.Username);
            if (user is null)
            {
                return Unauthorized(new { message = "Invalid username or password." });
            }

            var userData = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);

            if (await _store.IsLockedOutAsync(user.Id).ConfigureAwait(false))
            {
                var remaining = userData.LockoutEnd.HasValue
                    ? Math.Max(0, (int)(userData.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds)
                    : 900;
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = "Account is locked out due to too many failed attempts.",
                    lockoutRemainingSeconds = remaining,
                });
            }

            var totpEnabled = userData.TotpEnabled && userData.TotpVerified;
            var codeConsumedRecoveryIndex = -1;

            // --- Step 1: If user has 2FA, verify TOTP/recovery code FIRST ---
            // We return identical "invalid credentials" messages whether the password is wrong,
            // the code is missing, or the code is wrong — preventing account enumeration of
            // which users have 2FA enabled.
            if (totpEnabled)
            {
                if (string.IsNullOrEmpty(req.Code))
                {
                    await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                    return Unauthorized(new { message = "Invalid username, password, or verification code." });
                }

                bool codeValid = false;
                string? usedMethod = null;

                // Check if it's a recovery code (longer than 6 chars; allow optional dashes)
                var maybeRecovery = req.Code.Replace("-", "").Replace(" ", "");
                if (maybeRecovery.Length >= 8 && maybeRecovery.All(c => char.IsLetterOrDigit(c)))
                {
                    codeConsumedRecoveryIndex = FindRecoveryCodeIndex(userData, req.Code);
                    if (codeConsumedRecoveryIndex >= 0)
                    {
                        // Mark used IMMEDIATELY so a stolen recovery code can't be retried.
                        // We persist this even if password verification fails afterwards.
                        userData.RecoveryCodes[codeConsumedRecoveryIndex].Used = true;
                        userData.RecoveryCodes[codeConsumedRecoveryIndex].UsedAt = DateTime.UtcNow;
                        // v1.4: clear the "force recovery on next login" flag set
                        // by emergency lockout — the user has now demonstrated
                        // possession of a recovery code, restoring their normal
                        // 2FA methods on subsequent sign-ins.
                        userData.ForceRecoveryOnNextLogin = false;
                        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
                        codeValid = true;
                        usedMethod = "recovery";
                    }
                }

                // Else try TOTP
                if (!codeValid && req.Code.Length == 6 && req.Code.All(char.IsDigit))
                {
                    if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
                    {
                        return Unauthorized(new { message = "TOTP is enabled but no secret is configured. Please re-enroll." });
                    }

                    string secret;
                    try
                    {
                        // SEC-M3: pass userId for AAD-bound v2 ciphertexts.
                        // Auto-migrate any legacy v1 (no-AAD) record to v2 on
                        // first successful read — the rewrite happens lazily
                        // and is idempotent (already-v2 inputs are returned
                        // unchanged by MigrateToV2).
                        if (userData.EncryptedTotpSecret is { Length: > 0 } enc
                            && !enc.StartsWith("v2:", StringComparison.Ordinal))
                        {
                            var upgraded = _totpService.MigrateToV2(enc, user.Id);
                            if (!string.Equals(upgraded, enc, StringComparison.Ordinal))
                            {
                                userData.EncryptedTotpSecret = upgraded;
                                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
                            }
                        }
                        secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret!, user.Id);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[2FA] Failed to decrypt TOTP secret for {Name}", req.Username);
                        return StatusCode(500, new { message = "Failed to decrypt TOTP secret. Please re-enroll 2FA." });
                    }

                    // SEC-M4: pass persisted replay floor + capture accepted step.
                    if (_totpService.ValidateCode(secret, req.Code, user.Id.ToString(),
                        userData.LastUsedTotpStep, out var acceptedStep))
                    {
                        codeValid = true;
                        usedMethod = "totp";
                        userData.LastUsedTotpStep = acceptedStep;
                        // Persist the floor immediately — even if the password
                        // verification below fails, the replay floor advance
                        // is correct (the code was valid, an attacker who
                        // intercepted it cannot replay anyway).
                        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
                    }
                }

                if (!codeValid)
                {
                    await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                    await _store.AddAuditEntryAsync(new AuditEntry
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = user.Id,
                        Username = user.Username ?? string.Empty,
                        RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
                        Result = AuditResult.Failed,
                        Method = "totp",
                    }).ConfigureAwait(false);
                    // Generic message to avoid enumeration
                    return Unauthorized(new { message = "Invalid username, password, or verification code." });
                }

                _logger.LogInformation("[2FA] {Name} 2FA code accepted ({Method})", req.Username, usedMethod);
            }

            // --- Step 2: Verify password with Jellyfin. If this fails, don't touch any state. ---
            var deviceId = HttpContext.Request.Headers["X-Emby-Device-Id"].FirstOrDefault()
                ?? Guid.NewGuid().ToString("N");
            var deviceName = HttpContext.Request.Headers["X-Emby-Device-Name"].FirstOrDefault()
                ?? "Browser";

            var authRequest = new MediaBrowser.Controller.Session.AuthenticationRequest
            {
                Username = req.Username,
                Password = req.Password,
                App = "Jellyfin Web",
                AppVersion = "1.0.0",
                DeviceId = deviceId,
                DeviceName = deviceName,
                RemoteEndPoint = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            };

            // Pre-verify must be set BEFORE AuthenticateNewSession because SessionStarted
            // fires during that call. Scoped to (user, device) so sibling devices can't
            // piggy-back on the 2-minute window and bypass 2FA silently.
            _challengeStore.MarkDevicePreVerified(user.Id, deviceId);

            MediaBrowser.Controller.Authentication.AuthenticationResult result;
            var authSucceeded = false;
            try
            {
                try
                {
                    result = await _sessionManager.AuthenticateNewSession(authRequest).ConfigureAwait(false);
                    authSucceeded = true;
                }
                catch (MediaBrowser.Controller.Authentication.AuthenticationException)
                {
                    return Unauthorized(new { message = "Invalid username or password." });
                }
            }
            finally
            {
                if (!authSucceeded)
                {
                    _challengeStore.ConsumeDevicePreVerified(user.Id, deviceId);
                }
            }

            // --- Step 3: Auth succeeded. Now do the state mutations (trust record, audit, etc.) ---
            _challengeStore.UnblockAllForUser(user.Id);
            await _store.ResetFailedAttemptsAsync(user.Id).ConfigureAwait(false);
            _rateLimiter.Reset("auth:" + ip);

            // Only create a trust cookie/record if the user actually completed 2FA.
            // Users without 2FA don't need a trust cookie — there's nothing to trust.
            if (totpEnabled)
            {
                var (_, trustRecord) = _deviceTokenService.CreateDeviceToken(deviceId, deviceName);
                // Reload userData since we may have saved earlier (recovery code used) before SessionStarted ran
                userData = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);
                userData.TrustedDevices.Add(trustRecord);
                // SEC-L1: cap trusted-device list. Authenticated users would
                // otherwise grow this list unbounded by repeatedly opting
                // "Trust this device". Cap at 30 (~6× typical browser count)
                // and FIFO-evict the oldest by LastUsedAt when over.
                EnforceTrustedDeviceCap(userData);
                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

                // v2 cookie: deviceId and expiry are signed into the payload so
                // (a) a stolen cookie can't be replayed with an attacker-chosen
                // X-Emby-Device-Id header and (b) an attacker who tampers with
                // the trust record file can't extend the window. TTL is admin-
                // configurable in v1.4 (default 30 days, range 1-90).
                var ttlDays = Math.Clamp(
                    Plugin.Instance?.Configuration?.TrustCookieTtlDays ?? 30, 1, 90);
                var expiryUnix = DateTimeOffset.UtcNow.AddDays(ttlDays).ToUnixTimeSeconds();
                var deviceB64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(deviceId ?? string.Empty))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                var cookieValue = $"{user.Id:N}.{trustRecord.Id}.{deviceB64}.{expiryUnix}";
                var hmac = _cookieSigner.Sign(cookieValue);
                Response.Cookies.Append("__2fa_trust", $"{cookieValue}.{hmac}", new CookieOptions
                {
                    HttpOnly = true,
                    // SEC-H1: see TrustCookieMiddleware.IssueTrustCookie. IsHttps
                    // reads only the direct TCP scheme — behind a TLS-terminating
                    // reverse proxy the Secure flag would silently drop. Use the
                    // proxy-aware resolver instead. Browsers still reject Secure
                    // on plain-HTTP localhost; the resolver returns false there
                    // unchanged.
                    Secure = BypassEvaluator.IsSecureRequest(HttpContext),
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(ttlDays),
                    Path = "/",
                    IsEssential = true,
                });
            }

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = user.Id,
                Username = user.Username ?? string.Empty,
                RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
                DeviceId = deviceId,
                DeviceName = deviceName,
                Result = AuditResult.Success,
                Method = totpEnabled ? (codeConsumedRecoveryIndex >= 0 ? "recovery" : "totp") : "password_only",
            }).ConfigureAwait(false);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] /Authenticate unhandled exception");
            return StatusCode(500, new { message = "Internal server error. Check Jellyfin logs for [2FA] entries." });
        }
    }

    private static int FindRecoveryCodeIndex(UserTwoFactorData userData, string submitted)
    {
        var normalized = RecoveryCodeService.NormalizeForCompare(submitted);
        // Iterate in constant time relative to the user's code count — don't
        // early-return on match so timing can't reveal which index matched.
        int found = -1;
        for (int i = 0; i < userData.RecoveryCodes.Count; i++)
        {
            var stored = userData.RecoveryCodes[i];
            if (stored.Used) continue;
            if (RecoveryCodeService.Verify(normalized, stored.Hash) && found < 0)
            {
                found = i;
            }
        }
        return found;
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/inject.js — script injected into Jellyfin web UI
    // -------------------------------------------------------------------------

    [HttpGet("inject.js")]
    [AllowAnonymous]
    public IActionResult GetInjectScript()
    {
        var assembly = typeof(Plugin).Assembly;
        var resourceName = $"{typeof(Plugin).Namespace}.Pages.inject.js";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return NotFound();
        }

        using var reader = new System.IO.StreamReader(stream);
        var js = reader.ReadToEnd();
        // inject.js changes with every plugin upgrade — a CDN / reverse proxy
        // caching it for 24h means users don't see new login buttons, bug fixes,
        // or security hardening until the cache expires. Tell every intermediate
        // to revalidate on each request.
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        Response.Headers.Pragma = "no-cache";
        Response.Headers.Expires = "0";
        return Content(js, "application/javascript; charset=utf-8");
    }

    private IActionResult ServeEmbeddedPage(string filename)
    {
        var assembly = typeof(Plugin).Assembly;
        var resourceName = $"{typeof(Plugin).Namespace}.Pages.{filename}";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return NotFound();
        }

        using var reader = new System.IO.StreamReader(stream);
        var html = reader.ReadToEnd();

        // Anti-framing: /Setup reveals recovery codes and QR secret on screen;
        // /Challenge has a "Trust this device" click target. Both are prime
        // clickjacking targets. frame-ancestors 'none' is the modern equivalent
        // of X-Frame-Options: DENY; include both for browser coverage.
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Content-Security-Policy"] = "frame-ancestors 'none'";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Content(html, "text/html; charset=utf-8");
    }

    // -------------------------------------------------------------------------
    // 1. POST /TwoFactorAuth/Verify [AllowAnonymous]
    // -------------------------------------------------------------------------

    [HttpPost("Verify")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(VerifyResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<VerifyResponse>> Verify([FromBody, Required] VerifyRequest request)
    {
        // Per-IP rate limit on Verify (prevents brute force across multiple challenges)
        var ip = RateLimiter.ClientKey(HttpContext);
        var rl = _rateLimiter.CheckAndRecord("verify:" + ip, 10, TimeSpan.FromMinutes(1));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString());
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
                retryAfterSeconds = rl.retryAfterSeconds,
            });
        }

        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null)
        {
            return BadRequest(new { message = "Invalid or expired challenge." });
        }

        // Per-user rate limit on Verify — defense in depth against an attacker
        // using an IP rotator to sidestep the per-IP bucket. 15 attempts per 15
        // minutes matches the per-challenge 5-limit * typical churn without
        // locking out a flaky-connection legitimate user.
        var userRl = _rateLimiter.CheckAndRecord("verify_user:" + challenge.UserId.ToString("N"), 15, TimeSpan.FromMinutes(15));
        if (!userRl.allowed)
        {
            Response.Headers.Append("Retry-After", userRl.retryAfterSeconds.ToString());
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts for this account. Try again in {userRl.retryAfterSeconds} seconds.",
                retryAfterSeconds = userRl.retryAfterSeconds,
            });
        }

        // Per-challenge attempt limit — burns the challenge after 5 failed guesses
        if (challenge.AttemptCount >= 5)
        {
            _challengeStore.ConsumeChallenge(request.ChallengeToken);
            return Unauthorized(new { message = "Too many failed attempts on this challenge. Restart sign-in." });
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Account is locked out." });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        bool valid;
        int consumedRecoveryIdx = -1;

        // v1.4: ForceRecoveryOnNextLogin (set by emergency lockout) limits the
        // user to recovery / email until they consume one of those — block any
        // other method for this challenge.
        var lockedToRecovery = userData.ForceRecoveryOnNextLogin;
        if (lockedToRecovery
            && !string.Equals(request.Method, "email", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(request.Method, "recovery", StringComparison.OrdinalIgnoreCase))
        {
            return Unauthorized(new { message = "Account is in recovery mode — use a recovery code or email OTP." });
        }

        if (string.Equals(request.Method, "email", StringComparison.OrdinalIgnoreCase))
        {
            valid = _emailOtpService.ValidateCode(request.ChallengeToken, request.Code);
        }
        else if (string.Equals(request.Method, "recovery", StringComparison.OrdinalIgnoreCase))
        {
            consumedRecoveryIdx = FindRecoveryCodeIndex(userData, request.Code);
            valid = consumedRecoveryIdx >= 0;
            if (valid)
            {
                userData.RecoveryCodes[consumedRecoveryIdx].Used = true;
                userData.RecoveryCodes[consumedRecoveryIdx].UsedAt = DateTime.UtcNow;
            }
        }
        else
        {
            if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
            {
                challenge.AttemptCount++;
                await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
                return Unauthorized(new { message = "No TOTP secret configured." });
            }

            string secret;
            // SEC-M3: lazy v1->v2 migration on first decrypt, then decrypt.
            try
            {
                if (userData.EncryptedTotpSecret is { Length: > 0 } enc
                    && !enc.StartsWith("v2:", StringComparison.Ordinal))
                {
                    var upgraded = _totpService.MigrateToV2(enc, challenge.UserId);
                    if (!string.Equals(upgraded, enc, StringComparison.Ordinal))
                    {
                        userData.EncryptedTotpSecret = upgraded;
                        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
                    }
                }
                secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret!, challenge.UserId);
            }
            catch { return StatusCode(500, new { message = "TOTP secret is corrupted. Re-enroll 2FA." }); }
            // SEC-M4: enforce persisted replay floor across restarts.
            long acceptedTotpStep;
            valid = _totpService.ValidateCode(secret, request.Code, challenge.UserId.ToString(),
                userData.LastUsedTotpStep, out acceptedTotpStep);
            if (valid)
            {
                userData.LastUsedTotpStep = acceptedTotpStep;
                // Persist immediately so a parallel concurrent verify with
                // the same code at the same step is rejected by the floor.
                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
            }
        }

        // Clear emergency-recovery lock on successful recovery / email use.
        if (valid && lockedToRecovery
            && (string.Equals(request.Method, "email", StringComparison.OrdinalIgnoreCase)
                || string.Equals(request.Method, "recovery", StringComparison.OrdinalIgnoreCase)))
        {
            userData.ForceRecoveryOnNextLogin = false;
        }
        if (valid && consumedRecoveryIdx >= 0)
        {
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }
        else if (valid && lockedToRecovery)
        {
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }

        if (!valid)
        {
            challenge.AttemptCount++;
            await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = challenge.UserId,
                Username = challenge.Username,
                RemoteIp = challenge.RemoteIp ?? string.Empty,
                DeviceId = challenge.DeviceId ?? string.Empty,
                DeviceName = challenge.DeviceName ?? string.Empty,
                Result = AuditResult.Failed,
                Method = request.Method,
            }).ConfigureAwait(false);

            return Unauthorized(new { message = "Invalid 2FA code." });
        }

        _challengeStore.ConsumeChallenge(request.ChallengeToken);
        await _store.ResetFailedAttemptsAsync(challenge.UserId).ConfigureAwait(false);
        _rateLimiter.Reset("verify_user:" + challenge.UserId.ToString("N"));
        _rateLimiter.Reset("verify:" + ip);

        // Mark this (user, device) pre-verified so the WebSocket / follow-up
        // SessionStarted events that Jellyfin fires seconds after this don't
        // get blocked again. Without this we'd re-block the token we just
        // unblocked, and the browser ends up looping.
        _logger.LogDebug("[2FA] Verify pre-verify path: challenge.DeviceId='{D}'",
            challenge.DeviceId ?? "(null)");
        if (!string.IsNullOrEmpty(challenge.DeviceId))
        {
            _challengeStore.MarkDevicePreVerified(challenge.UserId, challenge.DeviceId);
            _logger.LogDebug("[2FA] MarkDevicePreVerified called for user {U} device '{D}'",
                challenge.UserId, challenge.DeviceId);
            // Device that just completed 2FA via code doesn't need to ALSO be
            // approved from a pending-pairing entry. Drop any matching one.
            _pendingPairings.Remove(challenge.UserId, challenge.DeviceId);
        }
        else
        {
            _logger.LogWarning("[2FA] challenge.DeviceId was null/empty — NOT marking pre-verified. Next session will be re-blocked.");
        }
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = challenge.UserId,
            Username = challenge.Username,
            RemoteIp = challenge.RemoteIp ?? string.Empty,
            DeviceId = challenge.DeviceId ?? string.Empty,
            DeviceName = challenge.DeviceName ?? string.Empty,
            Result = AuditResult.Success,
            Method = request.Method,
        }).ConfigureAwait(false);

        string? deviceToken = null;
        if (request.TrustDevice && !string.IsNullOrEmpty(challenge.DeviceId))
        {
            var (rawToken, trustedDevice) = _deviceTokenService.CreateDeviceToken(
                challenge.DeviceId,
                challenge.DeviceName ?? challenge.DeviceId);

            userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
            userData.TrustedDevices.Add(trustedDevice);
            // SEC-L1: cap trusted-device list (FIFO-evict oldest by LastUsedAt).
            EnforceTrustedDeviceCap(userData);
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

            deviceToken = rawToken;
        }

        // Return the stashed Jellyfin auth response from the middleware so the
        // client ends up with a valid session identical to a non-2FA login.
        if (!string.IsNullOrEmpty(challenge.PendingAuthResponse))
        {
            // Unblock the access token inside the stashed response — it was
            // blocked at middleware level when the challenge was issued, and
            // now that 2FA is complete the client is authorized to use it.
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(challenge.PendingAuthResponse);
                if (doc.RootElement.TryGetProperty("AccessToken", out var tokEl)
                    && tokEl.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    var tok = tokEl.GetString();
                    if (!string.IsNullOrEmpty(tok))
                    {
                        _challengeStore.UnblockToken(tok);
                        _logger.LogInformation("[2FA] Unblocked access token for {User} after successful 2FA", challenge.Username);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Could not parse stashed auth response to unblock token");
            }

            Response.ContentType = "application/json";
            if (deviceToken is not null)
            {
                Response.Headers.Append("X-TwoFactor-Device-Token", deviceToken);
            }

            return Content(challenge.PendingAuthResponse, "application/json");
        }

        // Fallback when middleware didn't stash a response (manual Verify call)
        return Ok(new VerifyResponse
        {
            AccessToken = string.Empty,
            DeviceToken = deviceToken,
        });
    }

    // -------------------------------------------------------------------------
    // 2. POST /TwoFactorAuth/Setup/Totp [Authorize]
    // -------------------------------------------------------------------------

    [HttpPost("Setup/Totp")]
    [Authorize]
    [ProducesResponseType(typeof(TotpSetupResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<TotpSetupResponse>> SetupTotp()
    {
        var userId = GetCurrentUserId();
        var jellyfinUser = _userManager.GetUserById(userId);
        var username = jellyfinUser?.Username ?? userId.ToString();

        var (secret, qrCodeBase64, manualEntryKey) = _totpService.GenerateSecret(username);
        // SEC-M3: bind ciphertext to userId via AAD so an attacker with
        // file-system write access can't swap blobs across user records.
        var encryptedSecret = _totpService.EncryptSecret(secret, userId);

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        userData.TotpEnabled = true;
        userData.TotpVerified = false;
        userData.EncryptedTotpSecret = encryptedSecret;
        // SEC-M4: reset replay floor on new secret — future codes start fresh.
        userData.LastUsedTotpStep = 0;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        // New secret ⇒ old replay cache entries can collide with codes the
        // authenticator is about to show. See TotpService.ResetReplayCache.
        _totpService.ResetReplayCache(userId.ToString());

        return Ok(new TotpSetupResponse
        {
            SecretKey = secret,
            QrCodeBase64 = qrCodeBase64,
            ManualEntryKey = manualEntryKey,
        });
    }

    // -------------------------------------------------------------------------
    // 3. POST /TwoFactorAuth/Setup/Totp/Confirm [Authorize]
    // -------------------------------------------------------------------------

    [HttpPost("Setup/Totp/Confirm")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> ConfirmTotp([FromBody, Required] ConfirmTotpRequest request)
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
        {
            return BadRequest("TOTP setup has not been initiated");
        }

        // SEC-M3: pass userId for AAD-bound v2 ciphertexts. v1 still works.
        var decryptedSecret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, userId);
        // SEC-M4: confirm-during-enrollment, no replay floor needed (the
        // secret was minted seconds ago).
        var valid = _totpService.ValidateCode(decryptedSecret, request.Code, userId.ToString(),
            persistedFloor: 0, out var acceptedStep);

        if (!valid)
        {
            return BadRequest("Invalid TOTP code");
        }

        userData.TotpVerified = true;
        userData.LastUsedTotpStep = acceptedStep;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // 4. POST /TwoFactorAuth/Setup/Disable [Authorize]
    // -------------------------------------------------------------------------

    [HttpPost("Setup/Disable")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> DisableTotp()
    {
        var userId = GetCurrentUserId();
        await _store.MutateAsync(userId, ud =>
        {
            ud.TotpEnabled = false;
            ud.TotpVerified = false;
            ud.EncryptedTotpSecret = null;
            ud.RecoveryCodes.Clear();
            ud.RecoveryCodesGeneratedAt = null;
            ud.TrustedDevices.Clear();
            ud.PairedDevices.Clear();
            ud.AppPasswords.Clear();
        }).ConfigureAwait(false);
        _pendingPairings.RemoveAllForUser(userId);
        _challengeStore.WipeAllForUser(userId);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "self_disable",
        }).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // POST /TwoFactorAuth/RecoveryCodes/Generate — generate (or rotate) recovery codes.
    // Returns plaintext codes ONCE. User must save them.
    // -------------------------------------------------------------------------

    [HttpPost("RecoveryCodes/Generate")]
    [Authorize]
    public async Task<IActionResult> GenerateRecoveryCodes()
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        if (!userData.TotpEnabled || !userData.TotpVerified)
        {
            return BadRequest(new { message = "Set up TOTP first before generating recovery codes." });
        }

        var (plaintext, records) = _recoveryCodes.GenerateCodes();
        userData.RecoveryCodes = records;
        userData.RecoveryCodesGeneratedAt = DateTime.UtcNow;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        return Ok(new
        {
            codes = plaintext,
            generatedAt = userData.RecoveryCodesGeneratedAt,
            warning = "These codes are shown ONCE. Save them in a password manager. Each code works for one login.",
        });
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/RecoveryCodes/Status — count of remaining + generated date.
    // Doesn't return the codes themselves.
    // -------------------------------------------------------------------------

    [HttpGet("RecoveryCodes/Status")]
    [Authorize]
    public async Task<IActionResult> GetRecoveryCodesStatus()
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        return Ok(new
        {
            total = userData.RecoveryCodes.Count,
            remaining = userData.RecoveryCodes.Count(c => !c.Used),
            generatedAt = userData.RecoveryCodesGeneratedAt,
        });
    }

    // -------------------------------------------------------------------------
    // 5. GET /TwoFactorAuth/Devices [Authorize]
    // -------------------------------------------------------------------------

    [HttpGet("Devices")]
    [Authorize]
    [ProducesResponseType(typeof(IReadOnlyList<TrustedDeviceResponse>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<TrustedDeviceResponse>>> GetDevices()
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        var response = userData.TrustedDevices.Select(d => new TrustedDeviceResponse
        {
            Id = d.Id,
            DeviceId = d.DeviceId,
            DeviceName = d.DeviceName,
            CreatedAt = d.CreatedAt,
            LastUsedAt = d.LastUsedAt,
        }).ToList();

        return Ok(response);
    }

    // -------------------------------------------------------------------------
    // 6. DELETE /TwoFactorAuth/Devices/{id} [Authorize]
    // -------------------------------------------------------------------------

    [HttpDelete("Devices/{id}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> DeleteDevice([FromRoute] string id)
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        var device = userData.TrustedDevices.FirstOrDefault(d => d.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        userData.TrustedDevices.Remove(device);
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        // Wipe in-memory pre-verify state for this device — otherwise a user
        // who just revoked would be in a ~2-minute window where the device
        // could still bypass 2FA.
        if (!string.IsNullOrWhiteSpace(device.DeviceId))
        {
            _challengeStore.ConsumeDevicePreVerified(userId, device.DeviceId);
        }

        // End any live Jellyfin session token tied to this device id.
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
            foreach (var d in devices.Items.Where(d =>
                !string.IsNullOrEmpty(d.DeviceId)
                && !string.IsNullOrEmpty(device.DeviceId)
                && string.Equals(d.DeviceId, device.DeviceId, StringComparison.Ordinal)
                && !string.IsNullOrEmpty(d.AccessToken)))
            {
                try { await _sessionManager.Logout(d.AccessToken).ConfigureAwait(false); }
                catch (Exception inner) { _logger.LogDebug(inner, "[2FA] Failed to logout token for device {Dev}", d.DeviceId); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Failed to end sessions on trusted device revoke");
        }

        return Ok();
    }

    // -------------------------------------------------------------------------
    // 7. POST /TwoFactorAuth/Devices/Register [Authorize]
    // -------------------------------------------------------------------------

    [HttpPost("Devices/Register")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> RegisterDevice([FromBody, Required] RegisterDeviceRequest request)
    {
        var userId = GetCurrentUserId();

        // Validate — deviceIds are client-controlled, so without bounds a
        // hostile client can inflate the user's JSON file indefinitely.
        if (!IsValidDeviceId(request.DeviceId))
        {
            return BadRequest(new { message = "Invalid device id" });
        }

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        // Hard cap — if the user already has 50 registered devices, refuse to
        // add more (likely a bug or a churn attack). Admins can clear via
        // Setup page. 50 is comfortably beyond any realistic number of
        // simultaneously-used browsers/clients a user owns.
        const int MaxRegisteredDevices = 50;
        if (userData.RegisteredDeviceIds.Count >= MaxRegisteredDevices
            && !userData.RegisteredDeviceIds.Contains(request.DeviceId))
        {
            return StatusCode(429, new { message = "Registered device limit reached. Revoke old devices from Setup." });
        }

        if (!userData.RegisteredDeviceIds.Contains(request.DeviceId))
        {
            userData.RegisteredDeviceIds.Add(request.DeviceId);
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }

        return Ok();
    }

    /// <summary>DeviceId validator — 1-128 chars, printable ASCII, no control bytes.
    /// Jellyfin clients use short hex-ish or base64-ish ids; anything else is
    /// either a bug or an attempt to smuggle control characters into storage.</summary>
    private static bool IsValidDeviceId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return false;
        if (id.Length > 128) return false;
        foreach (var c in id)
        {
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    }

    /// <summary>SEC-L1: hard cap on TrustedDevices count per user. Users would
    /// otherwise grow the list unbounded by ticking "Trust this device" on
    /// every browser. 30 is generous (typical user has 3-5 active browsers
    /// across phone/laptop/desktop); LRU-evict the oldest by LastUsedAt when
    /// the cap is exceeded so the just-added record is preserved.</summary>
    private const int MaxTrustedDevicesPerUser = 30;

    private static void EnforceTrustedDeviceCap(UserTwoFactorData userData)
    {
        if (userData.TrustedDevices.Count <= MaxTrustedDevicesPerUser) return;
        userData.TrustedDevices.Sort((a, b) => a.LastUsedAt.CompareTo(b.LastUsedAt));
        var toRemove = userData.TrustedDevices.Count - MaxTrustedDevicesPerUser;
        userData.TrustedDevices.RemoveRange(0, toRemove);
    }

    // -------------------------------------------------------------------------
    // POST /TwoFactorAuth/Pairings/Initiate [AllowAnonymous]
    // TV calls this to get a code to display + a poll token to check approval status.
    // -------------------------------------------------------------------------

    [HttpPost("Pairings/Initiate")]
    [AllowAnonymous]
    public ActionResult InitiatePairing([FromBody, Required] InitiatePairingRequest req)
    {
        // Throttle TV-initiated pairings per IP to keep the in-memory store small.
        var ip = RateLimiter.ClientKey(HttpContext);
        var rl = _rateLimiter.CheckAndRecord("pair:" + ip, 5, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString());
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many pairing requests. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        // Sanitize inputs — anonymous endpoint, fields surface in the admin
        // UI for approval, so reject anything that could be an XSS vector or
        // a control-character smuggle. Cap length so the list can't be used
        // as a write-amplification channel.
        var username = SanitizeDisplay(req.Username, 64);
        var deviceName = SanitizeDisplay(req.DeviceName, 64);

        var pairing = _devicePairingService.InitiatePairing(username, deviceName);
        return Ok(new
        {
            code = pairing.Code,
            pollToken = pairing.PollToken,
            expiresAt = pairing.ExpiresAt,
        });
    }

    private static string SanitizeDisplay(string? input, int maxLen)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var sb = new System.Text.StringBuilder(Math.Min(input.Length, maxLen));
        foreach (var c in input)
        {
            if (sb.Length >= maxLen) break;
            // Allow printable ASCII + common Latin letters, drop control chars,
            // drop HTML-significant <, >, ", ', &, `, =, / so even an admin UI
            // that later uses innerHTML can't be XSS'd via this pathway.
            if (c < 0x20 || c == 0x7F) continue;
            if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '&' || c == '`' || c == '=' || c == '/') continue;
            sb.Append(c);
        }
        return sb.ToString().Trim();
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/Pairings/Poll [AllowAnonymous]
    // TV polls this with its poll token to find out if the admin has approved.
    // When approved, returns the Quick Connect secret so the TV can finalize.
    // -------------------------------------------------------------------------

    [HttpGet("Pairings/Poll")]
    [AllowAnonymous]
    public ActionResult PollPairing([FromQuery] string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return BadRequest(new { message = "Missing token." });
        }

        // SEC-L2: per-IP cap so an unauthenticated attacker can't enumerate
        // pollTokens or hammer the in-memory pairing store. 60/min is generous
        // for legitimate TVs (typically poll every 2-5s during a single
        // pairing window); a botnet of polling clients trips it instantly.
        var pollIp = RateLimiter.ClientKey(HttpContext);
        var pollRl = _rateLimiter.CheckAndRecord("pair_poll:" + pollIp, 60, TimeSpan.FromMinutes(1));
        if (!pollRl.allowed)
        {
            Response.Headers.Append("Retry-After", pollRl.retryAfterSeconds.ToString());
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many poll requests. Try again in {pollRl.retryAfterSeconds} seconds.",
            });
        }

        // Reject obviously malformed tokens cheaply — the pairing store keys
        // are 32-byte base64url, so anything outside that shape is bogus.
        if (token.Length > 64 || token.Length < 16)
        {
            return NotFound(new { status = "expired" });
        }

        var pairing = _devicePairingService.PollByToken(token);
        if (pairing is null)
        {
            return NotFound(new { status = "expired" });
        }

        return Ok(new
        {
            status = pairing.Status.ToString().ToLowerInvariant(),
            quickConnectSecret = pairing.Status == PairingStatus.Approved ? pairing.QuickConnectSecret : null,
            expiresAt = pairing.ExpiresAt,
        });
    }

    // -------------------------------------------------------------------------
    // 8. GET /TwoFactorAuth/Pairings [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpGet("Pairings")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(IReadOnlyList<PairingResponse>), StatusCodes.Status200OK)]
    public ActionResult<IReadOnlyList<PairingResponse>> GetPendingPairings()
    {
        var pairings = _devicePairingService.GetPendingPairings();

        var response = pairings.Select(p => new PairingResponse
        {
            Code = p.Code,
            Username = p.Username,
            DeviceName = p.DeviceName,
            ExpiresAt = p.ExpiresAt,
        }).ToList();

        return Ok(response);
    }

    // -------------------------------------------------------------------------
    // 9. POST /TwoFactorAuth/Pairings/{code}/Approve [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("Pairings/{code}/Approve")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> ApprovePairing([FromRoute] string code)
    {
        var pairing = _devicePairingService.GetPairing(code);
        if (pairing is null)
        {
            return NotFound("Pairing request not found or expired");
        }

        // Reject pairing records that were initiated without a concrete user or
        // device — an empty-string DeviceId stored as a paired device would
        // create a trust record that matches any request whose DeviceId header
        // also ends up as an empty string (a 2FA bypass primitive).
        if (pairing.UserId == Guid.Empty || string.IsNullOrWhiteSpace(pairing.DeviceId))
        {
            return BadRequest("Pairing is missing user or device — refuse to approve");
        }

        var approved = _devicePairingService.ApprovePairing(code);
        if (!approved)
        {
            return NotFound("Pairing request not found or already actioned");
        }

        // Create a trusted device for the user
        var (rawToken, trustedDevice) = _deviceTokenService.CreateDeviceToken(pairing.DeviceId, pairing.DeviceName);
        var userData = await _store.GetUserDataAsync(pairing.UserId).ConfigureAwait(false);
        userData.TrustedDevices.Add(trustedDevice);
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        await _notificationService.NotifyPairingCompletedAsync(pairing.Username, pairing.DeviceName, approved: true).ConfigureAwait(false);

        return Ok(new { DeviceToken = rawToken });
    }

    // -------------------------------------------------------------------------
    // 10. POST /TwoFactorAuth/Pairings/{code}/Deny [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("Pairings/{code}/Deny")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> DenyPairing([FromRoute] string code)
    {
        var pairing = _devicePairingService.GetPairing(code);
        if (pairing is null)
        {
            return NotFound("Pairing request not found or expired");
        }

        var denied = _devicePairingService.DenyPairing(code);
        if (!denied)
        {
            return NotFound("Pairing request not found or already actioned");
        }

        await _notificationService.NotifyPairingCompletedAsync(pairing.Username, pairing.DeviceName, approved: false).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/MyStatus [Authorize] — the caller's own 2FA summary.
    // Non-admin equivalent of /Users filtered to self. Setup page uses this
    // so non-admin users see accurate status.
    // -------------------------------------------------------------------------

    [HttpGet("MyStatus")]
    [Authorize]
    public async Task<ActionResult<UserTwoFactorStatus>> GetMyStatus()
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var jellyfinUser = _userManager.GetUserById(userId);
        var isLockedOut = await _store.IsLockedOutAsync(userId).ConfigureAwait(false);
        return Ok(new UserTwoFactorStatus
        {
            UserId = userId,
            Username = jellyfinUser?.Username ?? userId.ToString(),
            TotpEnabled = data.TotpEnabled && data.TotpVerified,
            EmailOtpEnabled = data.EmailOtpPreferred,
            TrustedDeviceCount = data.TrustedDevices.Count,
            RecoveryCodesRemaining = data.RecoveryCodes.Count(c => !c.Used),
            IsLockedOut = isLockedOut,
            PasskeyCount = data.Passkeys.Count,
        });
    }

    // -------------------------------------------------------------------------
    // 11. GET /TwoFactorAuth/Users [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpGet("Users")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(IReadOnlyList<UserTwoFactorStatus>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<UserTwoFactorStatus>>> GetUsers()
    {
        var allUserData = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var result = new List<UserTwoFactorStatus>(allUserData.Count);

        foreach (var data in allUserData)
        {
            var jellyfinUser = _userManager.GetUserById(data.UserId);
            var isLockedOut = await _store.IsLockedOutAsync(data.UserId).ConfigureAwait(false);

            result.Add(new UserTwoFactorStatus
            {
                UserId = data.UserId,
                Username = jellyfinUser?.Username ?? data.UserId.ToString(),
                TotpEnabled = data.TotpEnabled && data.TotpVerified,
                EmailOtpEnabled = data.EmailOtpPreferred,
                TrustedDeviceCount = data.TrustedDevices.Count,
                RecoveryCodesRemaining = data.RecoveryCodes.Count(c => !c.Used),
                IsLockedOut = isLockedOut,
                PasskeyCount = data.Passkeys.Count,
            });
        }

        return Ok(result);
    }

    // -------------------------------------------------------------------------
    // POST /TwoFactorAuth/TestSmtp [admin] — sends a test email so admins can verify SMTP
    // -------------------------------------------------------------------------

    [HttpPost("TestSmtp")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> TestSmtp([FromBody, Required] TestSmtpRequest req)
    {
        if (string.IsNullOrEmpty(req.ToAddress))
        {
            return BadRequest(new { message = "Provide an email address to send the test to." });
        }

        try
        {
            await _emailOtpService.SendTestEmailAsync(req.ToAddress).ConfigureAwait(false);
            return Ok(new { message = "Test email sent. Check the inbox (and spam folder)." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] Test SMTP failed");
            return StatusCode(500, new { message = "SMTP test failed — check server logs for details." });
        }
    }

    // -------------------------------------------------------------------------
    // POST /TwoFactorAuth/Email [auth] — user sets their own email for OTP delivery
    // -------------------------------------------------------------------------

    [HttpPost("Email")]
    [Authorize]
    public async Task<IActionResult> SetMyEmail([FromBody, Required] SetEmailRequest req)
    {
        var userId = GetCurrentUserId();
        var email = req.Email?.Trim() ?? string.Empty;

        // Basic shape check
        if (!string.IsNullOrEmpty(email) && (!email.Contains('@') || email.Length > 254))
        {
            return BadRequest(new { message = "Invalid email address." });
        }

        var config = Plugin.Instance?.Configuration;
        if (config is null) return StatusCode(500, new { message = "Plugin not initialized." });

        config.SetUserEmail(userId.ToString("N"), string.IsNullOrEmpty(email) ? null : email);
        Plugin.Instance!.SaveConfiguration();

        await Task.CompletedTask;
        return Ok(new { message = "Saved." });
    }

    [HttpGet("Email")]
    [Authorize]
    public IActionResult GetMyEmail()
    {
        var userId = GetCurrentUserId();
        var email = Plugin.Instance?.Configuration.GetUserEmail(userId.ToString("N")) ?? string.Empty;
        return Ok(new { email });
    }

    // -------------------------------------------------------------------------
    // GET /TwoFactorAuth/AllTrustedDevices — admin: every trusted device across all users
    // -------------------------------------------------------------------------

    [HttpGet("AllTrustedDevices")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> GetAllTrustedDevices()
    {
        var allUsers = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var rows = new List<TrustedDeviceWithUser>();

        foreach (var ud in allUsers)
        {
            var ju = _userManager.GetUserById(ud.UserId);
            foreach (var d in ud.TrustedDevices)
            {
                rows.Add(new TrustedDeviceWithUser
                {
                    UserId = ud.UserId,
                    Username = ju?.Username ?? ud.UserId.ToString(),
                    Id = d.Id,
                    DeviceId = d.DeviceId,
                    DeviceName = d.DeviceName,
                    CreatedAt = d.CreatedAt,
                    LastUsedAt = d.LastUsedAt,
                });
            }
        }

        return Ok(rows.OrderByDescending(r => r.LastUsedAt));
    }

    // -------------------------------------------------------------------------
    // DELETE /TwoFactorAuth/Users/{userId}/Devices/{deviceRecordId} — admin revokes
    // -------------------------------------------------------------------------

    [HttpDelete("Users/{userId}/Devices/{deviceRecordId}")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> AdminRevokeDevice([FromRoute] Guid userId, [FromRoute] string deviceRecordId)
    {
        var ud = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        ud.TrustedDevices.RemoveAll(d => d.Id == deviceRecordId);
        await _store.SaveUserDataAsync(ud).ConfigureAwait(false);
        return Ok();
    }

    // -------------------------------------------------------------------------
    // 12. POST /TwoFactorAuth/Users/{id}/Toggle [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("Users/{id}/Toggle")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> ToggleUser([FromRoute] Guid id, [FromBody, Required] ToggleUserRequest request)
    {
        var userData = await _store.GetUserDataAsync(id).ConfigureAwait(false);
        var ju = _userManager.GetUserById(id);

        if (request.Enabled)
        {
            // Admin can't enable 2FA on behalf of a user — they need to enroll themselves.
            // We just clear the lockout / unblock so they can log in and visit /Setup.
            _challengeStore.UnblockAllForUser(id);
            await _store.ResetFailedAttemptsAsync(id).ConfigureAwait(false);
        }
        else
        {
            // Admin disable: wipe all 2FA state. User can re-enroll fresh.
            userData.TotpEnabled = false;
            userData.TotpVerified = false;
            userData.EncryptedTotpSecret = null;
            userData.RecoveryCodes.Clear();
            userData.RecoveryCodesGeneratedAt = null;
            userData.TrustedDevices.Clear();
            userData.PairedDevices.Clear();
            userData.AppPasswords.Clear();
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
            _challengeStore.WipeAllForUser(id);
            _pendingPairings.RemoveAllForUser(id);
        }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = id,
            Username = ju?.Username ?? id.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "admin_toggle_" + (request.Enabled ? "on" : "off"),
        }).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // 13. GET /TwoFactorAuth/AuditLog [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpGet("AuditLog")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(IReadOnlyList<AuditEntry>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<AuditEntry>>> GetAuditLog([FromQuery] int? limit = null)
    {
        var entries = await _store.GetAuditLogAsync(limit).ConfigureAwait(false);
        return Ok(entries);
    }

    // -------------------------------------------------------------------------
    // 14. GET /TwoFactorAuth/ApiKeys [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpGet("ApiKeys")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(IReadOnlyList<ApiKeyEntry>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<object>>> GetApiKeys()
    {
        var keys = await _store.GetApiKeysAsync().ConfigureAwait(false);
        // Never expose raw key material — only id/label/preview/created for
        // admin UI. Legacy keys with a raw Key still use preview from there.
        var safe = keys.Select(k => new
        {
            id = k.Id,
            label = k.Label,
            createdAt = k.CreatedAt,
            preview = !string.IsNullOrEmpty(k.KeyPreview)
                ? k.KeyPreview
                : (!string.IsNullOrEmpty(k.Key) && k.Key.Length > 6 ? k.Key.Substring(0, 6) + "…" : ""),
        }).ToList<object>();
        return Ok(safe);
    }

    // -------------------------------------------------------------------------
    // 15. POST /TwoFactorAuth/ApiKeys [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("ApiKeys")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(ApiKeyEntry), StatusCodes.Status200OK)]
    public async Task<ActionResult<object>> CreateApiKey([FromBody, Required] CreateApiKeyRequest request)
    {
        var rawKeyBytes = RandomNumberGenerator.GetBytes(32);
        var rawKey = Convert.ToBase64String(rawKeyBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        // Store only the hash + a short preview. Raw key is returned to the
        // admin once; they must copy it immediately.
        var newEntry = new ApiKeyEntry
        {
            Key = string.Empty,
            KeyHash = BypassEvaluator.HashApiKey(rawKey),
            KeyPreview = rawKey.Length > 6 ? rawKey.Substring(0, 6) + "…" : rawKey,
            Label = request.Label,
            CreatedAt = DateTime.UtcNow,
        };

        var keys = await _store.GetApiKeysAsync().ConfigureAwait(false);
        var mutableKeys = keys.ToList();
        mutableKeys.Add(newEntry);
        await _store.SaveApiKeysAsync(mutableKeys).ConfigureAwait(false);

        return Ok(new
        {
            id = newEntry.Id,
            label = newEntry.Label,
            createdAt = newEntry.CreatedAt,
            key = rawKey,
            preview = newEntry.KeyPreview,
            warning = "Copy this key now. You won't see it again.",
        });
    }

    // -------------------------------------------------------------------------
    // 16. DELETE /TwoFactorAuth/ApiKeys/{id} [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpDelete("ApiKeys/{id}")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> DeleteApiKey([FromRoute] string id)
    {
        var keys = await _store.GetApiKeysAsync().ConfigureAwait(false);
        var mutableKeys = keys.ToList();
        var entry = mutableKeys.FirstOrDefault(k => k.Id == id);

        if (entry is null)
        {
            return NotFound();
        }

        mutableKeys.Remove(entry);
        await _store.SaveApiKeysAsync(mutableKeys).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // 17. POST /TwoFactorAuth/Email/Send [AllowAnonymous]
    // -------------------------------------------------------------------------

    [HttpPost("Email/Send")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult> SendEmailOtp([FromBody, Required] SendEmailOtpRequest request)
    {
        // Per-IP rate limit: 5 sends per 5 minutes
        var ip = RateLimiter.ClientKey(HttpContext);
        var rl = _rateLimiter.CheckAndRecord("email:" + ip, 5, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString());
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many email requests. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null)
        {
            return BadRequest(new { message = "Invalid or expired challenge." });
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Account is locked out." });
        }

        // Per-user email address from plugin config (admin sets these)
        var email = Plugin.Instance?.Configuration.GetUserEmail(challenge.UserId.ToString("N"));

        var (_, sent) = await _emailOtpService.GenerateAndSendCodeAsync(
            challenge.UserId,
            challenge.Username,
            email,
            request.ChallengeToken).ConfigureAwait(false);

        if (!sent)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = email is null
                    ? "Email address not configured for this user. Ask the admin to set it in plugin settings."
                    : "Failed to send email — check SMTP configuration in plugin settings.",
            });
        }

        return Ok(new { message = "Code sent." });
    }

    // -------------------------------------------------------------------------
    // 18. POST /TwoFactorAuth/Sessions/{id}/Revoke [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("Sessions/{id}/Revoke")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult RevokeSession([FromRoute] string id)
    {
        var sessions = _sessionManager.Sessions;
        var session = sessions.FirstOrDefault(s => s.Id == id);

        if (session is null)
        {
            return NotFound("Session not found");
        }

        _sessionManager.ReportSessionEnded(id);

        return Ok();
    }

    // =========================================================================
    // App Passwords  (v1.3.0 — for native clients that submit a password)
    // =========================================================================

    public class CreateAppPasswordBody { public string Label { get; set; } = string.Empty; }

    [HttpGet("AppPasswords")]
    [Authorize]
    public async Task<IActionResult> ListAppPasswords()
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var rows = data.AppPasswords.Select(p => new
        {
            id = p.Id,
            label = p.Label,
            createdAt = p.CreatedAt,
            lastUsedAt = p.LastUsedAt,
            lastDeviceName = p.LastDeviceName,
        });
        return Ok(rows);
    }

    [HttpPost("AppPasswords")]
    [Authorize]
    public async Task<IActionResult> CreateAppPassword([FromBody, Required] CreateAppPasswordBody req)
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (!data.TotpEnabled || !data.TotpVerified)
        {
            return BadRequest(new { message = "Set up TOTP first before creating app passwords." });
        }

        if (data.AppPasswords.Count >= 20)
        {
            return BadRequest(new { message = "Limit reached. Revoke an existing app password first." });
        }

        var label = (req.Label ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(label)) label = "App password";
        if (label.Length > 80) label = label.Substring(0, 80);

        var (plaintext, hash) = _appPasswords.Generate();
        var entry = new AppPassword
        {
            Id = Guid.NewGuid().ToString("N"),
            Label = label,
            PasswordHash = hash,
            CreatedAt = DateTime.UtcNow,
        };
        data.AppPasswords.Add(entry);
        await _store.SaveUserDataAsync(data).ConfigureAwait(false);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "app_password_created:" + label,
        }).ConfigureAwait(false);

        return Ok(new
        {
            id = entry.Id,
            label = entry.Label,
            password = plaintext, // shown ONCE
            warning = "Copy this password now. You won't see it again. Use it as the password in your native app.",
        });
    }

    [HttpDelete("AppPasswords/{id}")]
    [Authorize]
    public async Task<IActionResult> RevokeAppPassword([FromRoute] string id)
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var removed = data.AppPasswords.RemoveAll(p => p.Id == id);
        if (removed == 0) return NotFound();
        await _store.SaveUserDataAsync(data).ConfigureAwait(false);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "app_password_revoked",
        }).ConfigureAwait(false);

        return Ok();
    }

    // =========================================================================
    // Paired Devices  (v1.3.0 — TVs/native clients trusted for 2FA bypass)
    // =========================================================================

    [HttpGet("PairedDevices")]
    [Authorize]
    public async Task<IActionResult> ListPairedDevices()
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var rows = data.PairedDevices.Select(p => new
        {
            id = p.Id,
            deviceId = p.DeviceId,
            deviceName = p.DeviceName,
            appName = p.AppName,
            source = p.Source,
            createdAt = p.CreatedAt,
            lastUsedAt = p.LastUsedAt,
            lastIp = p.LastIp,
        });
        return Ok(rows);
    }

    [HttpDelete("PairedDevices/{id}")]
    [Authorize]
    public async Task<IActionResult> RevokePairedDevice([FromRoute] string id)
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var target = data.PairedDevices.FirstOrDefault(p => p.Id == id);
        if (target is null) return NotFound();
        data.PairedDevices.Remove(target);
        await _store.SaveUserDataAsync(data).ConfigureAwait(false);

        // Wipe any in-memory bypass flag for this device so the revoke takes
        // effect instantly instead of honoring a ~2-minute pre-verify window.
        if (!string.IsNullOrWhiteSpace(target.DeviceId))
        {
            _challengeStore.ConsumeDevicePreVerified(userId, target.DeviceId);
        }

        // End any live session using this device. Revoke via access token
        // (fully invalidates the token) rather than ReportSessionEnded (which
        // only clears the transient session object and leaves the token live).
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
            foreach (var d in devices.Items.Where(d =>
                !string.IsNullOrEmpty(d.DeviceId)
                && !string.IsNullOrEmpty(target.DeviceId)
                && string.Equals(d.DeviceId, target.DeviceId, StringComparison.Ordinal)
                && !string.IsNullOrEmpty(d.AccessToken)))
            {
                try { await _sessionManager.Logout(d.AccessToken).ConfigureAwait(false); }
                catch { /* best effort */ }
            }
        }
        catch { /* best effort */ }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            DeviceId = target.DeviceId,
            DeviceName = target.DeviceName,
            Result = AuditResult.ConfigChanged,
            Method = "paired_device_revoked",
        }).ConfigureAwait(false);
        return Ok();
    }

    // =========================================================================
    // Pending Pairings  (v1.3.0 — devices that hit the 2FA wall)
    // =========================================================================

    [HttpGet("PendingPairings")]
    [Authorize]
    public IActionResult ListPendingPairings()
    {
        var userId = GetCurrentUserId();
        var rows = _pendingPairings.ListForUser(userId).Select(p => new
        {
            deviceId = p.DeviceId,
            deviceName = p.DeviceName,
            appName = p.AppName,
            remoteIp = p.RemoteIp,
            firstSeen = p.FirstSeen,
            lastSeen = p.LastSeen,
        });
        return Ok(rows);
    }

    public class ApprovePendingBody
    {
        public string DeviceId { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
    }

    [HttpPost("PendingPairings/Approve")]
    [Authorize]
    public async Task<IActionResult> ApprovePending([FromBody, Required] ApprovePendingBody req)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(req.DeviceId)) return BadRequest(new { message = "deviceId required" });

        var pending = _pendingPairings.Get(userId, req.DeviceId);
        if (pending is null) return NotFound(new { message = "Pending request not found or expired." });

        if (!_pendingPairings.Remove(userId, req.DeviceId))
        {
            return Ok(new { message = "Already paired." });
        }

        var label = (req.Label ?? string.Empty).Trim();
        if (label.Length > 80) label = label.Substring(0, 80);

        var alreadyPresent = false;
        await _store.MutateAsync(userId, ud =>
        {
            if (ud.PairedDevices.Any(p => p.DeviceId == req.DeviceId))
            {
                alreadyPresent = true;
                return;
            }
            ud.PairedDevices.Add(new PairedDevice
            {
                Id = Guid.NewGuid().ToString("N"),
                DeviceId = pending.DeviceId,
                DeviceName = string.IsNullOrEmpty(label) ? pending.DeviceName : label,
                AppName = pending.AppName,
                Source = "auto",
                CreatedAt = DateTime.UtcNow,
                LastUsedAt = DateTime.UtcNow,
                LastIp = pending.RemoteIp,
            });
        }).ConfigureAwait(false);
        if (alreadyPresent) return Ok(new { message = "Already paired." });

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            DeviceId = pending.DeviceId,
            DeviceName = pending.DeviceName,
            Result = AuditResult.ConfigChanged,
            Method = "device_paired_auto",
        }).ConfigureAwait(false);

        return Ok();
    }

    public class DenyPendingBody { public string DeviceId { get; set; } = string.Empty; }

    public class PairingQrBody { public string DeviceId { get; set; } = string.Empty; }

    /// <summary>Generate a signed approve token + QR for a pending pairing so the user
    /// can approve it by scanning with a phone instead of opening Setup on each device.
    /// Token format: "pair|userId|deviceId|expiryUnix" signed with CookieSigner.
    /// TTL 5 minutes; single-consume on the confirm endpoint.</summary>
    [HttpPost("PairingQr")]
    [Authorize]
    public IActionResult CreatePairingQr([FromBody, Required] PairingQrBody req)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(req.DeviceId)) return BadRequest(new { message = "deviceId required" });

        var pending = _pendingPairings.Get(userId, req.DeviceId);
        if (pending is null) return NotFound(new { message = "Pending request not found or expired." });

        var expiryUnix = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var payload = $"pair|{userId:N}|{req.DeviceId}|{expiryUnix}";
        var sig = _cookieSigner.Sign(payload);
        var token = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payload + "." + sig))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var scheme = HttpContext.Request.IsHttps ? "https" : "http";
        var host = HttpContext.Request.Host.Value;
        var url = $"{scheme}://{host}/TwoFactorAuth/PairConfirm?token={Uri.EscapeDataString(token)}";

        // Generate QR
        using var qrGen = new QRCoder.QRCodeGenerator();
        using var qrData = qrGen.CreateQrCode(url, QRCoder.QRCodeGenerator.ECCLevel.M);
        using var qrPng = new QRCoder.PngByteQRCode(qrData);
        var qrBytes = qrPng.GetGraphic(5);

        return Ok(new
        {
            qrCodeBase64 = Convert.ToBase64String(qrBytes),
            url,
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiryUnix),
            deviceName = pending.DeviceName,
            appName = pending.AppName,
        });
    }

    /// <summary>GET /TwoFactorAuth/PairConfirm — anonymous HTML confirm page rendered when
    /// someone scans the QR. JS on the page verifies they're signed in, decodes the token,
    /// and shows an approval prompt. Actual approval goes through the POST endpoint.</summary>
    [HttpGet("PairConfirm")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetPairConfirmPage() => ServeEmbeddedPage("pairconfirm.html");

    public class PairConfirmBody { public string Token { get; set; } = string.Empty; }

    /// <summary>POST /TwoFactorAuth/PairConfirm — authenticates the current signed-in user
    /// and, if the signed token is valid and matches THIS user, adds the device to paired list.</summary>
    [HttpPost("PairConfirm")]
    [Authorize]
    public async Task<IActionResult> ConfirmPairing([FromBody, Required] PairConfirmBody body)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(body.Token)) return BadRequest(new { message = "Missing token." });

        // Decode base64url
        string decoded;
        try
        {
            var fixedToken = body.Token.Replace('-', '+').Replace('_', '/');
            var pad = fixedToken.Length % 4;
            if (pad > 0) fixedToken += new string('=', 4 - pad);
            decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(fixedToken));
        }
        catch { return BadRequest(new { message = "Invalid token encoding." }); }

        var dotIdx = decoded.LastIndexOf('.');
        if (dotIdx < 0) return BadRequest(new { message = "Malformed token." });
        var payload = decoded.Substring(0, dotIdx);
        var sig = decoded.Substring(dotIdx + 1);

        if (!_cookieSigner.Verify(payload, sig))
            return Unauthorized(new { message = "Invalid token signature." });

        // Replay guard — a signed token inside its TTL can only be consumed once.
        if (!_challengeStore.TryConsumePairToken(sig))
            return Unauthorized(new { message = "Token already used." });

        var parts = payload.Split('|');
        if (parts.Length != 4 || parts[0] != "pair")
            return BadRequest(new { message = "Malformed token." });
        if (!Guid.TryParseExact(parts[1], "N", out var tokenUserId))
            return BadRequest(new { message = "Malformed user id." });
        if (tokenUserId != userId)
            return Unauthorized(new { message = "This pairing link belongs to a different user." });
        var deviceId = parts[2];
        if (!long.TryParse(parts[3], out var expiryUnix))
            return BadRequest(new { message = "Malformed expiry." });
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiryUnix)
            return BadRequest(new { message = "Pairing link expired. Generate a new QR." });

        var pending = _pendingPairings.Get(userId, deviceId);
        if (pending is null) return NotFound(new { message = "Pending pairing no longer exists." });

        // Single-consume: remove the pending entry FIRST so a concurrent
        // duplicate POST /PairConfirm returns the "already" branch without
        // re-adding a duplicate PairedDevice. Remove returns false if another
        // thread got there first.
        if (!_pendingPairings.Remove(userId, deviceId))
        {
            return Ok(new { message = "Already paired." });
        }

        var alreadyPresent = false;
        await _store.MutateAsync(userId, ud =>
        {
            if (ud.PairedDevices.Any(p => p.DeviceId == deviceId))
            {
                alreadyPresent = true;
                return;
            }
            ud.PairedDevices.Add(new PairedDevice
            {
                Id = Guid.NewGuid().ToString("N"),
                DeviceId = deviceId,
                DeviceName = pending.DeviceName,
                AppName = pending.AppName,
                Source = "qr",
                CreatedAt = DateTime.UtcNow,
                LastUsedAt = DateTime.UtcNow,
                LastIp = pending.RemoteIp,
            });
        }).ConfigureAwait(false);
        if (alreadyPresent) return Ok(new { message = "Already paired." });

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            DeviceId = deviceId,
            DeviceName = pending.DeviceName,
            Result = AuditResult.ConfigChanged,
            Method = "device_paired_qr",
        }).ConfigureAwait(false);

        return Ok(new { deviceName = pending.DeviceName });
    }

    [HttpPost("PendingPairings/Deny")]
    [Authorize]
    public async Task<IActionResult> DenyPending([FromBody, Required] DenyPendingBody req)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(req.DeviceId)) return BadRequest();
        var pending = _pendingPairings.Get(userId, req.DeviceId);
        _pendingPairings.Remove(userId, req.DeviceId);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            DeviceId = req.DeviceId,
            DeviceName = pending?.DeviceName ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "pending_pair_denied",
        }).ConfigureAwait(false);
        return Ok();
    }

    // =========================================================================
    // Active Sessions for the current user (read from Jellyfin SessionManager)
    // =========================================================================

    /// <summary>
    /// Lists every device that has a live Jellyfin access token for the current
    /// user. This is stable data from IDeviceManager, not the transient
    /// ISessionManager.Sessions list (which only holds currently-polling
    /// sessions and shows "no active sessions" for most signed-in browsers).
    /// </summary>
    [HttpGet("MySessions")]
    [Authorize]
    public IActionResult MySessions()
    {
        var userId = GetCurrentUserId();
        var currentToken = HttpContext.Request.Headers["X-Emby-Token"].FirstOrDefault() ?? string.Empty;
        var result = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
        var live = _sessionManager.Sessions
            .Where(s => s.UserId == userId)
            .ToDictionary(s => s.DeviceId ?? string.Empty, s => s, StringComparer.OrdinalIgnoreCase);

        var rows = result.Items.Select(d =>
        {
            live.TryGetValue(d.DeviceId ?? string.Empty, out var liveSession);
            return new
            {
                id = d.Id,
                deviceId = d.DeviceId,
                deviceName = d.DeviceName,
                appName = d.AppName,
                appVersion = d.AppVersion,
                lastActivity = d.DateLastActivity,
                isCurrent = !string.IsNullOrEmpty(currentToken)
                    && string.Equals(d.AccessToken, currentToken, StringComparison.Ordinal),
                remoteEndPoint = liveSession?.RemoteEndPoint,
                nowPlaying = liveSession?.NowPlayingItem?.Name,
            };
        }).OrderByDescending(x => x.lastActivity).ToList();

        return Ok(rows);
    }

    /// <summary>Revoke (logout) the access token on the given Device entity.
    /// Identified by the device's internal numeric Id.</summary>
    [HttpPost("MySessions/{id}/Revoke")]
    [Authorize]
    public async Task<IActionResult> RevokeMySession([FromRoute] string id)
    {
        var userId = GetCurrentUserId();
        var result = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
        var device = result.Items.FirstOrDefault(d => d.Id.ToString() == id);
        if (device is null) return NotFound();

        // Calling ISessionManager.Logout(accessToken) revokes the token server-side
        // and ends any active session using it. The client will get 401 on next call.
        if (!string.IsNullOrEmpty(device.AccessToken))
        {
            try { await _sessionManager.Logout(device.AccessToken).ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogWarning(ex, "[2FA] Failed to logout device token"); }
        }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            DeviceId = device.DeviceId ?? string.Empty,
            DeviceName = device.DeviceName ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "session_revoked",
        }).ConfigureAwait(false);

        return Ok();
    }

    // =========================================================================
    // v1.4 — Passkey / WebAuthn (additive 2nd factor)
    // =========================================================================

    public class PasskeyRegisterFinishRequest
    {
        public string Nonce { get; set; } = string.Empty;
        public string Response { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
    }

    /// <summary>Returns what RP ID and origin the server sees for THIS
    /// request. Useful for diagnosing reverse-proxy mismatches without
    /// touching server logs.</summary>
    [HttpGet("Passkeys/Diagnose")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult PasskeyDiagnose()
    {
        var config = Plugin.Instance?.Configuration;
        return Ok(new
        {
            requestHost = HttpContext.Request.Host.Value,
            requestScheme = HttpContext.Request.Scheme,
            xForwardedHost = HttpContext.Request.Headers["X-Forwarded-Host"].FirstOrDefault(),
            xForwardedProto = HttpContext.Request.Headers["X-Forwarded-Proto"].FirstOrDefault(),
            remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            configuredRpId = config?.WebAuthnRpId,
            configuredOrigins = config?.WebAuthnOrigins,
            trustForwardedFor = config?.TrustForwardedFor,
            trustedProxyCidrCount = config?.TrustedProxyCidrs.Length,
        });
    }

    /// <summary>Begin a passkey registration ceremony for the current user.
    /// Returns the JSON the browser passes to navigator.credentials.create()
    /// + a nonce that must be echoed on RegisterFinish.</summary>
    [HttpPost("Passkeys/RegisterBegin")]
    [Authorize]
    public async Task<IActionResult> PasskeyRegisterBegin()
    {
        var userId = GetCurrentUserId();
        var user = _userManager.GetUserById(userId);
        if (user is null) return Unauthorized();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        var optionsJson = _passkeys.BuildRegistrationOptions(HttpContext, userId, user.Username, data.Passkeys);
        var nonce = _passkeyChallenges.Begin(optionsJson, userId);
        return Content("{\"nonce\":\"" + nonce + "\",\"options\":" + optionsJson + "}", "application/json");
    }

    /// <summary>Validate the browser's attestation and persist the new passkey.</summary>
    [HttpPost("Passkeys/RegisterFinish")]
    [Authorize]
    public async Task<IActionResult> PasskeyRegisterFinish([FromBody, Required] PasskeyRegisterFinishRequest req)
    {
        var userId = GetCurrentUserId();
        var (optionsJson, ownerId) = _passkeyChallenges.Consume(req.Nonce);
        if (optionsJson is null || ownerId != userId)
            return BadRequest(new { message = "Registration challenge expired or invalid" });

        try
        {
            var cred = await _passkeys.CompleteRegistrationAsync(HttpContext, userId, optionsJson, req.Response, req.Label).ConfigureAwait(false);
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            await _notificationService.NotifyPasskeyRegisteredAsync(
                _userManager.GetUserById(userId)?.Username ?? userId.ToString(), cred.Label, ip).ConfigureAwait(false);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = userId,
                Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
                RemoteIp = ip,
                Result = AuditResult.ConfigChanged,
                Method = "passkey_registered:" + cred.Label,
            }).ConfigureAwait(false);
            return Ok(new { id = cred.Id, label = cred.Label, aaguid = cred.Aaguid });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Passkey registration failed");
            return BadRequest(new { message = "Registration failed: " + ex.Message });
        }
    }

    /// <summary>List a user's passkeys for the Setup page (no public key
    /// material exposed).</summary>
    [HttpGet("Passkeys")]
    [Authorize]
    public async Task<IActionResult> ListPasskeys()
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        return Ok(data.Passkeys.Select(p => new
        {
            id = p.Id,
            label = p.Label,
            aaguid = p.Aaguid,
            createdAt = p.CreatedAt,
            lastUsedAt = p.LastUsedAt,
        }));
    }

    public class PasskeyClientLog { public string Phase { get; set; } = ""; public string Name { get; set; } = ""; public string Message { get; set; } = ""; public string Ua { get; set; } = ""; }

    /// <summary>Browser-side WebAuthn errors only show as a generic
    /// "not allowed" string in some browsers (looking at you, Safari). The
    /// Setup page POSTs the actual DOMException name + message here so admins
    /// can debug from the server log. Rate-limited and length-capped because
    /// any signed-in user can hit this — without bounds it would be a
    /// trivial log-spam vector.</summary>
    [HttpPost("Passkeys/ClientLog")]
    [Authorize]
    public IActionResult LogPasskeyClientError([FromBody, Required] PasskeyClientLog body)
    {
        var userId = GetCurrentUserId();
        var rl = _rateLimiter.CheckAndRecord("passkey_log:" + userId.ToString("N"), 10, TimeSpan.FromMinutes(5));
        if (!rl.allowed) return StatusCode(429);
        static string Trim(string? s) => string.IsNullOrEmpty(s) ? string.Empty : (s.Length > 200 ? s.Substring(0, 200) : s);
        _logger.LogInformation("[2FA] Passkey client error phase={Phase} name={Name} msg={Msg} ua={Ua}",
            Trim(body.Phase), Trim(body.Name), Trim(body.Message), Trim(body.Ua));
        return Ok();
    }

    [HttpDelete("Passkeys/{id}")]
    [Authorize]
    public async Task<IActionResult> DeletePasskey([FromRoute] string id)
    {
        var userId = GetCurrentUserId();
        var removed = false;
        await _store.MutateAsync(userId, ud =>
        {
            removed = ud.Passkeys.RemoveAll(p => string.Equals(p.Id, id, StringComparison.Ordinal)) > 0;
        }).ConfigureAwait(false);
        if (!removed) return NotFound();
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = "passkey_revoked",
        }).ConfigureAwait(false);
        return Ok();
    }

    public class PasskeyAssertBeginRequest { public string ChallengeToken { get; set; } = string.Empty; }
    public class PasskeyAssertFinishRequest
    {
        public string ChallengeToken { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string Response { get; set; } = string.Empty;
    }

    /// <summary>Begin an assertion ceremony to satisfy the 2FA challenge step
    /// with a passkey. Anonymous: the challenge token identifies which user
    /// already passed username+password.</summary>
    [HttpPost("Verify/Passkey/Begin")]
    [AllowAnonymous]
    public async Task<IActionResult> PasskeyAssertBegin([FromBody, Required] PasskeyAssertBeginRequest req)
    {
        var challenge = _challengeStore.GetChallenge(req.ChallengeToken);
        if (challenge is null) return BadRequest(new { message = "Invalid or expired challenge" });
        var data = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        if (data.Passkeys.Count == 0) return BadRequest(new { message = "No passkeys registered for this user" });

        var optionsJson = _passkeys.BuildAssertionOptions(HttpContext, data.Passkeys);
        var nonce = _passkeyChallenges.Begin(optionsJson, challenge.UserId);
        return Content("{\"nonce\":\"" + nonce + "\",\"options\":" + optionsJson + "}", "application/json");
    }

    /// <summary>Validate the assertion and consume the 2FA challenge — returns
    /// the same VerifyResponse shape the TOTP path returns so the browser
    /// flow is uniform.</summary>
    [HttpPost("Verify/Passkey/Finish")]
    [AllowAnonymous]
    public async Task<IActionResult> PasskeyAssertFinish([FromBody, Required] PasskeyAssertFinishRequest req)
    {
        var challenge = _challengeStore.GetChallenge(req.ChallengeToken);
        if (challenge is null) return BadRequest(new { message = "Invalid or expired challenge" });
        var (optionsJson, userId) = _passkeyChallenges.Consume(req.Nonce);
        if (optionsJson is null || userId != challenge.UserId)
            return BadRequest(new { message = "Assertion challenge expired or invalid" });

        var ok = false;
        try
        {
            ok = await _passkeys.CompleteAssertionAsync(HttpContext, challenge.UserId, optionsJson, req.Response).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Passkey assertion failed");
        }

        if (!ok)
        {
            await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
            return Unauthorized(new { message = "Passkey verification failed" });
        }

        // Consume the challenge — same code path as TOTP-success (controller
        // already has Verify endpoint for that; we delegate by re-issuing the
        // stash). Simplest reuse: mark device pre-verified and return the
        // stashed PendingAuthResponse the way the TOTP Verify does.
        if (!_challengeStore.ConsumeChallenge(req.ChallengeToken))
            return BadRequest(new { message = "Challenge already consumed" });

        _challengeStore.MarkDevicePreVerified(challenge.UserId, challenge.DeviceId);
        _pendingPairings.Remove(challenge.UserId, challenge.DeviceId ?? string.Empty);

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = challenge.UserId,
            Username = challenge.Username,
            RemoteIp = ip,
            DeviceId = challenge.DeviceId ?? string.Empty,
            DeviceName = challenge.DeviceName ?? string.Empty,
            Result = AuditResult.Success,
            Method = "passkey",
        }).ConfigureAwait(false);

        // Return the stashed Jellyfin auth payload verbatim — same shape the
        // standard challenge.html flow consumes (parses out AccessToken etc.).
        var stashed = challenge.PendingAuthResponse;
        if (string.IsNullOrEmpty(stashed))
        {
            return Ok(new { message = "Verified, but no stashed auth response — sign in again from the start" });
        }
        return Content(stashed, "application/json");
    }

    // =========================================================================
    // v1.4 — Self-service emergency lockout
    // =========================================================================

    [HttpPost("Setup/EmergencyLockout")]
    [Authorize]
    public async Task<IActionResult> EmergencyLockout()
    {
        var userId = GetCurrentUserId();
        var user = _userManager.GetUserById(userId);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;

        // Wipe persisted bypass routes so no stale device sneaks back in.
        await _store.MutateAsync(userId, ud =>
        {
            ud.TrustedDevices.Clear();
            ud.PairedDevices.Clear();
            ud.RegisteredDeviceIds.Clear();
            ud.ForceRecoveryOnNextLogin = true;
        }).ConfigureAwait(false);

        var killed = await _sessionTerm.LogoutAllForUserAsync(userId).ConfigureAwait(false);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = user?.Username ?? userId.ToString(),
            RemoteIp = ip,
            Result = AuditResult.ConfigChanged,
            Method = "emergency_lockout",
        }).ConfigureAwait(false);

        await _notificationService.NotifyEmergencyLockoutAsync(user?.Username ?? userId.ToString(), ip).ConfigureAwait(false);

        return Ok(new { sessionsTerminated = killed });
    }

    // =========================================================================
    // v1.4 — Admin force-logout (single user)
    // =========================================================================

    [HttpPost("Users/{userId:guid}/ForceLogout")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> AdminForceLogout([FromRoute] Guid userId)
    {
        var target = _userManager.GetUserById(userId);
        if (target is null) return NotFound();

        var adminId = GetCurrentUserId();
        // v1.4 SEC-M2: refuse to lock out the last remaining admin (which
        // would render the server unrecoverable without CLI access). Two
        // guards: (1) admin can self-force-logout if other admins exist;
        // (2) any admin can be force-logged-out unless they're the only one.
        // SEC-M2: refuse to force-logout the only remaining administrator —
        // would lock the server out of the admin UI permanently.
        try
        {
            if (target.HasPermission(PermissionKind.IsAdministrator))
            {
                var adminCount = _userManager.Users.Count(u =>
                    u.HasPermission(PermissionKind.IsAdministrator));
                if (adminCount <= 1)
                {
                    return Conflict(new { message = "Refusing to force-logout the only remaining administrator." });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Couldn't enumerate admins for last-admin guard — proceeding");
        }

        await _store.MutateAsync(userId, ud =>
        {
            ud.TrustedDevices.Clear();
            ud.RegisteredDeviceIds.Clear();
        }).ConfigureAwait(false);

        var killed = await _sessionTerm.LogoutAllForUserAsync(userId).ConfigureAwait(false);

        var adminName = _userManager.GetUserById(adminId)?.Username ?? adminId.ToString();
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = target.Username,
            RemoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Result = AuditResult.ConfigChanged,
            Method = $"admin_force_logout_by:{adminName}",
        }).ConfigureAwait(false);

        await _notificationService.NotifyAdminForceLogoutAsync(target.Username, adminName, killed).ConfigureAwait(false);
        return Ok(new { sessionsTerminated = killed });
    }

    // =========================================================================
    // v1.4 — Bulk admin actions
    // =========================================================================

    public class BulkActionRequest
    {
        public string Action { get; set; } = string.Empty;
        public List<Guid> UserIds { get; set; } = new();
    }

    [HttpPost("Admin/Bulk")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> BulkAction([FromBody, Required] BulkActionRequest req)
    {
        if (req.UserIds.Count == 0) return BadRequest(new { message = "No users selected" });
        // SEC-M8: `disable_2fa` was an inconsistent half-wipe (cleared TOTP +
        // recovery + passkeys but left app passwords + registered device IDs +
        // email-OTP preference). Renamed to `reset_2fa` and made it a full
        // wipe so the action does what its label implies. Old name kept as an
        // alias for one release for any admin scripts that called the API.
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "reset_2fa", "disable_2fa", "rotate_recovery", "revoke_paired_devices", "revoke_trusted_browsers", "force_logout"
        };
        if (!allowed.Contains(req.Action))
            return BadRequest(new { message = "Unknown action: " + req.Action });

        var adminId = GetCurrentUserId();
        var adminName = _userManager.GetUserById(adminId)?.Username ?? adminId.ToString();
        var actorIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;

        int processed = 0;
        foreach (var uid in req.UserIds.Distinct())
        {
            try
            {
                switch (req.Action.ToLowerInvariant())
                {
                    // SEC-M8: full reset — wipes EVERY 2FA artifact for the user.
                    case "reset_2fa":
                    case "disable_2fa": // legacy alias
                        await _store.MutateAsync(uid, ud =>
                        {
                            ud.TotpEnabled = false;
                            ud.TotpVerified = false;
                            ud.EncryptedTotpSecret = null;
                            ud.RecoveryCodes.Clear();
                            ud.RecoveryCodesGeneratedAt = null;
                            ud.Passkeys.Clear();
                            ud.AppPasswords.Clear();
                            ud.RegisteredDeviceIds.Clear();
                            ud.PairedDevices.Clear();
                            ud.TrustedDevices.Clear();
                            ud.SeenContexts.Clear();
                            ud.EmailOtpPreferred = false;
                            ud.ForceRecoveryOnNextLogin = false;
                        }).ConfigureAwait(false);
                        _challengeStore.WipeAllForUser(uid);
                        break;
                    case "rotate_recovery":
                        var (plain, records) = _recoveryCodes.GenerateCodes();
                        await _store.MutateAsync(uid, ud =>
                        {
                            ud.RecoveryCodes = records;
                            ud.RecoveryCodesGeneratedAt = DateTime.UtcNow;
                        }).ConfigureAwait(false);
                        // Plaintext is NOT returned in bulk — admin must reset per user to see codes.
                        break;
                    case "revoke_paired_devices":
                        await _store.MutateAsync(uid, ud => ud.PairedDevices.Clear()).ConfigureAwait(false);
                        break;
                    case "revoke_trusted_browsers":
                        await _store.MutateAsync(uid, ud => ud.TrustedDevices.Clear()).ConfigureAwait(false);
                        break;
                    case "force_logout":
                        await _sessionTerm.LogoutAllForUserAsync(uid).ConfigureAwait(false);
                        break;
                }
                // SEC-L1: per-user audit entry so the hash chain reflects bulk
                // admin actions — without this the audit log silently drops them.
                await _store.AddAuditEntryAsync(new AuditEntry
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = uid,
                    Username = _userManager.GetUserById(uid)?.Username ?? uid.ToString(),
                    RemoteIp = actorIp,
                    Result = AuditResult.ConfigChanged,
                    Method = $"bulk:{req.Action.ToLowerInvariant()}_by:{adminName}",
                }).ConfigureAwait(false);
                processed++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Bulk action {Action} failed for user {UserId}", req.Action, uid);
            }
        }
        return Ok(new { processed, action = req.Action });
    }

    // =========================================================================
    // v1.4 — Recovery codes PDF
    // =========================================================================

    public class RecoveryPdfRequest { public List<string> Codes { get; set; } = new(); }

    /// <summary>Render the just-generated recovery codes as a PDF the user can
    /// print + save. Codes must be supplied by the caller (we don't keep
    /// plaintext) — the Setup page POSTs back what /Generate returned.</summary>
    [HttpPost("RecoveryCodes/Pdf")]
    [Authorize]
    public IActionResult GenerateRecoveryPdf([FromBody, Required] RecoveryPdfRequest req)
    {
        if (req.Codes.Count == 0) return BadRequest(new { message = "No codes provided" });
        // SEC-M5: cap inputs so a logged-in user can't ask for a 10000-code
        // PDF as a memory/CPU resource hog.
        if (req.Codes.Count > 50) return BadRequest(new { message = "Too many codes" });
        foreach (var c in req.Codes)
        {
            if (c is null || c.Length > 64) return BadRequest(new { message = "Code too long" });
        }
        var userId = GetCurrentUserId();
        var username = _userManager.GetUserById(userId)?.Username ?? userId.ToString();
        // Sanitize username for use inside Content-Disposition: header injection
        // (\r\n) and filename-unsafe chars stripped; if nothing useful remains,
        // fall back to the user GUID.
        var safeName = new string(username.Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.').ToArray());
        if (string.IsNullOrEmpty(safeName)) safeName = userId.ToString("N");
        var serverName = "Jellyfin";
        var bytes = _recoveryPdf.Render(username, req.Codes, serverName);
        Response.Headers["Content-Disposition"] = $"attachment; filename=jellyfin-2fa-recovery-{safeName}.pdf";
        return File(bytes, "application/pdf");
    }

    // =========================================================================
    // v1.4 — Diagnostics + Stats + Export + Rate-limit observability
    // =========================================================================

    [HttpGet("Diagnostics")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> RunDiagnostics()
    {
        var checks = await _diagnostics.RunAsync().ConfigureAwait(false);
        return Ok(checks.Select(c => new { id = c.Id, label = c.Label, status = c.Status.ToString(), detail = c.Detail }));
    }

    [HttpGet("Stats")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> GetStats()
    {
        var s = await _stats.ComputeAsync().ConfigureAwait(false);
        return Ok(s);
    }

    [HttpGet("Users/{userId:guid}/Export")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> ExportUser([FromRoute] Guid userId)
    {
        var data = await _userExport.BuildExportAsync(userId).ConfigureAwait(false);
        var json = System.Text.Json.JsonSerializer.Serialize(data, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        Response.Headers["Content-Disposition"] = $"attachment; filename=2fa-export-{userId:N}.json";
        return Content(json, "application/json");
    }

    [HttpGet("RateLimitTrips")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetRateLimitTrips() => Ok(_rateLimiter.RecentTrips());

    // =========================================================================
    // v1.4 — TOTP self-service rotate (current code + recovery code)
    // =========================================================================

    public class TotpRotateRequest
    {
        public string CurrentCode { get; set; } = string.Empty;
        public string RecoveryCode { get; set; } = string.Empty;
    }

    [HttpPost("Setup/Totp/Rotate")]
    [Authorize]
    public async Task<IActionResult> RotateTotp([FromBody, Required] TotpRotateRequest req)
    {
        var userId = GetCurrentUserId();
        var user = _userManager.GetUserById(userId);
        if (user is null) return Unauthorized();

        if (await _store.IsLockedOutAsync(userId).ConfigureAwait(false))
            return StatusCode(429, new { message = "Account locked" });

        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (!data.TotpEnabled || string.IsNullOrEmpty(data.EncryptedTotpSecret))
            return BadRequest(new { message = "TOTP not enabled" });

        if (!_totpService.ValidateCode(data.EncryptedTotpSecret, req.CurrentCode, userId.ToString("N")))
        {
            await _store.RecordFailedAttemptAsync(userId).ConfigureAwait(false);
            return Unauthorized(new { message = "Current TOTP code is invalid" });
        }
        var rIdx = FindRecoveryCodeIndex(data, req.RecoveryCode);
        if (rIdx < 0)
        {
            await _store.RecordFailedAttemptAsync(userId).ConfigureAwait(false);
            return Unauthorized(new { message = "Recovery code is invalid" });
        }

        var (newSecret, newQr, newManual) = _totpService.GenerateSecret(user.Username);
        await _store.MutateAsync(userId, ud =>
        {
            ud.EncryptedTotpSecret = newSecret;
            // Mark the recovery code we used as consumed so the same one
            // can't be replayed.
            if (rIdx < ud.RecoveryCodes.Count) ud.RecoveryCodes[rIdx].Used = true;
            if (rIdx < ud.RecoveryCodes.Count) ud.RecoveryCodes[rIdx].UsedAt = DateTime.UtcNow;
            ud.TotpVerified = false; // user must re-confirm with the new authenticator
        }).ConfigureAwait(false);

        var rotateIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = user.Username,
            RemoteIp = rotateIp,
            Result = AuditResult.ConfigChanged,
            Method = "totp_rotated",
        }).ConfigureAwait(false);
        // SEC-M3: fire a notification so the legitimate user notices if an
        // attacker who already has both factors silently rotates their seed.
        try { await _notificationService.NotifyTotpRotatedAsync(user.Username, rotateIp).ConfigureAwait(false); }
        catch (Exception ex) { _logger.LogDebug(ex, "[2FA] TOTP rotate notification failed"); }

        return Ok(new { qrCode = newQr, manualEntryKey = newManual });
    }

    // =========================================================================
    // v1.4 — QR-pair-from-phone (reverse of TV pairing flow)
    // Desktop browser asks for a signed pair-token, renders as QR. Phone
    // (already signed in) scans → existing /PairConfirm endpoint completes.
    // =========================================================================

    /// <summary>Issues a signed pair-confirm token for the CURRENT browser
    /// (so a phone scanning its QR can mark this browser as a paired device).
    /// Reuses the existing PairConfirm verification path.</summary>
    [HttpGet("Setup/QrPair/Begin")]
    [Authorize]
    public IActionResult QrPairBegin()
    {
        var userId = GetCurrentUserId();
        var deviceId = HttpContext.Request.Headers["X-Emby-Device-Id"].FirstOrDefault()
            ?? TwoFactorEnforcementMiddleware.ParseEmbyAuth(
                HttpContext.Request.Headers["X-Emby-Authorization"].FirstOrDefault(), "DeviceId")
            ?? string.Empty;
        if (string.IsNullOrEmpty(deviceId))
            return BadRequest(new { message = "Cannot determine current device id" });

        // v1.4 SEC-H4: cross-check that the deviceId in headers matches a real
        // device record for the calling user — without this, a signed-in user
        // could mint a QR token for an arbitrary deviceId and trick someone
        // into approving a device that isn't theirs.
        var token = HttpContext.Request.Headers["X-Emby-Token"].FirstOrDefault();
        var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
        var ownsDevice = devices.Items.Any(d =>
            !string.IsNullOrEmpty(d.DeviceId)
            && string.Equals(d.DeviceId, deviceId, StringComparison.Ordinal)
            && (string.IsNullOrEmpty(token) || string.Equals(d.AccessToken, token, StringComparison.Ordinal)));
        if (!ownsDevice)
            return Unauthorized(new { message = "Caller does not own the supplied deviceId" });

        var expiry = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var payload = $"pair|{userId:N}|{deviceId}|{expiry}";
        var sig = _cookieSigner.Sign(payload);
        var combined = payload + "." + sig;
        var b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(combined))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var scheme = HttpContext.Request.IsHttps ? "https" : "http";
        var host = HttpContext.Request.Host.Value;
        var url = $"{scheme}://{host}/TwoFactorAuth/PairConfirm?token={Uri.EscapeDataString(b64)}";
        return Ok(new { url, expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry) });
    }

    // =========================================================================
    // v1.4 — Per-user max concurrent sessions (admin override)
    // =========================================================================

    public class MaxSessionsRequest { public int? Max { get; set; } }

    [HttpPut("Users/{userId:guid}/MaxSessions")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> SetMaxSessions([FromRoute] Guid userId, [FromBody, Required] MaxSessionsRequest req)
    {
        if (req.Max.HasValue && (req.Max.Value < 0 || req.Max.Value > 100))
            return BadRequest(new { message = "Max must be 0-100 or null" });
        await _store.MutateAsync(userId, ud => ud.MaxConcurrentSessions = req.Max).ConfigureAwait(false);
        return Ok();
    }

    // =========================================================================
    // v1.4 — Webhook test ping (admin)
    // =========================================================================

    [HttpPost("Admin/WebhookTest")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> TestWebhook()
    {
        // SEC-L9: rate-limit so admin spam-clicking the test button can't DoS
        // their own webhook receiver (or be used to amplify pings from a
        // compromised admin session). 5/minute is plenty for genuine testing.
        var rl = _rateLimiter.CheckAndRecord("webhook_test", 5, TimeSpan.FromMinutes(1));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString());
            return StatusCode(429, new { message = $"Too many test requests. Retry in {rl.retryAfterSeconds}s." });
        }
        await _notificationService.NotifyLoginAttemptAsync("__test_user__", "127.0.0.1", "Webhook test", true).ConfigureAwait(false);
        return Ok(new { message = "Test event dispatched. Check your webhook receiver." });
    }
}

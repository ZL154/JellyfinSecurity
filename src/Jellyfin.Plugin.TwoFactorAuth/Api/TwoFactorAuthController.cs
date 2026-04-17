using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data.Queries;
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
                        secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[2FA] Failed to decrypt TOTP secret for {Name}", req.Username);
                        return StatusCode(500, new { message = "Failed to decrypt TOTP secret. Please re-enroll 2FA." });
                    }

                    if (_totpService.ValidateCode(secret, req.Code, user.Id.ToString()))
                    {
                        codeValid = true;
                        usedMethod = "totp";
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
                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

                // v2 cookie: deviceId and expiry are signed into the payload so
                // (a) a stolen cookie can't be replayed with an attacker-chosen
                // X-Emby-Device-Id header and (b) an attacker who tampers with
                // the trust record file can't extend the window.
                var expiryUnix = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds();
                var deviceB64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(deviceId ?? string.Empty))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                var cookieValue = $"{user.Id:N}.{trustRecord.Id}.{deviceB64}.{expiryUnix}";
                var hmac = _cookieSigner.Sign(cookieValue);
                Response.Cookies.Append("__2fa_trust", $"{cookieValue}.{hmac}", new CookieOptions
                {
                    HttpOnly = true,
                    Secure = HttpContext.Request.IsHttps, // Browsers reject Secure on plain http localhost
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(30),
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

        if (string.Equals(request.Method, "email", StringComparison.OrdinalIgnoreCase))
        {
            valid = _emailOtpService.ValidateCode(request.ChallengeToken, request.Code);
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
            try { secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret); }
            catch { return StatusCode(500, new { message = "TOTP secret is corrupted. Re-enroll 2FA." }); }
            valid = _totpService.ValidateCode(secret, request.Code, challenge.UserId.ToString());
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
        var encryptedSecret = _totpService.EncryptSecret(secret);

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        userData.TotpEnabled = true;
        userData.TotpVerified = false;
        userData.EncryptedTotpSecret = encryptedSecret;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

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

        var decryptedSecret = _totpService.DecryptSecret(userData.EncryptedTotpSecret);
        var valid = _totpService.ValidateCode(decryptedSecret, request.Code, userId.ToString());

        if (!valid)
        {
            return BadRequest("Invalid TOTP code");
        }

        userData.TotpVerified = true;
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
}

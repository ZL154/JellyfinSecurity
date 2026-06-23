using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Data.Queries;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
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
    private readonly IpBanService _ipBans;
    private readonly IpAllowlistService _allowlist;
    private readonly StepUpService _stepUp;
    private readonly SecurityScoreService _scoreService;
    private readonly ConfigExportService _export;
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
        IpBanService ipBans,
        IpAllowlistService allowlist,
        StepUpService stepUp,
        SecurityScoreService scoreService,
        ConfigExportService configExport,
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
        _ipBans = ipBans;
        _allowlist = allowlist;
        _stepUp = stepUp;
        _scoreService = scoreService;
        _export = configExport;
        _logger = logger;
    }

    // -------------------------------------------------------------------------
    // Helper: get current authenticated user ID from JWT claims
    // -------------------------------------------------------------------------

    // v2.5.0: canonical supported-language allowlist. Kept as a static
    // readonly field (CA1861) so the array isn't reallocated on every
    // /public-config or /preferences hit.
    private static readonly string[] SupportedLanguages = { "en", "de", "es", "fr", "it", "ja", "pt", "zh" };

    private Guid GetCurrentUserId()
    {
        var claim = User.FindFirst("Jellyfin-UserId");
        if (claim != null && Guid.TryParse(claim.Value, out var userId))
        {
            return userId;
        }

        throw new UnauthorizedAccessException();
    }

    /// <summary>v2.5.0: returns true if the current caller is an admin
    /// (via PermissionKind.IsAdministrator on their Jellyfin user) OR is
    /// the same user identified by <paramref name="userId"/>. Used by the
    /// per-user preferences endpoints so non-admins can manage their own
    /// language without granting them admin-only routes.</summary>
    private bool IsAuthorizedForUser(Guid userId)
    {
        Guid current;
        try
        {
            current = GetCurrentUserId();
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }

        if (current == userId) return true;

        // Admin check mirrors how AdminForceLogout / dashboard enumeration
        // identify admins — the IsAdministrator permission on the Jellyfin
        // user record. The [Authorize] policy "RequiresElevation" reads the
        // same bit, so this stays consistent with the rest of the controller.
        try
        {
            var ju = _userManager.GetUserById(current);
            if (ju is not null && ju.HasPermission(PermissionKind.IsAdministrator))
            {
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] IsAuthorizedForUser admin probe failed — denying");
        }

        return false;
    }

    /// <summary>v2.5.0: returns a 403-challenge ActionResult if this admin needs
    /// step-up for the action and hasn't got a valid token; null if allowed.</summary>
    private ActionResult? StepUpGuard(StepUpAction action)
    {
        var adminId = GetCurrentUserId();
        if (_stepUp.NeedsStepUpToken(adminId, action))
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new { message = "Step-up authentication required.", stepUpRequired = true });
        }
        return null;
    }

    /// <summary>SECURITY [v2.5.6] (ext review self-service-takeover, round-5
    /// fix D): user-self step-up gate. Prevents a stolen logged-in session
    /// from silently taking over the account by adding/replacing the
    /// attacker's own 2FA factor. Honors the tri-state
    /// <see cref="Configuration.SelfServiceStepUpMode"/>:
    ///   * Off → allow (legacy, accepted risk).
    ///   * UserChoice → enforce only if the user has opted in via
    ///     <see cref="Models.UserTwoFactorData.RequireStepUpForChanges"/>.
    ///   * Forced → always enforce when user has existing 2FA.
    /// Users with no existing 2FA are exempt under every mode — first-time
    /// enrollment has no prior factor to step up from.
    /// Returns null when allowed, or a 403 ActionResult to short-circuit.</summary>
    private async Task<ActionResult?> EnforceSelfServiceStepUpAsync(Guid userId, string? code, string? stepUpToken = null)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null) return null;

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        // SECURITY [v2.5.9]: "existing 2FA" must count EVERY factor that
        // currently protects the account, not just TOTP/passkeys. v2.5.7
        // added OIDC step-up but this gate didn't recognise OIDC-only or
        // email-only users, so a hijacked session for those users could
        // add/replace the attacker's own factor with no step-up. Include:
        //   - SSO/OIDC links (the user authenticates via an IdP)
        //   - email OTP, when the server has it enabled and the user relies
        //     on it (EmailOtpPreferred)
        var emailFactorActive = config.EmailOtpEnabled && userData.EmailOtpPreferred;
        var hasExisting2fa = (userData.TotpEnabled && userData.TotpVerified)
                             || userData.Passkeys.Count > 0
                             || userData.SsoLinks.Count > 0
                             || emailFactorActive;
        if (!hasExisting2fa) return null;

        var modeRequiresStepUp = config.SelfServiceStepUpMode switch
        {
            Configuration.SelfServiceStepUpMode.Off => false,
            Configuration.SelfServiceStepUpMode.UserChoice => userData.RequireStepUpForChanges,
            Configuration.SelfServiceStepUpMode.Forced => true,
            _ => true,
        };
        if (!modeRequiresStepUp) return null;

        // [v2.5.6] (round-5c): single-use step-up token path. The UI calls
        // /StepUp/UserCodeVerify or /StepUp/UserPasskeyVerify to exchange a
        // fresh factor proof for a 60-second token, then submits the token
        // here. Lets the prompt offer "TOTP / recovery code / passkey" as
        // alternative verification methods.
        if (_challengeStore.ConsumeUserStepUpToken(stepUpToken, userId)) return null;

        // [v2.5.6] (round-5d): also accept an email step-up code submitted
        // directly in `code` after the UI clicked "Send code by email".
        // EmailOtpService.ValidateStepUpCode does the single-use consume so
        // an attacker can't replay the same email OTP.
        // SECURITY [v2.5.9] (audit medium): rate-limit the user-self step-up
        // CODE path. The admin StepUp/Verify and the login verify path each
        // have a per-user limiter; this gate didn't — letting a hijacked
        // (non-elevated) session brute-force the 6-digit TOTP step-up code to
        // mint factor changes without ever tripping a limiter or lockout.
        // 15 attempts / 15 min per user, mirroring "verify_user:".
        if (!string.IsNullOrWhiteSpace(code))
        {
            var ssRl = _rateLimiter.CheckAndRecord("stepup_self:" + userId.ToString("N"), 15, TimeSpan.FromMinutes(15));
            if (!ssRl.allowed)
            {
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = $"Too many verification attempts. Try again in {ssRl.retryAfterSeconds} seconds.",
                    stepUpRequired = true,
                });
            }
        }

        var ok = !string.IsNullOrWhiteSpace(code)
                 && (_stepUp.VerifyUserCode(userData, code!) || _emailOtpService.ValidateStepUpCode(userId, code!));
        if (!ok)
        {
            await _store.RecordFailedAttemptAsync(userId).ConfigureAwait(false);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "A current authenticator or recovery code is required to modify two-factor settings.",
                stepUpRequired = true,
                twoFactorRequired = true,
            });
        }

        // Success — clear the step-up attempt counter for this user.
        _rateLimiter.Reset("stepup_self:" + userId.ToString("N"));

        // VerifyUserCode may have marked a recovery code as Used on the
        // local clone (and bumped LastUsedTotpStep). Persist atomically so
        // a second concurrent step-up can't replay the same code.
        await _store.MutateAsync(userId, ud =>
        {
            foreach (var cloneCode in userData.RecoveryCodes)
            {
                if (!cloneCode.Used) continue;
                if (string.IsNullOrEmpty(cloneCode.Hash)) continue;
                var match = ud.RecoveryCodes.FirstOrDefault(c =>
                    string.Equals(c.Hash, cloneCode.Hash, StringComparison.Ordinal) && !c.Used);
                if (match is not null)
                {
                    match.Used = true;
                    match.UsedAt = cloneCode.UsedAt ?? DateTime.UtcNow;
                }
            }
            if (userData.LastUsedTotpStep > ud.LastUsedTotpStep)
            {
                ud.LastUsedTotpStep = userData.LastUsedTotpStep;
            }
        }).ConfigureAwait(false);

        return null;
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

    [HttpGet("Challenge/Info")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(ChallengeInfoResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ActionResult<ChallengeInfoResponse> GetChallengeInfo([FromQuery] string token)
    {
        var challenge = _challengeStore.GetChallenge(token);
        if (challenge is null)
        {
            return BadRequest(new { message = "Invalid or expired challenge." });
        }

        return Ok(new ChallengeInfoResponse
        {
            Username = challenge.Username,
            Methods = challenge.AvailableMethods,
            EnrollmentRequired = challenge.EnrollmentRequired,
            ExpiresAt = challenge.ExpiresAt,
        });
    }

    [HttpPost("Enroll/Totp/Begin")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(TotpSetupResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<TotpSetupResponse>> BeginForcedTotpEnrollment([FromBody, Required] ChallengeTokenRequest request)
    {
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_ipBans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null || !challenge.EnrollmentRequired)
        {
            return BadRequest(new { message = "Invalid or expired enrollment challenge." });
        }

        if (!await _allowlist.IsAllowedAsync(challenge.UserId, clientIp).ConfigureAwait(false))
        {
            _ipBans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        var rl = _rateLimiter.CheckAndRecord("enroll_begin:" + request.ChallengeToken, 5, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many setup attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        if (userData.TotpVerified || userData.Passkeys.Count > 0)
        {
            return BadRequest(new { message = "This account already has a second factor." });
        }

        var (secret, qrCodeBase64, manualEntryKey) = _totpService.GenerateSecret(challenge.Username);
        // v2.4.1: only stash the secret here. TotpEnabled stays false until
        // Confirm verifies a code. Without this, a user who clicks Begin
        // Setup then navigates away gets stranded: TotpEnabled=true makes
        // the middleware treat them as enrolled, but TotpVerified=false
        // means "totp" isn't offered as a method — so on next sign-in they
        // get an email-only challenge with no way to actually use it.
        // SECURITY [v2.5.6] (F4): MutateAsync for atomic enrollment-stash.
        var encryptedSecretForced = _totpService.EncryptSecret(secret, challenge.UserId);
        await _store.MutateAsync(challenge.UserId, ud =>
        {
            ud.TotpVerified = false;
            ud.EncryptedTotpSecret = encryptedSecretForced;
            ud.LastUsedTotpStep = 0;
        }).ConfigureAwait(false);
        _totpService.ResetReplayCache(challenge.UserId.ToString());

        return Ok(new TotpSetupResponse
        {
            SecretKey = secret,
            QrCodeBase64 = qrCodeBase64,
            ManualEntryKey = manualEntryKey,
        });
    }

    [HttpPost("Enroll/Totp/Confirm")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> ConfirmForcedTotpEnrollment([FromBody, Required] ForcedEnrollmentConfirmRequest request)
    {
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_ipBans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null || !challenge.EnrollmentRequired)
        {
            return BadRequest(new { message = "Invalid or expired enrollment challenge." });
        }

        if (challenge.AttemptCount >= 5)
        {
            _challengeStore.ConsumeChallenge(request.ChallengeToken);
            _ipBans.RecordFailure(clientIp);
            return Unauthorized(new { message = "Too many failed attempts on this challenge. Restart sign-in." });
        }

        if (!await _allowlist.IsAllowedAsync(challenge.UserId, clientIp).ConfigureAwait(false))
        {
            _ipBans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        var rl = _rateLimiter.CheckAndRecord("enroll_confirm:" + clientIp, 10, TimeSpan.FromMinutes(1));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
        {
            return BadRequest(new { message = "TOTP setup has not been started." });
        }

        string secret;
        try
        {
            secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, challenge.UserId);
        }
        catch
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = "TOTP secret is corrupted. Restart setup." });
        }

        var valid = _totpService.ValidateCode(
            secret,
            request.Code,
            challenge.UserId.ToString(),
            persistedFloor: 0,
            out var acceptedStep);
        if (!valid)
        {
            challenge.IncrementAttempt();
            await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
            _ipBans.RecordFailure(clientIp);
            return Unauthorized(new { message = "Invalid authenticator code." });
        }

        // SECURITY [v2.5.6] (F4): atomic enrollment-confirm. Combines the
        // TOTP flip + the optional TrustDevice insert into a single
        // MutateAsync so two concurrent /Enroll/Confirm with TrustDevice
        // can't both insert and lose one.
        string? deviceToken = null;
        Models.TrustedDevice? newTrust = null;
        string? rawTokenLocal = null;
        if (request.TrustDevice && !string.IsNullOrEmpty(challenge.DeviceId))
        {
            (rawTokenLocal, newTrust) = _deviceTokenService.CreateDeviceToken(
                challenge.DeviceId,
                challenge.DeviceName ?? challenge.DeviceId);
        }
        await _store.MutateAsync(challenge.UserId, ud =>
        {
            ud.TotpEnabled = true;
            ud.TotpVerified = true;
            if (acceptedStep > ud.LastUsedTotpStep) ud.LastUsedTotpStep = acceptedStep;
            if (newTrust is not null)
            {
                ud.TrustedDevices.Add(newTrust);
                EnforceTrustedDeviceCap(ud);
            }
        }).ConfigureAwait(false);
        if (rawTokenLocal is not null) deviceToken = rawTokenLocal;

        _challengeStore.ConsumeChallenge(request.ChallengeToken);
        await _store.ResetFailedAttemptsAsync(challenge.UserId).ConfigureAwait(false);
        _rateLimiter.Reset("enroll_confirm:" + clientIp);
        _ipBans.RecordSuccess(clientIp);

        if (!string.IsNullOrEmpty(challenge.DeviceId))
        {
            _challengeStore.MarkDevicePreVerified(challenge.UserId, challenge.DeviceId);
            _pendingPairings.Remove(challenge.UserId, challenge.DeviceId);
        }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = challenge.UserId,
            Username = challenge.Username,
            RemoteIp = challenge.RemoteIp ?? clientIp,
            DeviceId = challenge.DeviceId ?? string.Empty,
            DeviceName = challenge.DeviceName ?? string.Empty,
            Result = AuditResult.Success,
            Method = "forced_enroll_totp",
        }).ConfigureAwait(false);

        if (string.IsNullOrEmpty(challenge.PendingAuthResponse))
        {
            return Ok(new { message = "Two-factor setup complete. Sign in again to continue." });
        }

        UnblockAccessTokenFromPendingAuthResponse(challenge.PendingAuthResponse, challenge.Username);
        if (deviceToken is not null)
        {
            Response.Headers.Append("X-TwoFactor-Device-Token", deviceToken);
        }

        return Content(challenge.PendingAuthResponse, "application/json");
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
            var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
            if (_ipBans.CheckBanned(clientIp) is { } ban)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    message = "This IP address is temporarily blocked.",
                    expiresAt = ban.ExpiresAt,
                });
            }

            var rl = _rateLimiter.CheckAndRecord("auth:" + clientIp, 10, TimeSpan.FromMinutes(1));
            if (!rl.allowed)
            {
                Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
                    retryAfterSeconds = rl.retryAfterSeconds,
                });
            }

            // [v2.5.12] (#82, cpb34): only the username is required. Jellyfin
            // supports passwordless users (admin-disabled password), who sign in
            // with a blank password at the standard portal — so the 2FA portal
            // must accept a blank password too. Jellyfin's own auth path below
            // still rejects a blank password for users who DO have one, so this
            // doesn't weaken anyone's real password policy.
            if (req is null || string.IsNullOrEmpty(req.Username))
            {
                return BadRequest(new { message = "Username is required." });
            }

            // SEC-L8: cap submitted credential field lengths. Jellyfin's auth
            // path runs PBKDF2 internally; an unbounded body lets an attacker
            // burn server CPU per request. 1KB password / 256B username covers
            // realistic upper bounds (long passphrases ~200 chars) while
            // killing the DoS vector.
            if ((req.Password?.Length ?? 0) > 1024
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
                // SECURITY [v2.5.5] (Finding 20): equalize timing so an
                // attacker can't enumerate which usernames exist by measuring
                // response time. Perform an equivalent GetUserDataAsync call
                // with Guid.Empty so the no-user path costs the same as the
                // user-exists-but-wrong-code path.
                _ = await _store.GetUserDataAsync(Guid.Empty).ConfigureAwait(false);
                _ipBans.RecordFailure(clientIp);
                // SECURITY [v2.5.9] (audit low): identical message for every
                // auth failure (bad user / bad password / bad code) so the
                // response can't be used as a 2FA-code-validity oracle.
                return Unauthorized(new { message = "Invalid username, password, or verification code." });
            }

            var userData = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);
            if (!await _allowlist.IsAllowedAsync(user.Id, clientIp).ConfigureAwait(false))
            {
                _ipBans.RecordFailure(clientIp);
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    message = "Sign-in is not allowed from this network.",
                });
            }

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
            var hasPasskey = userData.Passkeys.Count > 0;
            var isAdmin = user.HasPermission(PermissionKind.IsAdministrator);
            var config = Plugin.Instance?.Configuration;

            // SECURITY [v2.5.6]: passkey-only users (passkey enrolled, no
            // TOTP) cannot sign in via this endpoint with just a password.
            // The endpoint only verifies TOTP / recovery / email-OTP as the
            // second factor; passkey assertions go through
            // /TwoFactorAuth/Passkey/LoginBegin + /LoginComplete. Without
            // this guard, a passkey-only account was bypassable with just a
            // password — the prior `requiresPostPasswordChallenge` formula
            // treated "no TOTP" as "no 2FA" and skipped the challenge.
            if (!totpEnabled && hasPasskey)
            {
                _ipBans.RecordFailure(clientIp);
                return Unauthorized(new
                {
                    message = "This account is configured for passkey sign-in. Use the passkey flow.",
                });
            }

            // SECURITY [v2.5.6]: use the modern `ShouldEnforceFor(isAdmin)`
            // helper which honours both the legacy `RequireForAllUsers`
            // (true ⇒ All) AND the v2.4+ `EnforcementScope` (Admins / All).
            // Prior code only checked the legacy flag, leaving a bypass for
            // installations that opted into the per-role policy with the
            // legacy flag unset.
            var requiresPostPasswordChallenge = !totpEnabled && (config?.ShouldEnforceFor(isAdmin) == true);

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
                    _ipBans.RecordFailure(clientIp);
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
                        _ipBans.RecordFailure(clientIp);
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
                    _ipBans.RecordFailure(clientIp);
                    await _store.AddAuditEntryAsync(new AuditEntry
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = user.Id,
                        Username = user.Username ?? string.Empty,
                        RemoteIp = clientIp,
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
                RemoteEndPoint = clientIp,
            };

            // Pre-verify must be set BEFORE AuthenticateNewSession because SessionStarted
            // fires during that call. Scoped to (user, device) so sibling devices can't
            // piggy-back on the 2-minute window and bypass 2FA silently.
            if (!requiresPostPasswordChallenge)
            {
                _challengeStore.MarkDevicePreVerified(user.Id, deviceId);
            }

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
                    _ipBans.RecordFailure(clientIp);
                    // SECURITY [v2.5.9] (audit low): identical message for every
                // auth failure (bad user / bad password / bad code) so the
                // response can't be used as a 2FA-code-validity oracle.
                return Unauthorized(new { message = "Invalid username, password, or verification code." });
                }
            }
            finally
            {
                if (!authSucceeded && !requiresPostPasswordChallenge)
                {
                    _challengeStore.ConsumeDevicePreVerified(user.Id, deviceId);
                }
            }

            if (requiresPostPasswordChallenge)
            {
                // [v2.5.6] (round-5 fix B): treat a configured email + email
                // OTP globally enabled as a valid sole 2FA factor. Lets users
                // who never want TOTP and don't have a passkey complete
                // sign-in via email OTP instead of being forced into TOTP
                // enrollment.
                var hasEmailFactor = config?.EmailOtpEnabled == true
                    && !string.IsNullOrEmpty(config?.GetUserEmail(user.Id.ToString("N")));
                var enrollmentRequired = userData.Passkeys.Count == 0 && !hasEmailFactor;
                var methods = new List<string>();
                if (enrollmentRequired)
                {
                    methods.Add("enroll");
                }
                else
                {
                    if (userData.Passkeys.Count > 0) methods.Add("passkey");
                    if (config?.EmailOtpEnabled == true) methods.Add("email");
                    if (methods.Count == 0)
                    {
                        methods.Add("enroll");
                        enrollmentRequired = true;
                    }
                }

                var challenge = _challengeStore.CreateChallenge(
                    user.Id,
                    user.Username ?? req.Username,
                    methods,
                    deviceId,
                    deviceName,
                    clientIp,
                    enrollmentRequired);
                challenge.PendingAuthResponse = System.Text.Json.JsonSerializer.Serialize(result);
                if (!string.IsNullOrEmpty(result.AccessToken))
                {
                    _challengeStore.BlockToken(result.AccessToken);
                }

                await _store.AddAuditEntryAsync(new AuditEntry
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = user.Id,
                    Username = user.Username ?? req.Username,
                    RemoteIp = clientIp,
                    DeviceId = deviceId ?? string.Empty,
                    DeviceName = deviceName,
                    Result = AuditResult.ChallengeIssued,
                    Method = string.Join(",", methods),
                }).ConfigureAwait(false);

                return Unauthorized(new TwoFactorRequiredResponse
                {
                    TwoFactorRequired = true,
                    ChallengeToken = challenge.Token,
                    Methods = methods,
                    EnrollmentRequired = enrollmentRequired,
                    ChallengePageUrl = $"/TwoFactorAuth/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
                    EnrollmentPageUrl = $"/TwoFactorAuth/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
                });
            }

            // --- Step 3: Auth succeeded. Now do the state mutations (trust record, audit, etc.) ---
            _challengeStore.UnblockAllForUser(user.Id);
            // Mark the newly-minted access token as verified so the
            // SessionStarted handler's failsafe BlockToken doesn't re-block
            // it on reconnects 3+ minutes later (issue #27).
            if (!string.IsNullOrEmpty(result.AccessToken))
            {
                _challengeStore.MarkTokenVerified(result.AccessToken);
            }
            await _store.ResetFailedAttemptsAsync(user.Id).ConfigureAwait(false);
            _rateLimiter.Reset("auth:" + clientIp);
            _ipBans.RecordSuccess(clientIp);

            // Only create a trust cookie/record if the user actually completed 2FA.
            // Users without 2FA don't need a trust cookie — there's nothing to trust.
            if (totpEnabled && req.TrustDevice)
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
                // configurable in v1.4 (default 30 days, range 1-90). v2.5.0:
                // if the trust record carries IndefiniteTrust, the cookie is
                // issued with ~100yr expiry.
                DateTimeOffset cookieExpires;
                if (trustRecord.IndefiniteTrust)
                {
                    cookieExpires = DateTimeOffset.UtcNow.AddYears(100);
                }
                else
                {
                    var ttlDays = Math.Clamp(
                        Plugin.Instance?.Configuration?.TrustCookieTtlDays ?? 30, 1, 90);
                    cookieExpires = DateTimeOffset.UtcNow.AddDays(ttlDays);
                }
                var expiryUnix = cookieExpires.ToUnixTimeSeconds();
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
                    Expires = cookieExpires,
                    Path = "/",
                    IsEssential = true,
                });
            }

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = user.Id,
                Username = user.Username ?? string.Empty,
                RemoteIp = clientIp,
                DeviceId = deviceId ?? string.Empty,
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

    // [v2.5.9] (issue #64): also serve at an EXTENSION-LESS route. A CDN /
    // Cloudflare cache rule that matches "*.js" (and overrides our no-store
    // origin headers with a long edge TTL) freezes inject.js for days, so
    // client-side fixes never reach users behind a proxy. The "/inject" URL
    // doesn't match a ".js" rule, so it stays DYNAMIC/uncached and always
    // serves fresh. IndexHtmlInjectionMiddleware points the script tag here.
    [HttpGet("inject")]
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
        // [v2.5.9] (issue #64): Debug-level trace of which inject URL was
        // requested + the client UA — invaluable for diagnosing CDN/webview
        // caching of the injected script. Debug so it doesn't spam Info on
        // every login-page load.
        _logger.LogDebug("[2FA] inject served: path={Path}{Query} len={Len} ua={UA}",
            Request.Path.Value, Request.QueryString.Value, js.Length, Request.Headers.UserAgent.ToString());
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
        Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
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
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_ipBans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var rl = _rateLimiter.CheckAndRecord("verify:" + clientIp, 10, TimeSpan.FromMinutes(1));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
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

        // SECURITY [v2.5.5] (Finding 7): when RequireChallengeIpMatch is on,
        // reject /Verify if the submitting client is on a different /24
        // (IPv4) or /48 (IPv6) than the original challenge IP. Defence vs
        // challenge-token replay from a captured token. Defaults off because
        // reverse-proxy / CF Tunnel setups legitimately see the apparent
        // client IP shift between Authenticate and Verify even within one
        // valid user session.
        var requireIp = Plugin.Instance?.Configuration?.RequireChallengeIpMatch == true;
        if (requireIp && !string.IsNullOrEmpty(challenge.RemoteIp) && !string.IsNullOrEmpty(clientIp))
        {
            if (!SameIpPrefix(challenge.RemoteIp, clientIp))
            {
                _logger.LogWarning(
                    "[2FA] /Verify rejected: challenge issued from {ChIp} but verify came from {ClIp} (RequireChallengeIpMatch=ON)",
                    challenge.RemoteIp, clientIp);
                _ipBans.RecordFailure(clientIp);
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    message = "Challenge token cannot be verified from a different network.",
                });
            }
        }

        if (!await _allowlist.IsAllowedAsync(challenge.UserId, clientIp).ConfigureAwait(false))
        {
            _ipBans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        // Per-user rate limit on Verify — defense in depth against an attacker
        // using an IP rotator to sidestep the per-IP bucket. 15 attempts per 15
        // minutes matches the per-challenge 5-limit * typical churn without
        // locking out a flaky-connection legitimate user.
        var userRl = _rateLimiter.CheckAndRecord("verify_user:" + challenge.UserId.ToString("N"), 15, TimeSpan.FromMinutes(15));
        if (!userRl.allowed)
        {
            Response.Headers.Append("Retry-After", userRl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
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
            _ipBans.RecordFailure(clientIp);
            return Unauthorized(new { message = "Too many failed attempts on this challenge. Restart sign-in." });
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Account is locked out." });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        bool valid;
        int consumedRecoveryIdx = -1;

        // SECURITY [v2.5.6] (ext review #2): enforce challenge.AvailableMethods.
        // The challenge issuer encodes which methods are valid for THIS
        // challenge (e.g. TOTP-only when the user has only TOTP, or
        // recovery+email when the user is locked-to-recovery). Prior code
        // dispatched on request.Method without checking the allow-list,
        // letting a user submit method="recovery" against a challenge that
        // only offered "totp". This weakens recovery-only / enrollment-
        // required states.
        if (challenge.AvailableMethods is { Count: > 0 }
            && !challenge.AvailableMethods.Any(m =>
                string.Equals(m, request.Method, StringComparison.OrdinalIgnoreCase)))
        {
            _ipBans.RecordFailure(clientIp);
            return Unauthorized(new { message = "Verification method is not available for this challenge." });
        }

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
                challenge.IncrementAttempt();
                await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
                _ipBans.RecordFailure(clientIp);
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
        // SECURITY [v2.5.6] (U5): persist via MutateAsync diff-apply so two
        // concurrent /Verify requests using the same unused recovery code
        // can't both mark it Used on separate clones before either persists.
        // Match by Hash and only flip entries that the canonical store
        // still sees as unused — the loser-thread sees Used=true already
        // and the recovery code is consumed exactly once on disk.
        if (valid && consumedRecoveryIdx >= 0)
        {
            await _store.MutateAsync(challenge.UserId, ud =>
            {
                foreach (var cloneCode in userData.RecoveryCodes)
                {
                    if (!cloneCode.Used) continue;
                    if (string.IsNullOrEmpty(cloneCode.Hash)) continue;
                    var match = ud.RecoveryCodes.FirstOrDefault(c =>
                        string.Equals(c.Hash, cloneCode.Hash, StringComparison.Ordinal) && !c.Used);
                    if (match is not null)
                    {
                        match.Used = true;
                        match.UsedAt = cloneCode.UsedAt ?? DateTime.UtcNow;
                    }
                }
                if (!userData.ForceRecoveryOnNextLogin)
                {
                    ud.ForceRecoveryOnNextLogin = false;
                }
            }).ConfigureAwait(false);
        }
        else if (valid && lockedToRecovery)
        {
            await _store.MutateAsync(challenge.UserId, ud =>
            {
                if (!userData.ForceRecoveryOnNextLogin)
                {
                    ud.ForceRecoveryOnNextLogin = false;
                }
            }).ConfigureAwait(false);
        }

        if (!valid)
        {
            challenge.IncrementAttempt();
            await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
            _ipBans.RecordFailure(clientIp);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = challenge.UserId,
                Username = challenge.Username,
                RemoteIp = challenge.RemoteIp ?? string.Empty,
                DeviceId = challenge.DeviceId ?? string.Empty,
                DeviceName = challenge.DeviceName ?? string.Empty,
                Result = AuditResult.Failed,
                Method = (request.Method ?? string.Empty).Length > 32
                    ? (request.Method ?? string.Empty)[..32]
                    : (request.Method ?? string.Empty),
            }).ConfigureAwait(false);

            return Unauthorized(new { message = "Invalid 2FA code." });
        }

        _challengeStore.ConsumeChallenge(request.ChallengeToken);
        await _store.ResetFailedAttemptsAsync(challenge.UserId).ConfigureAwait(false);
        _rateLimiter.Reset("verify_user:" + challenge.UserId.ToString("N"));
        _rateLimiter.Reset("verify:" + clientIp);
        _ipBans.RecordSuccess(clientIp);

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
            Method = (request.Method ?? string.Empty).Length > 32
                ? (request.Method ?? string.Empty)[..32]
                : (request.Method ?? string.Empty),
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
            UnblockAccessTokenFromPendingAuthResponse(challenge.PendingAuthResponse, challenge.Username);

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

    // Reflection-based enumeration to dodge Jellyfin 10.11.9's
    // IUserManager.Users return-type ABI break. See issue #27 — the IL
    // call site compiled against 10.11.8 throws MissingMethodException on
    // a 10.11.9 host; reflection re-binds at runtime against either ABI.
    // Empty enumeration on any failure so admin endpoints degrade gracefully.
    private IEnumerable<User> EnumerateAllUsers()
    {
        // Jellyfin 10.11.10 renamed `IUserManager.Users` (property) →
        // `GetUsers()` (method). Try the method first; fall back to the
        // old property via string-named reflection for any older 10.11.x
        // host. `nameof(IUserManager.Users)` was the previous shim but
        // fails to COMPILE against 10.11.10 since the symbol is gone.
        IEnumerable? raw = null;
        try
        {
            var getUsersMethod = typeof(IUserManager).GetMethod("GetUsers", Type.EmptyTypes);
            if (getUsersMethod is not null)
            {
                raw = getUsersMethod.Invoke(_userManager, null) as IEnumerable;
            }
            else
            {
                var prop = typeof(IUserManager).GetProperty("Users");
                raw = prop?.GetValue(_userManager) as IEnumerable;
            }
        }
        catch (Exception)
        {
            yield break;
        }
        if (raw is null) yield break;
        foreach (var item in raw)
        {
            if (item is User u) yield return u;
        }
    }

    // v2.5.3 (issue #37 follow-up): same reflection shim applied to
    // ISessionManager.Sessions. Jellyfin 10.11.9+ also changed the return
    // type of this property — without this wrapper, the Overview dashboard
    // KPI count, the active-sessions admin endpoint, and the MySessions
    // device-enrichment endpoint would each throw MissingMethodException
    // on a 10.11.9+ host. Empty enumeration on any failure so the dashboard
    // / RevokeSession / MySessions endpoints degrade gracefully.
    private IEnumerable<SessionInfo> EnumerateSessions()
    {
        IEnumerable? raw;
        try
        {
            var prop = typeof(ISessionManager).GetProperty(nameof(ISessionManager.Sessions));
            raw = prop?.GetValue(_sessionManager) as IEnumerable;
        }
        catch (Exception)
        {
            yield break;
        }
        if (raw is null) yield break;
        foreach (var item in raw)
        {
            if (item is SessionInfo s) yield return s;
        }
    }

    private void UnblockAccessTokenFromPendingAuthResponse(string pendingAuthResponse, string username)
    {
        if (string.IsNullOrEmpty(pendingAuthResponse))
        {
            return;
        }

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(pendingAuthResponse);
            if (doc.RootElement.TryGetProperty("AccessToken", out var tokenElement)
                && tokenElement.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                var token = tokenElement.GetString();
                if (!string.IsNullOrEmpty(token))
                {
                    _challengeStore.UnblockToken(token);
                    // Mark verified so AuthenticationEventHandler's failsafe
                    // BlockToken doesn't re-block this token on subsequent
                    // SessionStarted events (websocket reconnects, new tabs).
                    // See ChallengeStore._verifiedTokens / issue #27.
                    _challengeStore.MarkTokenVerified(token);
                    _logger.LogInformation("[2FA] Unblocked access token for {User} after successful 2FA", username);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Could not parse stashed auth response to unblock token");
        }
    }

    // -------------------------------------------------------------------------
    // 2. POST /TwoFactorAuth/Setup/Totp [Authorize]
    // -------------------------------------------------------------------------

    [HttpPost("Setup/Totp")]
    [Authorize]
    [ProducesResponseType(typeof(TotpSetupResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<TotpSetupResponse>> SetupTotp([FromBody] StepUpCodeRequest? request = null)
    {
        var userId = GetCurrentUserId();

        // SECURITY [v2.5.6] (ext review self-service-takeover): a stolen
        // session must not be able to silently swap the user's TOTP secret
        // for the attacker's by calling this endpoint. If the user already
        // has 2FA enrolled, require a fresh current-factor proof.
        var stepUp = await EnforceSelfServiceStepUpAsync(userId, request?.Code, request?.StepUpToken).ConfigureAwait(false);
        if (stepUp is not null) return stepUp;

        var jellyfinUser = _userManager.GetUserById(userId);
        var username = jellyfinUser?.Username ?? userId.ToString();

        var (secret, qrCodeBase64, manualEntryKey) = _totpService.GenerateSecret(username);
        // SEC-M3: bind ciphertext to userId via AAD so an attacker with
        // file-system write access can't swap blobs across user records.
        var encryptedSecret = _totpService.EncryptSecret(secret, userId);

        // SECURITY [v2.5.6] (F4): MutateAsync for atomic enrollment-stash.
        // v2.4.1: stash the secret only. TotpEnabled flips to true on Confirm
        // (see ConfirmTotp). Otherwise a user who backs out of setup leaves
        // the account half-enrolled.
        await _store.MutateAsync(userId, ud =>
        {
            ud.TotpVerified = false;
            ud.EncryptedTotpSecret = encryptedSecret;
            // SEC-M4: reset replay floor on new secret.
            ud.LastUsedTotpStep = 0;
        }).ConfigureAwait(false);

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

        // v2.4.1: flip both flags here. SetupTotp stopped pre-setting
        // TotpEnabled to avoid the half-enrollment lockout, so Confirm is
        // the one place where TOTP is genuinely turned on.
        // SECURITY [v2.5.6] (F4): MutateAsync for atomic flip.
        await _store.MutateAsync(userId, ud =>
        {
            ud.TotpEnabled = true;
            ud.TotpVerified = true;
            if (acceptedStep > ud.LastUsedTotpStep) ud.LastUsedTotpStep = acceptedStep;
        }).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // 4. POST /TwoFactorAuth/Setup/Disable [Authorize]
    // -------------------------------------------------------------------------

    [HttpPost("Setup/Disable")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult> DisableTotp([FromBody] DisableRequest? request = null)
    {
        var userId = GetCurrentUserId();

        // v2.5.0: optional re-auth guard. When on, require a fresh TOTP/recovery
        // code before wiping. Verified against current user data.
        //
        // SECURITY [v2.5.6] (F2): although the wipe below clears RecoveryCodes
        // making reuse moot in the happy path, persist VerifyUserCode's
        // mutations (matched recovery-code Used + LastUsedTotpStep advance)
        // inside an atomic MutateAsync BEFORE the wipe runs. Closes the
        // narrow window where an exception between verify and wipe leaves
        // the recovery code re-usable, and also closes a parallel
        // concurrent-disable race where two threads both verify the same
        // code before either wipes.
        var config = Plugin.Instance?.Configuration;
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        // SECURITY [v2.5.9] (audit top-tier #5): DisableTotp is the most
        // destructive self-service action (the wipe below clears TOTP,
        // recovery codes, trusted + paired devices and app passwords), yet it
        // previously required a fresh factor ONLY when the legacy
        // RequireTwoFactorToDisable flag (default off) was set — so under
        // SelfServiceStepUpMode.Forced a hijacked session could still strip a
        // victim's 2FA with no step-up. Require verification when EITHER the
        // legacy flag is set OR the self-service mode demands it for a user
        // with any existing factor (TOTP / passkey / OIDC / email).
        var hasExisting2faForDisable = (userData.TotpEnabled && userData.TotpVerified)
            || userData.Passkeys.Count > 0
            || userData.SsoLinks.Count > 0
            || (config?.EmailOtpEnabled == true && userData.EmailOtpPreferred);
        var modeRequiresDisableStepUp = hasExisting2faForDisable && (config?.SelfServiceStepUpMode switch
        {
            Configuration.SelfServiceStepUpMode.Off => false,
            Configuration.SelfServiceStepUpMode.UserChoice => userData.RequireStepUpForChanges,
            Configuration.SelfServiceStepUpMode.Forced => true,
            _ => true,
        });
        if (config is { RequireTwoFactorToDisable: true } || modeRequiresDisableStepUp)
        {
            // [v2.5.6] (round-5c): accept either a fresh code or a step-up
            // token (issued by /StepUp/UserCodeVerify or
            // /StepUp/UserPasskeyVerify). The token path lets the UI offer
            // "use a passkey" as an alternative to typing a code.
            var tokenOk = _challengeStore.ConsumeUserStepUpToken(request?.StepUpToken, userId);
            var codeOk = !string.IsNullOrWhiteSpace(request?.Code)
                         && _stepUp.VerifyUserCode(userData, request!.Code!);
            if (!tokenOk && !codeOk)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    message = "A current authenticator or recovery code is required to disable two-factor authentication.",
                    twoFactorRequired = true,
                });
            }
            // Persist VerifyUserCode's mutations atomically (matches the
            // N-A18 diff-apply pattern in StepUpVerify).
            await _store.MutateAsync(userId, ud =>
            {
                foreach (var cloneCode in userData.RecoveryCodes)
                {
                    if (!cloneCode.Used) continue;
                    if (string.IsNullOrEmpty(cloneCode.Hash)) continue;
                    var match = ud.RecoveryCodes.FirstOrDefault(c =>
                        string.Equals(c.Hash, cloneCode.Hash, StringComparison.Ordinal) && !c.Used);
                    if (match is not null)
                    {
                        match.Used = true;
                        match.UsedAt = cloneCode.UsedAt ?? DateTime.UtcNow;
                    }
                }
                if (userData.LastUsedTotpStep > ud.LastUsedTotpStep)
                {
                    ud.LastUsedTotpStep = userData.LastUsedTotpStep;
                }
            }).ConfigureAwait(false);
        }

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

    // POST /TwoFactorAuth/StepUp/Verify — exchange a fresh 2FA code for a
    // short-lived step-up token so the next sensitive admin action passes.
    [HttpPost("StepUp/Verify")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult> StepUpVerify([FromBody] StepUpVerifyRequest request)
    {
        var userId = GetCurrentUserId();

        // Rate-limit step-up verification per user to prevent brute-forcing the
        // 6-digit TOTP space from a compromised admin session token. Mirrors the
        // per-user bucket used by the main Verify endpoint (15 attempts / 15 min).
        var stepUpRl = _rateLimiter.CheckAndRecord("stepup:" + userId.ToString("N"), 15, TimeSpan.FromMinutes(15));
        if (!stepUpRl.allowed)
        {
            Response.Headers.Append("Retry-After", stepUpRl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {stepUpRl.retryAfterSeconds} seconds.",
                retryAfterSeconds = stepUpRl.retryAfterSeconds,
            });
        }

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        var ok = !string.IsNullOrWhiteSpace(request?.Code)
                 && _stepUp.VerifyUserCode(userData, request!.Code!);
        if (!ok)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = "Invalid code." });
        }

        // Persist any consumed recovery code (VerifyUserCode marks it Used),
        // then grant the step-up token.
        // SECURITY [v2.5.5] (N-A18): apply only the diff (which entries went
        // from Used=false to Used=true on the clone) instead of replacing
        // the whole RecoveryCodes list. Prior code overwrote any concurrent
        // mutation (e.g. an admin regenerating the user's recovery codes
        // mid-step-up). We match by Hash so even if the canonical list was
        // reordered or extended, we touch the right entry.
        await _store.MutateAsync(userId, ud =>
        {
            foreach (var cloneCode in userData.RecoveryCodes)
            {
                if (!cloneCode.Used) continue;
                if (string.IsNullOrEmpty(cloneCode.Hash)) continue;
                var match = ud.RecoveryCodes.FirstOrDefault(c =>
                    string.Equals(c.Hash, cloneCode.Hash, StringComparison.Ordinal) && !c.Used);
                if (match is not null)
                {
                    match.Used = true;
                    match.UsedAt = cloneCode.UsedAt ?? DateTime.UtcNow;
                }
            }
        }).ConfigureAwait(false);
        _challengeStore.MarkStepUpVerified(userId);
        return Ok(new { verified = true });
    }

    // -------------------------------------------------------------------------
    // POST /TwoFactorAuth/RecoveryCodes/Generate — generate (or rotate) recovery codes.
    // Returns plaintext codes ONCE. User must save them.
    // -------------------------------------------------------------------------

    [HttpPost("RecoveryCodes/Generate")]
    [Authorize]
    public async Task<IActionResult> GenerateRecoveryCodes([FromBody] StepUpCodeRequest? request = null)
    {
        var userId = GetCurrentUserId();

        // SECURITY [v2.5.6] (ext review self-service-takeover): regenerating
        // recovery codes hands a fresh recovery factor to whoever calls
        // this endpoint. A stolen session must prove ownership of the
        // current factor first.
        var stepUp = await EnforceSelfServiceStepUpAsync(userId, request?.Code, request?.StepUpToken).ConfigureAwait(false);
        if (stepUp is not null) return stepUp;

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        if (!userData.TotpEnabled || !userData.TotpVerified)
        {
            return BadRequest(new { message = "Set up TOTP first before generating recovery codes." });
        }

        var (plaintext, records) = _recoveryCodes.GenerateCodes();
        var generatedAt = DateTime.UtcNow;
        // SECURITY [v2.5.6] (F3): MutateAsync for atomic write under the
        // per-user semaphore. Prior Get→Save raced with any concurrent
        // mutation (e.g. concurrent /Disable, /Verify that consumes a
        // code).
        await _store.MutateAsync(userId, ud =>
        {
            ud.RecoveryCodes = records;
            ud.RecoveryCodesGeneratedAt = generatedAt;
        }).ConfigureAwait(false);

        return Ok(new
        {
            codes = plaintext,
            generatedAt,
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
            IndefiniteTrust = d.IndefiniteTrust,
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

        // SECURITY [v2.5.6] (F1): MutateAsync for atomic find+remove under
        // the per-user semaphore. Prior code did Get→Save outside the lock
        // — a concurrent device-add or auth-handler LastUsedAt update could
        // silently drop one of the changes.
        Models.TrustedDevice? device = null;
        await _store.MutateAsync(userId, ud =>
        {
            device = ud.TrustedDevices.FirstOrDefault(d => d.Id == id);
            if (device is not null) ud.TrustedDevices.Remove(device);
        }).ConfigureAwait(false);

        if (device is null)
        {
            return NotFound();
        }

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
    // v2.5.0: per-device indefinite-trust opt-in. Gated by the admin-side
    // AllowIndefiniteTrust master switch; refuses when off so a stale client
    // can't flip the bit after the admin disabled the feature. Self-or-admin
    // authorized via IsAuthorizedForUser.
    // -------------------------------------------------------------------------

    [HttpPut("Users/{userId:guid}/TrustedBrowsers/{recordId}/Indefinite")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> SetTrustedBrowserIndefinite(
        [FromRoute] Guid userId,
        [FromRoute] string recordId,
        [FromBody] SetIndefiniteTrustRequest request)
    {
        if (!IsAuthorizedForUser(userId)) return Forbid();
        var cfg = Plugin.Instance?.Configuration ?? new Jellyfin.Plugin.TwoFactorAuth.Configuration.PluginConfiguration();
        if (!cfg.AllowIndefiniteTrust)
        {
            return BadRequest(new { message = "Indefinite trust is disabled by the administrator." });
        }
        // Step-up gate: extending trust forever is security-relevant, so it
        // counts as a config change under the admin-side StepUpLevel policy.
        var guard = StepUpGuard(StepUpAction.ConfigChange);
        if (guard is not null) return guard;
        await _store.MutateAsync(userId, d =>
        {
            var rec = d.TrustedDevices.FirstOrDefault(t => t.Id == recordId);
            if (rec is not null) rec.IndefiniteTrust = request?.Indefinite ?? false;
        }).ConfigureAwait(false);
        return Ok(new { ok = true });
    }

    [HttpPut("Users/{userId:guid}/PairedDevices/{recordId}/Indefinite")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> SetPairedDeviceIndefinite(
        [FromRoute] Guid userId,
        [FromRoute] string recordId,
        [FromBody] SetIndefiniteTrustRequest request)
    {
        if (!IsAuthorizedForUser(userId)) return Forbid();
        var cfg = Plugin.Instance?.Configuration ?? new Jellyfin.Plugin.TwoFactorAuth.Configuration.PluginConfiguration();
        if (!cfg.AllowIndefiniteTrust)
        {
            return BadRequest(new { message = "Indefinite trust is disabled by the administrator." });
        }
        var guard = StepUpGuard(StepUpAction.ConfigChange);
        if (guard is not null) return guard;
        await _store.MutateAsync(userId, d =>
        {
            var rec = d.PairedDevices.FirstOrDefault(p => p.Id == recordId);
            if (rec is not null) rec.IndefiniteTrust = request?.Indefinite ?? false;
        }).ConfigureAwait(false);
        return Ok(new { ok = true });
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
            // SECURITY [v2.5.5] (F12): MutateAsync for atomic add + populate
            // the new timestamped entries list. The legacy string list is
            // still populated so existing read paths and admin tooling keep
            // working unchanged; the new list is what the bypass evaluator
            // checks when RegisteredDeviceMaxAgeDays > 0.
            await _store.MutateAsync(userId, ud =>
            {
                if (!ud.RegisteredDeviceIds.Contains(request.DeviceId))
                {
                    ud.RegisteredDeviceIds.Add(request.DeviceId);
                }
                if (!ud.RegisteredDeviceEntries.Any(e => string.Equals(e.DeviceId, request.DeviceId, StringComparison.Ordinal)))
                {
                    ud.RegisteredDeviceEntries.Add(new RegisteredDeviceEntry
                    {
                        DeviceId = request.DeviceId,
                        RegisteredAt = DateTime.UtcNow,
                    });
                }
            }).ConfigureAwait(false);
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
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
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

    // SECURITY [v2.5.5] (Finding 7): same-IP-prefix check for the optional
    // challenge-token IP binding. /24 (IPv4) tolerates NAT and corporate
    // proxy egress; /48 (IPv6) tolerates standard SLAAC subnet allocations.
    // Both sides are best-effort parsed — unparseable strings return false
    // (i.e. mismatch) so a malformed IP can't accidentally pass the check.
    private static bool SameIpPrefix(string a, string b)
    {
        if (!System.Net.IPAddress.TryParse(a, out var ipA)) return false;
        if (!System.Net.IPAddress.TryParse(b, out var ipB)) return false;
        if (ipA.AddressFamily != ipB.AddressFamily) return false;
        var bytesA = ipA.GetAddressBytes();
        var bytesB = ipB.GetAddressBytes();
        if (ipA.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // /24: first 3 octets must match
            return bytesA[0] == bytesB[0] && bytesA[1] == bytesB[1] && bytesA[2] == bytesB[2];
        }
        if (ipA.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // /48: first 6 bytes must match
            for (int i = 0; i < 6; i++)
            {
                if (bytesA[i] != bytesB[i]) return false;
            }
            return true;
        }
        return false;
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
            Response.Headers.Append("Retry-After", pollRl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
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
        // SECURITY [v2.5.6] (A1): MutateAsync for atomic add under the
        // per-user semaphore. Prior code did Get→Save outside the lock —
        // a concurrent TrustedDevices mutation (user-side revoke, LastUsedAt
        // update from auth handler) could silently drop the just-created
        // record, leaving the TV device token issued to the user with no
        // matching server-side hash (TV permanently fails to bypass 2FA).
        var (rawToken, trustedDevice) = _deviceTokenService.CreateDeviceToken(pairing.DeviceId, pairing.DeviceName);
        await _store.MutateAsync(pairing.UserId, ud =>
        {
            ud.TrustedDevices.Add(trustedDevice);
        }).ConfigureAwait(false);

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
        var cfg = Plugin.Instance?.Configuration;
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
            // [v2.5.6] (round-5 fix D): surface the admin's mode + per-user
            // opt-in so the Setup page can render the toggle and decide
            // whether to prompt for the current code on each mutation.
            SelfServiceStepUpMode = (cfg?.SelfServiceStepUpMode ?? Configuration.SelfServiceStepUpMode.Forced).ToString(),
            RequireStepUpForChanges = data.RequireStepUpForChanges,
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
        // [v2.5.8] (issue #55 followup, Dasnap): enumerate from Jellyfin's
        // user table, not from the plugin's per-user data files. The old
        // path missed any Jellyfin user who had never triggered plugin-side
        // data creation, so the Users tab silently dropped them until they
        // next signed in (whereupon AuthenticationEventHandler wrote a
        // record and they "reappeared"). Looking up plugin data per user
        // via the store returns an empty default when no file exists, so
        // users with no 2FA enrollment now show with all-zero counts
        // instead of being invisible.
        var jellyfinUsers = EnumerateAllUsers().ToList();
        var result = new List<UserTwoFactorStatus>(jellyfinUsers.Count);

        foreach (var ju in jellyfinUsers)
        {
            if (ju.Id == Guid.Empty) continue;

            UserTwoFactorData data;
            try
            {
                data = await _store.GetUserDataAsync(ju.Id).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // SECURITY [v2.5.6]: store reads fail CLOSED on I/O errors.
                // For the LISTING (read-only, no auth decision) surface a
                // best-effort row with zero counts rather than 500'ing the
                // whole dashboard — admins still see the user and can
                // investigate the missing record from logs.
                _logger.LogWarning(ex, "[2FA] User {UserId} ({Username}) data unreadable; rendering with zeroes",
                    ju.Id, ju.Username);
                data = new UserTwoFactorData { UserId = ju.Id };
            }

            bool isLockedOut;
            try
            {
                isLockedOut = await _store.IsLockedOutAsync(ju.Id).ConfigureAwait(false);
            }
            catch (Exception)
            {
                isLockedOut = false;
            }

            result.Add(new UserTwoFactorStatus
            {
                UserId = ju.Id,
                Username = ju.Username ?? ju.Id.ToString(),
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

    /// <summary>[v2.5.6] (round-5 fix D): per-user toggle for the
    /// hardened-security step-up gate. Only meaningful when the admin's
    /// SelfServiceStepUpMode is UserChoice — Forced overrides this on
    /// the server side; Off ignores it. Honors the same step-up gate as
    /// every other mutating endpoint so an attacker with a stolen session
    /// can't silently flip it off.</summary>
    public class StepUpPrefRequest
    {
        public bool Enabled { get; set; }
        public string? Code { get; set; }
        // [v2.5.6] (round-5c): step-up token alternative — see StepUpCodeRequest.
        public string? StepUpToken { get; set; }
    }

    [HttpPost("MyStepUpPreference")]
    [Authorize]
    public async Task<IActionResult> SetMyStepUpPreference([FromBody, Required] StepUpPrefRequest req)
    {
        var userId = GetCurrentUserId();

        // [v2.5.6] (round-5 fix D): changing this preference is itself a
        // factor-mutating operation — a stolen session could otherwise flip
        // it off and then mutate factors without any step-up. Gate via the
        // same EnforceSelfServiceStepUpAsync helper.
        var stepUp = await EnforceSelfServiceStepUpAsync(userId, req.Code, req.StepUpToken).ConfigureAwait(false);
        if (stepUp is not null) return stepUp;

        await _store.MutateAsync(userId, ud => { ud.RequireStepUpForChanges = req.Enabled; }).ConfigureAwait(false);
        return Ok(new { requireStepUpForChanges = req.Enabled });
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
        // SECURITY [v2.5.5] (N-A11): use MutateAsync so the read-modify-write
        // happens under the per-user semaphore. Prior code did a clone-read,
        // mutated the clone, then SaveUserDataAsync — racing with any
        // concurrent write to the same user (a parallel auth bypass updating
        // TrustedDevices[].LastUsedAt, or the user's own /Devices/{id}
        // DELETE) silently overwrote those updates. MutateAsync is the
        // canonical pattern used by every other writer in the codebase.
        await _store.MutateAsync(userId, ud =>
        {
            ud.TrustedDevices.RemoveAll(d => d.Id == deviceRecordId);
        }).ConfigureAwait(false);
        return Ok();
    }

    // -------------------------------------------------------------------------
    // v2.5.0: per-user UI language preference. Self-or-admin: any logged-in
    // user can read/write their OWN language preference; admins can read/write
    // any user's. Authorization is enforced inline via IsAuthorizedForUser so
    // the route stays a single endpoint. (Pre-2.5.0 this was admin-only as a
    // ship-fast compromise; the helper landed alongside the i18n surface.)
    // -------------------------------------------------------------------------

    [HttpGet("users/{userId:guid}/preferences")]
    [Authorize]
    public async Task<IActionResult> GetUserPreferences([FromRoute] Guid userId)
    {
        if (!IsAuthorizedForUser(userId)) return Forbid();

        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var cfg = Plugin.Instance?.Configuration ?? new Jellyfin.Plugin.TwoFactorAuth.Configuration.PluginConfiguration();
        return Ok(new
        {
            language = data.Language,
            effectiveLanguage = data.Language ?? cfg.DefaultLanguage,
            defaultLanguage = cfg.DefaultLanguage,
        });
    }

    [HttpPut("users/{userId:guid}/preferences")]
    [Authorize]
    public async Task<IActionResult> UpdateUserPreferences([FromRoute] Guid userId, [FromBody] UpdatePreferencesRequest request)
    {
        if (!IsAuthorizedForUser(userId)) return Forbid();

        if (request is null)
        {
            return BadRequest(new { message = "body required" });
        }

        if (!string.IsNullOrEmpty(request.Language)
            && Array.IndexOf(SupportedLanguages, request.Language) < 0)
        {
            return BadRequest(new { message = "unsupported language" });
        }

        await _store.MutateAsync(userId, d =>
        {
            d.Language = string.IsNullOrEmpty(request.Language) ? null : request.Language;
        }).ConfigureAwait(false);

        return Ok(new { ok = true });
    }

    // -------------------------------------------------------------------------
    // 12. POST /TwoFactorAuth/Users/{id}/Toggle [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("Users/{id}/Toggle")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> ToggleUser([FromRoute] Guid id, [FromBody, Required] ToggleUserRequest request)
    {
        // SECURITY [v2.5.6] (U3): require step-up. Admin disabling another
        // user's 2FA is a destructive action that an attacker holding a
        // hijacked admin cookie should not be able to invoke without
        // re-verification. Same classification as ResetOtherUser2fa.
        var guard = StepUpGuard(StepUpAction.ResetOtherUser2fa);
        if (guard is not null) return guard;

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
            // SECURITY [v2.5.6] (A2): admin disable now runs under MutateAsync
            // for atomic wipe. Prior code did Get→Save outside the lock —
            // racing concurrent auth-side mutations could lose updates.
            await _store.MutateAsync(id, ud =>
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
        // SECURITY [v2.5.5] (N-A6): apply step-up guard. StepUpAction.ViewAuditLog
        // is classified as StepUpLevel.Everything in StepUpService — the
        // classification existed but was never enforced. The audit log
        // contains usernames, IPs, device IDs, and auth-method strings;
        // a hijacked admin session token shouldn't be enough to read it,
        // re-verification of a TOTP / recovery code is required.
        var guard = StepUpGuard(StepUpAction.ViewAuditLog);
        if (guard is not null) return guard;

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
        // SECURITY [v2.5.6] (U3): require step-up to mint an API key.
        // Minting a credential without fresh re-verification means a
        // hijacked admin session can quietly persist access. ConfigChange
        // classification gates this with a TOTP / passkey / recovery
        // re-prompt in the step-up window.
        var apiKeyGuard = StepUpGuard(StepUpAction.ConfigChange);
        if (apiKeyGuard is not null) return apiKeyGuard;

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
        // SECURITY [v2.5.6] (U3): require step-up. Revoking an API key is
        // destructive (breaks integrations); requiring step-up prevents a
        // hijacked admin session from silently disabling automation.
        var delApiKeyGuard = StepUpGuard(StepUpAction.ConfigChange);
        if (delApiKeyGuard is not null) return delApiKeyGuard;

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
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_ipBans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var rl = _rateLimiter.CheckAndRecord("email:" + clientIp, 5, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
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

        // SECURITY [v2.5.9]: only send an email OTP when the challenge actually
        // offers "email" as a method. Without this, anyone holding a valid
        // challenge token for a TOTP/passkey-only user could trigger OTP
        // emails (inbox spam / noise). Mirrors the AvailableMethods
        // enforcement in Verify. Return the same generic success as the happy
        // path so this can't be used to probe which tokens are email-eligible.
        if (challenge.AvailableMethods is { Count: > 0 }
            && !challenge.AvailableMethods.Any(m => string.Equals(m, "email", StringComparison.OrdinalIgnoreCase)))
        {
            return Ok(new { message = "If an email is configured for this user, a code has been sent." });
        }

        if (!await _allowlist.IsAllowedAsync(challenge.UserId, clientIp).ConfigureAwait(false))
        {
            _ipBans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Account is locked out." });
        }

        // SEC v2.4 M2: per-user email rate limit on top of per-IP. Without
        // this, an attacker holding a valid challenge token (i.e. they just
        // triggered an auth attempt for the target user) can rotate IPs and
        // spam the target's inbox with OTP emails. The challenge token is
        // bound to a single user so per-IP limits don't help here.
        var userEmailRl = _rateLimiter.CheckAndRecord(
            "email:user:" + challenge.UserId.ToString("N"),
            3,
            TimeSpan.FromMinutes(15));
        if (!userEmailRl.allowed)
        {
            // Return the same generic success as the happy path. Don't reveal
            // a per-user cap was hit — that itself leaks which tokens map to
            // spammable accounts.
            return Ok(new { message = "If an email is configured for this user, a code has been sent." });
        }

        // Per-user email address from plugin config (admin sets these)
        var email = Plugin.Instance?.Configuration.GetUserEmail(challenge.UserId.ToString("N"));

        var (_, sent) = await _emailOtpService.GenerateAndSendCodeAsync(
            challenge.UserId,
            challenge.Username,
            email,
            request.ChallengeToken).ConfigureAwait(false);

        // SEC v2.4 H1: generic response regardless of whether email was
        // configured or SMTP send failed. Previously the message text told
        // an attacker holding a valid challenge token whether the target
        // user had email OTP set up. SMTP failures are still logged server
        // side via _emailOtpService so admins can triage.
        if (!sent && email is null)
        {
            _logger.LogDebug(
                "[2FA] Email OTP requested for user with no configured address (userId={UserId})",
                challenge.UserId);
        }
        return Ok(new { message = "If an email is configured for this user, a code has been sent." });
    }

    // -------------------------------------------------------------------------
    // 18. POST /TwoFactorAuth/Sessions/{id}/Revoke [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("Sessions/{id}/Revoke")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> RevokeSession([FromRoute] string id)
    {
        var sessions = EnumerateSessions();
        var session = sessions.FirstOrDefault(s => s.Id == id);

        if (session is null)
        {
            return NotFound("Session not found");
        }

        await _sessionManager.ReportSessionEnded(id).ConfigureAwait(false);

        return Ok();
    }

    // =========================================================================
    // App Passwords  (v1.3.0 — for native clients that submit a password)
    // =========================================================================

    public class CreateAppPasswordBody
    {
        public string Label { get; set; } = string.Empty;

        // SECURITY [v2.5.6] (ext review self-service-takeover): step-up
        // code accompanying a factor-mutation. Required when the user
        // already has 2FA enrolled and the admin's SelfServiceStepUpMode
        // requires it (Forced — or UserChoice + per-user opt-in). Validated
        // by EnforceSelfServiceStepUpAsync.
        public string? Code { get; set; }

        // [v2.5.6] (round-5c): step-up token alternative — see StepUpCodeRequest.
        public string? StepUpToken { get; set; }
    }

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

        // SECURITY [v2.5.6] (ext review self-service-takeover): an app
        // password is a permanent password-replacement credential. A
        // stolen session creating one establishes long-term persistence
        // independent of the original password. Require step-up.
        var stepUp = await EnforceSelfServiceStepUpAsync(userId, req.Code, req.StepUpToken).ConfigureAwait(false);
        if (stepUp is not null) return stepUp;

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
        // SECURITY [v2.5.6] (A10): atomic add via MutateAsync. Re-checks
        // the cap inside the lock so two concurrent requests can't both
        // see count=19 and push to 21.
        var added = false;
        await _store.MutateAsync(userId, ud =>
        {
            if (ud.AppPasswords.Count < 20)
            {
                ud.AppPasswords.Add(entry);
                added = true;
            }
        }).ConfigureAwait(false);
        if (!added)
        {
            return BadRequest(new { message = "Limit reached. Revoke an existing app password first." });
        }

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
        // SECURITY [v2.5.6] (A9): atomic remove via MutateAsync.
        var removed = 0;
        await _store.MutateAsync(userId, ud =>
        {
            removed = ud.AppPasswords.RemoveAll(p => p.Id == id);
        }).ConfigureAwait(false);
        if (removed == 0) return NotFound();

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
            indefiniteTrust = p.IndefiniteTrust,
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

        // SECURITY [v2.5.5] (Finding 19): use proxy-aware scheme resolution.
        // Behind a TLS-terminating reverse proxy, HttpContext.Request.IsHttps
        // is always false; BypassEvaluator.ResolveScheme honours
        // X-Forwarded-Proto from trusted proxies.
        var scheme = BypassEvaluator.ResolveScheme(HttpContext);
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
        // SECURITY [v2.5.6] (fourth-audit A13): validate DeviceId length
        // and shape via the same IsValidDeviceId guard as /Devices/Register.
        // Prior code only checked non-empty, letting a 100KB DeviceId
        // through into the audit log.
        if (!IsValidDeviceId(req.DeviceId)) return BadRequest(new { message = "Invalid device id" });
        var pending = _pendingPairings.Get(userId, req.DeviceId);
        // [v2.5.6] (round-5 fix A): use the new Deny() which also adds the
        // device to a sticky denylist so the next auth retry from that device
        // doesn't immediately re-create the pending entry (which made the
        // Deny button appear broken in v2.5.5 — the entry would reappear
        // within seconds).
        _pendingPairings.Deny(userId, req.DeviceId);

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
        var live = EnumerateSessions()
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
        var device = result.Items.FirstOrDefault(d => d.Id.ToString(CultureInfo.InvariantCulture) == id);
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
    public async Task<IActionResult> PasskeyRegisterBegin([FromBody] StepUpCodeRequest? request = null)
    {
        var userId = GetCurrentUserId();
        var user = _userManager.GetUserById(userId);
        if (user is null) return Unauthorized();

        // SECURITY [v2.5.6] (F5-A6): block passkey registration while the
        // account is locked out. A user with a still-valid session token
        // that was issued before the lockout fired shouldn't be able to
        // modify their security configuration mid-lockout. Same posture
        // as every other state-mutating user endpoint.
        if (await _store.IsLockedOutAsync(userId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new { message = "Account is locked out — cannot modify passkeys until lockout expires." });
        }

        // SECURITY [v2.5.6] (ext review self-service-takeover): adding a
        // passkey grants an alternative permanent 2nd-factor. A stolen
        // session registering a passkey establishes attacker-controlled
        // ongoing access. Require step-up via current TOTP/recovery code.
        // The RegisterFinish endpoint is paired with this one via the
        // nonce returned here, so gating Begin gates the whole flow.
        var stepUp = await EnforceSelfServiceStepUpAsync(userId, request?.Code, request?.StepUpToken).ConfigureAwait(false);
        if (stepUp is not null) return stepUp;

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
            // SECURITY [v2.5.5]: do not echo ex.Message to the client.
            // Fido2NetLib error messages frequently include internal
            // implementation detail (expected RP ID, expected origin, raw
            // credential ID, attestation format names) that are useful for
            // fingerprinting the WebAuthn configuration. Full detail still
            // goes to the warning log for admin diagnostics — generic
            // message to the client.
            _logger.LogWarning(ex, "[2FA] Passkey registration failed");
            return BadRequest(new { message = "Registration failed — check your authenticator and try again." });
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
    public async Task<IActionResult> DeletePasskey([FromRoute] string id, [FromQuery] string? code = null, [FromQuery] string? stepUpToken = null)
    {
        var userId = GetCurrentUserId();

        // SECURITY [v2.5.6] (ext review self-service-takeover): deleting a
        // passkey weakens the user's 2FA posture (could be their only
        // factor). A stolen session must prove ownership before tearing
        // down factors. Code or step-up token arrives on query string
        // since this is a DELETE with no body in the existing UI.
        var stepUp = await EnforceSelfServiceStepUpAsync(userId, code, stepUpToken).ConfigureAwait(false);
        if (stepUp is not null) return stepUp;

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
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_ipBans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        // SEC v2.4: rate-limit passkey assertion. ECDSA-verify cost on the
        // Finish path is small but non-zero; without a cap an attacker can
        // grind login latency for legitimate users via a flood of crafted
        // assertions. Matches the pattern used on /Authenticate + /Verify.
        var pkRl = _rateLimiter.CheckAndRecord("pk_assert:" + clientIp, 20, TimeSpan.FromMinutes(1));
        if (!pkRl.allowed)
        {
            Response.Headers.Append("Retry-After", pkRl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many passkey requests. Try again in {pkRl.retryAfterSeconds} seconds.",
            });
        }

        var challenge = _challengeStore.GetChallenge(req.ChallengeToken);
        if (challenge is null) return BadRequest(new { message = "Invalid or expired challenge" });
        if (!await _allowlist.IsAllowedAsync(challenge.UserId, clientIp).ConfigureAwait(false))
        {
            _ipBans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        // SECURITY [v2.5.6] (ext review #2): enforce challenge.AvailableMethods.
        // "passkey" must be in the allow-list for THIS challenge. Without
        // this guard a user could call /Verify/Passkey/Begin against a
        // challenge that the issuer scoped to TOTP-only (e.g. when in
        // recovery mode).
        if (challenge.AvailableMethods is { Count: > 0 }
            && !challenge.AvailableMethods.Any(m =>
                string.Equals(m, "passkey", StringComparison.OrdinalIgnoreCase)))
        {
            _ipBans.RecordFailure(clientIp);
            return BadRequest(new { message = "Passkey verification is not available for this challenge." });
        }

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
        var requestIp = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? requestIp;
        if (_ipBans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        // SEC v2.4: defense-in-depth on the ECDSA-verify hot path. Shares the
        // same per-IP bucket as Begin so a flood is capped across both halves
        // of the assertion ceremony.
        var pkRl = _rateLimiter.CheckAndRecord("pk_assert:" + clientIp, 20, TimeSpan.FromMinutes(1));
        if (!pkRl.allowed)
        {
            Response.Headers.Append("Retry-After", pkRl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many passkey requests. Try again in {pkRl.retryAfterSeconds} seconds.",
            });
        }

        var challenge = _challengeStore.GetChallenge(req.ChallengeToken);
        if (challenge is null) return BadRequest(new { message = "Invalid or expired challenge" });
        if (!await _allowlist.IsAllowedAsync(challenge.UserId, clientIp).ConfigureAwait(false))
        {
            _ipBans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        var (optionsJson, userId) = _passkeyChallenges.Consume(req.Nonce);
        if (optionsJson is null || userId != challenge.UserId)
        {
            _ipBans.RecordFailure(clientIp);
            return BadRequest(new { message = "Assertion challenge expired or invalid" });
        }

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
            _ipBans.RecordFailure(clientIp);
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

        var ip = clientIp;
        _ipBans.RecordSuccess(clientIp);
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
        UnblockAccessTokenFromPendingAuthResponse(stashed, challenge.Username);
        return Content(stashed, "application/json");
    }

    // =========================================================================
    // [v2.5.6] (round-5c): User-self step-up — exchange a fresh factor proof
    // (TOTP code, recovery code, OR a passkey assertion) for a single-use
    // 60-second token that the next factor-mutation request can submit in
    // lieu of a fresh code. Lets the prompt UI give the user a choice of
    // verification methods ("Use TOTP" / "Use a passkey") instead of being
    // hard-locked to typing a code.
    // =========================================================================

    [HttpPost("StepUp/UserPasskeyBegin")]
    [Authorize]
    public async Task<IActionResult> UserStepUpPasskeyBegin()
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (data.Passkeys.Count == 0)
            return BadRequest(new { message = "No passkeys registered for this user." });
        var optionsJson = _passkeys.BuildAssertionOptions(HttpContext, data.Passkeys);
        var nonce = _passkeyChallenges.Begin(optionsJson, userId);
        return Content("{\"nonce\":\"" + nonce + "\",\"options\":" + optionsJson + "}", "application/json");
    }

    [HttpPost("StepUp/UserPasskeyVerify")]
    [Authorize]
    public async Task<IActionResult> UserStepUpPasskeyVerify([FromBody, Required] PasskeyAssertFinishRequest req)
    {
        var userId = GetCurrentUserId();
        var (optionsJson, ownerId) = _passkeyChallenges.Consume(req.Nonce);
        if (optionsJson is null || ownerId != userId)
            return BadRequest(new { message = "Step-up challenge expired or invalid." });
        bool ok;
        try
        {
            ok = await _passkeys.CompleteAssertionAsync(HttpContext, userId, optionsJson, req.Response).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return Unauthorized(new { message = "Passkey assertion failed." });
        }
        if (!ok) return Unauthorized(new { message = "Passkey assertion failed." });
        var token = _challengeStore.MintUserStepUpToken(userId);
        return Ok(new { stepUpToken = token });
    }

    [HttpPost("StepUp/UserCodeVerify")]
    [Authorize]
    public async Task<IActionResult> UserStepUpCodeVerify([FromBody, Required] StepUpCodeRequest req)
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var code = req.Code ?? string.Empty;

        // [v2.5.6] (round-5d): accept TOTP, recovery, OR an email step-up
        // code. EmailOtpService.ValidateStepUpCode consumes single-use on
        // success so we can call it freely.
        if (_stepUp.VerifyUserCode(data, code))
        {
            // Persist consumed-recovery / replay-floor mutations atomically
            // before returning the token. Matches the disable-2FA pattern.
            await _store.MutateAsync(userId, ud =>
            {
                foreach (var c in data.RecoveryCodes)
                {
                    if (!c.Used) continue;
                    if (string.IsNullOrEmpty(c.Hash)) continue;
                    var match = ud.RecoveryCodes.FirstOrDefault(r =>
                        string.Equals(r.Hash, c.Hash, StringComparison.Ordinal) && !r.Used);
                    if (match is not null)
                    {
                        match.Used = true;
                        match.UsedAt = c.UsedAt ?? DateTime.UtcNow;
                    }
                }
                if (data.LastUsedTotpStep > ud.LastUsedTotpStep)
                    ud.LastUsedTotpStep = data.LastUsedTotpStep;
            }).ConfigureAwait(false);
        }
        else if (!_emailOtpService.ValidateStepUpCode(userId, code))
        {
            return Unauthorized(new { message = "Invalid code." });
        }

        var token = _challengeStore.MintUserStepUpToken(userId);
        return Ok(new { stepUpToken = token });
    }

    [HttpPost("StepUp/UserEmailSend")]
    [Authorize]
    public async Task<IActionResult> UserStepUpEmailSend()
    {
        var userId = GetCurrentUserId();
        var cfg = Plugin.Instance?.Configuration;
        if (cfg is null || !cfg.EmailOtpEnabled)
            return BadRequest(new { message = "Email OTP is disabled on this server." });
        var email = cfg.GetUserEmail(userId.ToString("N"));
        if (string.IsNullOrEmpty(email))
            return BadRequest(new { message = "No email configured for your account." });
        var jellyfinUser = _userManager.GetUserById(userId);
        var username = jellyfinUser?.Username ?? userId.ToString();
        var sent = await _emailOtpService.SendStepUpCodeAsync(userId, username, email).ConfigureAwait(false);
        if (!sent)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { message = "Failed to send email. Check SMTP configuration." });
        return Ok(new { sent = true });
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
                // Reflection-based enumeration — Jellyfin 10.11.9 changed
                // IUserManager.Users's return type, breaking the IL-bound
                // call site compiled against 10.11.8. Reflection works on
                // both ABIs. See issue #27 / StatsService.EnumerateUsers.
                var adminCount = EnumerateAllUsers().Count(u =>
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

        var guard = StepUpGuard(StepUpAction.ResetOtherUser2fa);
        if (guard is not null) return guard;

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

    // POST /TwoFactorAuth/Admin/HardeningConfig — focused save endpoint for the
    // v2.5.0 opt-in hardening toggles. Gated by step-up so an admin can't flip
    // these from a hijacked session. Broader plugin config still flows through
    // Jellyfin's built-in PUT /Plugins/{guid}/Configuration which can't be
    // intercepted to gate.
    [HttpPost("Admin/HardeningConfig")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public ActionResult SaveHardeningConfig([FromBody] HardeningConfigRequest request)
    {
        var guard = StepUpGuard(StepUpAction.ConfigChange);
        if (guard is not null) return guard;

        var plugin = Plugin.Instance;
        if (plugin is null) return StatusCode(StatusCodes.Status500InternalServerError);

        var config = plugin.Configuration;
        if (request.RequireTwoFactorToDisable.HasValue)
        {
            config.RequireTwoFactorToDisable = request.RequireTwoFactorToDisable.Value;
        }
        if (request.StepUpLevel.HasValue)
        {
            config.StepUpLevel = request.StepUpLevel.Value;
        }
        if (request.StepUpWindowSeconds.HasValue)
        {
            // Clamp to the same range MarkStepUpVerified uses (60-900).
            config.StepUpWindowSeconds = Math.Clamp(request.StepUpWindowSeconds.Value, 60, 900);
        }
        if (request.AllowIndefiniteTrust.HasValue)
        {
            config.AllowIndefiniteTrust = request.AllowIndefiniteTrust.Value;
        }
        plugin.SaveConfiguration();
        return Ok();
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

    /// <summary>v2.5.0: rebuilds the audit-log hash chain after the admin
    /// has reviewed a broken-chain diagnostic. Gated by the destructive-tier
    /// step-up policy because it intentionally erases tampering evidence —
    /// a malicious admin who already has 2FA could use this to clean up
    /// after themselves. The dashboard audit_chain factor reads as green
    /// again immediately after a successful rebuild.</summary>
    [HttpPost("Admin/RebuildAuditChain")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> RebuildAuditChain()
    {
        var guard = StepUpGuard(StepUpAction.ResetOtherUser2fa);
        if (guard is not null) return guard;
        var count = await _store.RebuildAuditChainAsync().ConfigureAwait(false);
        return Ok(new { ok = true, rebuilt = count });
    }

    /// <summary>v2.5.0: persist the server-wide DefaultLanguage that the
    /// pre-login pages (login.html, challenge.html, setup.html) read via
    /// /TwoFactorAuth/public-config to pick a translation bundle before a
    /// per-user preference is available. Validates against the supported-
    /// language allowlist before writing so a malicious or typo'd value
    /// can't poison the bundle resolution.</summary>
    [HttpPost("Admin/DefaultLanguage")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult SetDefaultLanguage([FromBody] DefaultLanguageRequest request)
    {
        if (string.IsNullOrWhiteSpace(request?.DefaultLanguage))
        {
            return BadRequest(new { message = "defaultLanguage required" });
        }
        if (Array.IndexOf(SupportedLanguages, request.DefaultLanguage) < 0)
        {
            return BadRequest(new { message = "unsupported language" });
        }
        var cfg = Plugin.Instance?.Configuration;
        if (cfg is null)
        {
            return StatusCode(500, new { message = "no config" });
        }
        cfg.DefaultLanguage = request.DefaultLanguage;
        Plugin.Instance?.SaveConfiguration();
        return Ok(new { ok = true });
    }

    [HttpGet("Stats")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> GetStats()
    {
        var s = await _stats.ComputeAsync().ConfigureAwait(false);
        return Ok(s);
    }

    // v2.5.2: in-memory cache for the Dashboard/Overview response keyed by
    // range. The endpoint runs the security-score pipeline (full user list +
    // full audit log scan + chain verification) AND builds the chart, so a
    // tab switch / range flip / refresh would otherwise re-pay the whole
    // bill. 15-second TTL: long enough that flipping between tabs feels
    // instant, short enough that admins see fresh data within a minute of
    // any change. Cache is cross-admin (data is server-wide) and small (<6
    // entries: 1w/1m/1y × bucketing). On a process restart it clears.
    private static readonly object _overviewCacheLock = new();
    private static readonly Dictionary<string, (DateTime At, object Body)> _overviewCache = new();
    private static readonly TimeSpan _overviewCacheTtl = TimeSpan.FromSeconds(15);

    [HttpGet("Dashboard/Overview")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> GetDashboardOverview([FromQuery] string range = "1m")
    {
        // SECURITY [v2.5.6] (A5): normalise the cache key to a small set of
        // accepted values BEFORE indexing the cache. Prior code keyed on
        // raw user input (`range.ToLowerInvariant()`) — any distinct value
        // an admin sent created a new cache entry. With unknown values
        // all normalising to the same body downstream, this just bloated
        // memory permanently.
        var preNormalizedRange = (range ?? "1m").ToLowerInvariant();
        var cacheKey = preNormalizedRange switch
        {
            "1m" or "5m" or "1h" or "24h" or "7d" or "30d" => preNormalizedRange,
            _ => "1m",
        };
        lock (_overviewCacheLock)
        {
            if (_overviewCache.TryGetValue(cacheKey, out var entry) &&
                (DateTime.UtcNow - entry.At) < _overviewCacheTtl)
            {
                return Ok(entry.Body);
            }
            // Also cap the cache to those known keys — bound on growth.
            if (_overviewCache.Count > 16)
            {
                _overviewCache.Clear();
            }
        }

        var score = await _scoreService.ComputeAsync().ConfigureAwait(false);
        var history = await _scoreService.GetHistoryAsync(30).ConfigureAwait(false);
        var stats = await _stats.ComputeAsync().ConfigureAwait(false);
        var audit = await _store.GetAuditLogAsync(limit: null).ConfigureAwait(false);
        var bans = _ipBans.ListActive();

        // Enrollment-by-role
        var users = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var enrolledIds = new HashSet<Guid>(users
            .Where(d => d.TotpEnabled || d.Passkeys.Count > 0)
            .Select(d => d.UserId));
        int adminsTotal = 0, adminsEnrolled = 0, regularTotal = 0, regularEnrolled = 0;
        // v2.5.0 fix #2: HasPermission is an EXTENSION METHOD on User, not an instance
        // method, so GetType().GetMethod("HasPermission") returns null and every user
        // was being classified as non-admin. Use the typed extension-method call.
        // v2.5.2 fix (issue #37): the previous direct `_userManager.Users` call threw
        // System.MissingMethodException on Jellyfin 10.11.9+ because get_Users()'s
        // return type changed between the ABI we compile against (10.11.8) and the
        // ABI the user runs (10.11.10). Route through EnumerateAllUsers() which
        // already wraps the property in a reflection shim that re-binds at runtime.
        foreach (var u in EnumerateAllUsers())
        {
            var isAdmin = u.HasPermission(PermissionKind.IsAdministrator);
            var isEnrolled = enrolledIds.Contains(u.Id);
            if (isAdmin) { adminsTotal++; if (isEnrolled) adminsEnrolled++; }
            else { regularTotal++; if (isEnrolled) regularEnrolled++; }
        }

        // v2.5.0: time-series window is selectable via ?range=1w|1m|1y.
        // 1w and 1m bucket per UTC day; 1y buckets per month. Any unknown
        // value falls back to 1m so admins can't trigger a server error
        // by hand-crafting the URL. The output is BACKFILLED — every
        // bucket between `since` and now appears (even with zero counts)
        // so the chart spans the full range instead of collapsing to a
        // single bar when audit retention is shorter than the window.
        var normalizedRange = range?.ToLowerInvariant() switch
        {
            "1w" => "1w",
            "1y" => "1y",
            _ => "1m"
        };
        DateTime since;
        bool monthly;
        switch (normalizedRange)
        {
            case "1w":
                since = DateTime.UtcNow.Date.AddDays(-6);
                monthly = false;
                break;
            case "1y":
                // Start at the first day of the month 11 months ago, so a 1-year chart
                // spans 12 monthly buckets including the current (partial) month.
                // Computing via AddMonths(-11) avoids the unsafe (Year-1) pattern that
                // CodeQL flags as potentially producing an invalid DateTime year.
                var firstOfThisMonth = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1, 0, 0, 0, DateTimeKind.Utc);
                since = firstOfThisMonth.AddMonths(-11);
                monthly = true;
                break;
            default:
                since = DateTime.UtcNow.Date.AddDays(-29);
                monthly = false;
                break;
        }
        var bucketFormat = monthly ? "yyyy-MM" : "yyyy-MM-dd";

        // Bucket the real audit entries.
        var grouped = audit
            .Where(e => e.Timestamp >= since)
            .GroupBy(e => e.Timestamp.ToString(bucketFormat, CultureInfo.InvariantCulture))
            .ToDictionary(g => g.Key, g => new
            {
                success = g.Count(e => e.Result == AuditResult.Success),
                failed = g.Count(e => e.Result == AuditResult.Failed),
                locked = g.Count(e => e.Result == AuditResult.Locked)
            });

        // Backfill: enumerate every expected bucket between `since` and now.
        var timeSeries = new List<object>();
        if (monthly)
        {
            var cursor = new DateTime(since.Year, since.Month, 1, 0, 0, 0, DateTimeKind.Utc);
            var end = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1, 0, 0, 0, DateTimeKind.Utc);
            while (cursor <= end)
            {
                var key = cursor.ToString(bucketFormat, CultureInfo.InvariantCulture);
                grouped.TryGetValue(key, out var bucket);
                timeSeries.Add(new
                {
                    date = key,
                    success = bucket?.success ?? 0,
                    failed = bucket?.failed ?? 0,
                    locked = bucket?.locked ?? 0
                });
                cursor = cursor.AddMonths(1);
            }
        }
        else
        {
            var cursor = since.Date;
            var end = DateTime.UtcNow.Date;
            while (cursor <= end)
            {
                var key = cursor.ToString(bucketFormat, CultureInfo.InvariantCulture);
                grouped.TryGetValue(key, out var bucket);
                timeSeries.Add(new
                {
                    date = key,
                    success = bucket?.success ?? 0,
                    failed = bucket?.failed ?? 0,
                    locked = bucket?.locked ?? 0
                });
                cursor = cursor.AddDays(1);
            }
        }

        int chainBroken = DiagnosticsService.VerifyAuditChainPublic(audit);

        var body = new
        {
            // Flatten typed DTOs into anonymous shape so System.Text.Json
            // emits camelCase consistently — the SecurityScore/IpBanEntry
            // classes have PascalCase properties and Jellyfin's serializer
            // does not auto-lowercase nested DTO members.
            score = new
            {
                total = score.Total,
                possible = score.Possible,
                grade = score.Grade,
                // v2.5.0: flatten LabelKey / NextActionKey / NextActionData
                // onto the anonymous shape so System.Text.Json camelCases them
                // for the admin UI. Without flattening, Jellyfin's serializer
                // keeps the original PascalCase property names on nested DTOs
                // and the frontend's f.labelKey / f.nextActionData lookups
                // come back undefined (see commit d70e730 for the underlying
                // serializer quirk).
                factors = score.Factors.Select(f => new
                {
                    id = f.Id,
                    label = f.Label,
                    labelKey = f.LabelKey,
                    earned = f.Earned,
                    possible = f.Possible,
                    status = f.Status,
                    nextAction = f.NextAction,
                    nextActionKey = f.NextActionKey,
                    nextActionData = f.NextActionData
                }),
                computedAt = score.ComputedAt
            },
            kpis = new
            {
                enrolledUsers = stats.EnrolledCount,
                totalUsers = stats.TotalUsers,
                activeSessions = EnumerateSessions().Count(),
                bannedIps = bans.Count,
                auditEntries = audit.Count,
                auditChainBroken = chainBroken
            },
            history = history.Select(h => new { date = h.Date, score = h.Score }),
            enrollmentByRole = new
            {
                adminsTotal,
                adminsEnrolled,
                regularTotal,
                regularEnrolled
            },
            range = normalizedRange,
            timeSeries,
            bans = bans.Select(b => new
            {
                ip = b.Ip,
                bannedAt = b.BannedAt,
                expiresAt = b.ExpiresAt,
                failureCount = b.FailureCount,
                source = b.Source,
                note = b.Note
            })
        };

        lock (_overviewCacheLock)
        {
            _overviewCache[cacheKey] = (DateTime.UtcNow, body);
        }
        return Ok(body);
    }

    // v2.5.0: anonymous server-wide defaults so login.html / challenge.html
    // can pick the right translation bundle BEFORE the user authenticates.
    // Only exposes non-sensitive defaults (current admin DefaultLanguage and
    // the supported-language allowlist).
    [HttpGet("public-config")]
    [AllowAnonymous]
    public IActionResult GetPublicConfig()
    {
        var cfg = Plugin.Instance?.Configuration ?? new Jellyfin.Plugin.TwoFactorAuth.Configuration.PluginConfiguration();
        Response.Headers["Cache-Control"] = "no-cache, must-revalidate";
        return Ok(new
        {
            defaultLanguage = cfg.DefaultLanguage,
            supportedLanguages = SupportedLanguages,
            // v2.5.0: lets setup.html decide whether to render the per-device
            // indefinite-trust toggle. The server-side endpoints also enforce
            // this — the public-config flag is purely a UI gate.
            allowIndefiniteTrust = cfg.AllowIndefiniteTrust,
            // [v2.5.7] (issue #48 feature): inject.js reads these to decide
            // whether to render the built-in 2FA / Passkey login buttons.
            // Independent toggles so admins can pick the shape they want.
            // Purely a UI gate — the /TwoFactorAuth/Login plugin login page
            // still works regardless of these flags.
            hideBuiltInTwoFactorButton = cfg.HideBuiltInTwoFactorButton,
            hideBuiltInPasskeyButton = cfg.HideBuiltInPasskeyButton,
            // [v2.5.11] (#69, ZEROX7) UI gate: hide the username/password form on
            // the login page for this client when password sign-in is disabled.
            // LAN / exempt-CIDR exemptions are resolved per request IP; the admin
            // exemption can't be known before login, so an admin on a blocked
            // network uses inject.js's "sign in with a password" reveal link
            // (the server still allows them via AllowAdminPasswordLogin).
            passwordLoginDisabled = ComputePasswordLoginDisabledForRequest(cfg),
            // [v2.5.11] (#71, ZEROX7) show the login-page "Forgot password?" link
            // only when recovery is enabled AND SMTP is configured.
            passwordRecoveryEnabled = cfg.EnablePasswordRecovery
                && !string.IsNullOrEmpty(cfg.SmtpHost)
                && !string.IsNullOrEmpty(cfg.SmtpFromAddress),
            // [v2.5.12] (#80, ZEROX7) sub-option: hide Jellyfin's native
            // forgot-password link (only meaningful when recovery is on).
            hideBuiltInForgotPassword = cfg.HideBuiltInForgotPassword,
        });
    }

    /// <summary>[v2.5.11] (#69) whether the login-page password form should be
    /// hidden for THIS request's client. Mirrors the server-side enforcement in
    /// LockoutMessageMiddleware minus the admin check (unknowable pre-login).</summary>
    private bool ComputePasswordLoginDisabledForRequest(Jellyfin.Plugin.TwoFactorAuth.Configuration.PluginConfiguration cfg)
    {
        if (!cfg.DisablePasswordLogin)
        {
            return false;
        }

        try
        {
            var ip = Jellyfin.Plugin.TwoFactorAuth.Services.BypassEvaluator.ResolveClientIp(HttpContext);
            if (!string.IsNullOrEmpty(ip))
            {
                if (cfg.AllowPasswordLoginOnLan && cfg.LanBypassCidrs is { Length: > 0 })
                {
                    foreach (var c in cfg.LanBypassCidrs)
                    {
                        if (Jellyfin.Plugin.TwoFactorAuth.Services.BypassEvaluator.IsIpInCidr(ip, c))
                        {
                            return false;
                        }
                    }
                }

                if (cfg.PasswordLoginExemptCidrs is { Length: > 0 })
                {
                    foreach (var c in cfg.PasswordLoginExemptCidrs)
                    {
                        if (Jellyfin.Plugin.TwoFactorAuth.Services.BypassEvaluator.IsIpInCidr(ip, c))
                        {
                            return false;
                        }
                    }
                }
            }
        }
        catch
        {
            // Fall through — report disabled (the reveal link still lets admins in).
        }

        return true;
    }

    // =====================================================================
    // [v2.5.11] (#71, ZEROX7) Self-service password recovery by email.
    // All anonymous; the service is SMTP-gated and rate-limited, and responses
    // are generic so they never reveal whether an account/email exists.
    // =====================================================================

    /// <summary>Body for POST PasswordReset/Request.</summary>
    public sealed class PasswordResetRequestBody
    {
        public string? Identifier { get; set; }
    }

    /// <summary>Body for POST PasswordReset/Complete.</summary>
    public sealed class PasswordResetCompleteBody
    {
        public string? Token { get; set; }

        public string? NewPassword { get; set; }
    }

    private static PasswordResetService? ResolvePasswordResetService(HttpContext ctx)
        => ctx.RequestServices.GetService(typeof(PasswordResetService)) as PasswordResetService;

    [HttpPost("PasswordReset/Request")]
    [AllowAnonymous]
    public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestBody body)
    {
        var svc = ResolvePasswordResetService(HttpContext);
        if (svc is not null)
        {
            var origin = $"{Request.Scheme}://{Request.Host}";
            var ip = RateLimiter.ClientKey(HttpContext);
            await svc.RequestResetAsync(body?.Identifier, origin, ip).ConfigureAwait(false);
        }

        // Always identical — anti-enumeration.
        return Ok(new { message = "If an account with that name or email exists and has an email on file, a reset link has been sent." });
    }

    [HttpGet("PasswordReset/Validate")]
    [AllowAnonymous]
    public IActionResult ValidatePasswordResetToken([FromQuery] string? token)
    {
        var svc = ResolvePasswordResetService(HttpContext);
        Response.Headers["Cache-Control"] = "no-store";
        return Ok(new { valid = svc is not null && svc.ValidateToken(token) });
    }

    [HttpGet("PasswordReset")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult PasswordResetPage() => ServeEmbeddedPage("password-reset.html");

    [HttpPost("PasswordReset/Complete")]
    [AllowAnonymous]
    public async Task<IActionResult> CompletePasswordReset([FromBody] PasswordResetCompleteBody body)
    {
        if (body is null || string.IsNullOrWhiteSpace(body.Token) || string.IsNullOrEmpty(body.NewPassword))
        {
            return BadRequest(new { message = "Missing reset token or new password." });
        }

        if (body.NewPassword.Length < 4)
        {
            return BadRequest(new { message = "Please choose a longer password." });
        }

        var svc = ResolvePasswordResetService(HttpContext);
        if (svc is null)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { message = "Password recovery is unavailable." });
        }

        var ok = await svc.CompleteResetAsync(body.Token, body.NewPassword).ConfigureAwait(false);
        if (!ok)
        {
            return BadRequest(new { message = "This reset link is invalid or has expired. Please request a new one." });
        }

        return Ok(new { message = "Your password has been reset. You can now sign in." });
    }

    // =====================================================================
    // [v2.5.14] (#100, Re4mstr) OIDC onboarding — set a local Jellyfin password.
    // An OIDC-auto-created user (provider has ForcePasswordSetup on) is flagged
    // MustSetPassword and landed here by the bridge. The page authenticates with
    // the just-minted session token and POSTs a chosen password; we validate it
    // against the plugin-global policy, set it, and clear the flag.
    // =====================================================================

    [HttpGet("SetPassword")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult SetPasswordPage() => ServeEmbeddedPage("setpassword.html");

    [HttpGet("SetPassword/Policy")]
    [Authorize]
    public IActionResult GetOnboardingPasswordPolicy()
    {
        var c = Plugin.Instance?.Configuration;
        Response.Headers["Cache-Control"] = "no-store";
        return Ok(new
        {
            minLength = Math.Clamp(c?.OnboardingPasswordMinLength ?? 16, 1, 256),
            requireUppercase = c?.OnboardingPasswordRequireUppercase ?? false,
            requireLowercase = c?.OnboardingPasswordRequireLowercase ?? false,
            requireDigit = c?.OnboardingPasswordRequireDigit ?? false,
        });
    }

    [HttpPost("SetPassword")]
    [Authorize]
    public async Task<IActionResult> SetOnboardingPassword([FromBody] SetPasswordBody body)
    {
        Guid userId;
        try { userId = GetCurrentUserId(); }
        catch (UnauthorizedAccessException) { return Unauthorized(); }

        // Authenticated, but still rate-limit so a hijacked session can't brute the
        // endpoint or spam ChangePassword.
        var rl = _rateLimiter.CheckAndRecord("setpw:" + userId.ToString("N"), 10, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Too many attempts. Please try again shortly." });
        }

        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (!data.MustSetPassword)
        {
            // Not pending (already set, or never flagged) — don't let this be a
            // generic password-change backdoor that skips Jellyfin's own checks.
            return BadRequest(new { message = "No password setup is pending for this account." });
        }

        var pw = body?.Password ?? string.Empty;
        var policyErr = ValidateOnboardingPassword(pw);
        if (policyErr is not null)
        {
            return BadRequest(new { message = policyErr });
        }

        try
        {
            await _userManager.ChangePassword(userId, pw).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] (#100) Failed to set onboarding password for {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = "Could not set the password. Please try again." });
        }

        await _store.MutateAsync(userId, ud => ud.MustSetPassword = false).ConfigureAwait(false);
        _logger.LogInformation("[2FA] (#100) User {UserId} set a local Jellyfin password during OIDC onboarding", userId);
        return Ok(new { ok = true });
    }

    /// <summary>[v2.5.14] (#100) Validate an onboarding password against the
    /// plugin-global policy. Returns null when valid, else a user-facing reason.</summary>
    private static string? ValidateOnboardingPassword(string pw)
    {
        var c = Plugin.Instance?.Configuration;
        var min = Math.Clamp(c?.OnboardingPasswordMinLength ?? 16, 1, 256);
        if (string.IsNullOrEmpty(pw) || pw.Length < min)
        {
            return $"Password must be at least {min} characters.";
        }

        if ((c?.OnboardingPasswordRequireUppercase ?? false) && !pw.Any(char.IsUpper))
        {
            return "Password must contain an uppercase letter.";
        }

        if ((c?.OnboardingPasswordRequireLowercase ?? false) && !pw.Any(char.IsLower))
        {
            return "Password must contain a lowercase letter.";
        }

        if ((c?.OnboardingPasswordRequireDigit ?? false) && !pw.Any(char.IsDigit))
        {
            return "Password must contain a number.";
        }

        return null;
    }

    /// <summary>[v2.5.14] (#100) Body for POST /TwoFactorAuth/SetPassword.</summary>
    public sealed class SetPasswordBody
    {
        public string Password { get; set; } = string.Empty;
    }

    // v2.5.0: shared anonymous i18n helper script. Serves an embedded JS
    // resource so pre-login pages (login.html, challenge.html, setup.html)
    // can share a single tr() loader. The .js file is added in a follow-up
    // commit — until then this endpoint returns 404, which is harmless.
    // [v2.5.12] (#79) Also served at the EXTENSIONLESS path so a CDN cache rule
    // matching "*.js" (e.g. Cloudflare's default) can't edge-cache it and freeze
    // the UI language / login strings for days, overriding our no-store header.
    // Same dodge inject.js already uses with "/inject". Pages reference the
    // extensionless URL; the ".js" route stays for back-compat / direct access.
    [HttpGet("tfa-i18n")]
    [HttpGet("tfa-i18n.js")]
    [AllowAnonymous]
    [Produces("application/javascript")]
    public IActionResult GetSharedI18nScript()
    {
        var assembly = typeof(Plugin).Assembly;
        var resourceName = $"{typeof(Plugin).Namespace}.Pages.tfa-i18n.js";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null) return NotFound();
        using var reader = new System.IO.StreamReader(stream);
        var js = reader.ReadToEnd();
        // [v2.5.12] (#79): tfa-i18n.js drives the UI language + login-page
        // strings and changes every upgrade. The previous "no-cache,
        // must-revalidate" (no no-store, no max-age=0) still let browsers serve
        // a stale copy, so language/i18n fixes didn't take effect until the
        // cache aged out. Match inject.js — tell every intermediary never to
        // store it.
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        Response.Headers.Pragma = "no-cache";
        Response.Headers.Expires = "0";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        return Content(js, "application/javascript; charset=utf-8");
    }

    // v2.5.0: externalize admin.html's huge inline <script> body so it survives
    // Jellyfin's admin SPA loadView templater. The templater treats ${...} like
    // a template-literal engine and corrupts embedded JS, throwing SyntaxError.
    //
    // v2.5.2: MUST stay [AllowAnonymous]. v2.5.1's CodeQL CWE-285 "fix" set
    // this to [Authorize] on the assumption that same-origin <script src>
    // requests carry credentials — they carry COOKIES, not the
    // `Authorization: MediaBrowser Token="..."` header that Jellyfin's auth
    // pipeline actually checks. The script 401s, never loads, admin page
    // sticks at "Computing…" and tabs stop working. The script content is
    // PURE JAVASCRIPT UI code shipped to every admin browser anyway — there
    // is nothing to gate. CodeQL #255 stays dismissed as a false-positive
    // (the named-resource heuristic flagged the "admin-" prefix).
    // [v2.5.12] (#79) Extensionless alias too — see GetSharedI18nScript: keeps a
    // CDN "*.js" cache rule from freezing the admin UI script.
    [HttpGet("admin-script")]
    [HttpGet("admin-script.js")]
    [AllowAnonymous]
    [Produces("application/javascript")]
    public IActionResult GetAdminScript()
    {
        var assembly = typeof(Plugin).Assembly;
        var resourceName = $"{typeof(Plugin).Namespace}.Pages.admin-script.js";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null) return NotFound();
        using var reader = new System.IO.StreamReader(stream);
        var js = reader.ReadToEnd();
        Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        return Content(js, "application/javascript; charset=utf-8");
    }

    [HttpGet("translations/{lang}")]
    [AllowAnonymous]
    public ActionResult GetTranslations([FromRoute] string lang)
    {
        // v2.5.0: no auth required so challenge.html and setup.html can load
        // translations before the user has signed in. Sanitize lang to prevent
        // path traversal - only letters and dashes allowed.
        Response.Headers["Cache-Control"] = "no-cache, must-revalidate";
        var clean = new string((lang ?? "en").ToLowerInvariant()
            .Where(c => (c >= 'a' && c <= 'z') || c == '-').ToArray());
        if (string.IsNullOrEmpty(clean)) clean = "en";

        var content = Helpers.ResourceReader.ReadEmbeddedText(
            $"Jellyfin.Plugin.TwoFactorAuth.Pages.translations.{clean}.json");
        if (content is null && clean != "en")
        {
            content = Helpers.ResourceReader.ReadEmbeddedText(
                "Jellyfin.Plugin.TwoFactorAuth.Pages.translations.en.json");
        }
        if (content is null) return NotFound();
        return Content(content, "application/json");
    }

    [HttpGet("Config/Export")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> ExportConfig([FromQuery] bool includeSecrets = false, [FromHeader(Name = "X-Export-Passphrase")] string? passphrase = null)
    {
        if (includeSecrets)
        {
            var guard = StepUpGuard(StepUpAction.ExportFullConfig);
            if (guard is not null) return guard;
            if (string.IsNullOrEmpty(passphrase))
                return BadRequest(new { message = "passphrase required for full export" });
            var fullEnv = await _export.BuildFullExportAsync(passphrase).ConfigureAwait(false);
            var json = System.Text.Json.JsonSerializer.Serialize(fullEnv, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            Response.Headers["Content-Disposition"] = string.Format(CultureInfo.InvariantCulture, "attachment; filename=2fa-export-full-{0:yyyyMMdd-HHmmss}.json", DateTime.UtcNow);
            return Content(json, "application/json");
        }

        var env = await _export.BuildConfigOnlyExportAsync().ConfigureAwait(false);
        var plainJson = System.Text.Json.JsonSerializer.Serialize(env, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        Response.Headers["Content-Disposition"] = string.Format(CultureInfo.InvariantCulture, "attachment; filename=2fa-export-config-{0:yyyyMMdd-HHmmss}.json", DateTime.UtcNow);
        return Content(plainJson, "application/json");
    }

    [HttpPost("Config/Import")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> ImportConfig([FromBody] ImportConfigRequest request)
    {
        if (request?.Envelope is null) return BadRequest(new { message = "envelope required" });
        var guard = StepUpGuard(StepUpAction.ImportConfig);
        if (guard is not null) return guard;

        try
        {
            var result = await _export.ImportAsync(request.Envelope, request.Passphrase).ConfigureAwait(false);
            if (!result.Success)
                return BadRequest(new { message = result.Error, warnings = result.Warnings });
            return Ok(new { ok = true, warnings = result.Warnings ?? new List<string>() });
        }
        catch (InvalidOperationException ex)
        {
            // SECURITY [v2.5.9] (audit low): don't echo internal exception
            // text to the client (consistent with the OIDC/Fido2 paths). Log
            // the detail server-side; return a generic message.
            _logger.LogWarning(ex, "[2FA] Config import failed");
            return BadRequest(new { message = "Config import failed. Check the server log for details." });
        }
    }

    [HttpGet("Users/{userId:guid}/Export")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<IActionResult> ExportUser([FromRoute] Guid userId)
    {
        // SECURITY [v2.5.9] (audit medium): gate per-user export behind
        // step-up like the full-config export. A hijacked admin session could
        // otherwise exfiltrate a user's 2FA export without re-proving control.
        var exportGuard = StepUpGuard(StepUpAction.ExportWithSecrets);
        if (exportGuard is not null) return exportGuard;

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

        // SECURITY [v2.5.5]: decrypt the stored AES-GCM ciphertext before
        // passing it to ValidateCode. Prior versions passed data.EncryptedTotpSecret
        // (the base64 ciphertext) directly, which Base32Encoding.ToBytes() then
        // threw on (lowercase letters not in base32 alphabet), causing
        // ValidateCode to return false for every legitimate rotation attempt.
        // Effect was a functional DoS on /Setup/Totp/Rotate — users could not
        // self-rotate their authenticator without admin intervention. The
        // canonical decrypt-then-validate pattern is used in every other
        // ValidateCode call site in this file (e.g. /Authenticate, /Verify).
        var rotateSecret = _totpService.DecryptSecret(data.EncryptedTotpSecret, userId);
        // SECURITY [v2.5.5] (N-A17): use the 4-arg ValidateCode overload with
        // the persisted replay floor so a recorded rotation code can't be
        // replayed within its 30s window across the in-memory dedup boundary
        // (e.g. across a restart, or by a parallel session that bypasses
        // the per-process _usedTimeSteps cache). Match the floor up-front,
        // advance it on success.
        if (!_totpService.ValidateCode(rotateSecret, req.CurrentCode, userId.ToString("N"),
                persistedFloor: data.LastUsedTotpStep, out var rotateMatchedStep))
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
        // SECURITY [v2.5.5] (N-A10, CRITICAL regression fix): encrypt the new
        // base32 secret BEFORE persisting. Prior batch-2 build stored the raw
        // base32 plaintext in EncryptedTotpSecret, which (a) leaked the live
        // TOTP seed to anyone with filesystem read access on the user store
        // and (b) broke the next sign-in because DecryptSecret would fail on
        // a non-ciphertext input. The bug was technically present pre-v2.5.5
        // too, but unreachable because the F1 ciphertext-as-base32 bug made
        // ValidateCode always return false, preventing this code path from
        // executing. Fixing F1 made this path live, surfacing the latent
        // miss-encrypt. Matches the SetupTotp / ConfirmForcedTotpEnrollment
        // pattern that every other rotate-style path already uses.
        var newEncrypted = _totpService.EncryptSecret(newSecret, userId);
        await _store.MutateAsync(userId, ud =>
        {
            ud.EncryptedTotpSecret = newEncrypted;
            if (rotateMatchedStep > ud.LastUsedTotpStep)
            {
                ud.LastUsedTotpStep = rotateMatchedStep;
            }
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
        // SECURITY [v2.5.5] (Finding 19): use proxy-aware scheme resolution.
        // Behind a TLS-terminating reverse proxy, HttpContext.Request.IsHttps
        // is always false; BypassEvaluator.ResolveScheme honours
        // X-Forwarded-Proto from trusted proxies.
        var scheme = BypassEvaluator.ResolveScheme(HttpContext);
        var host = HttpContext.Request.Host.Value;
        var url = $"{scheme}://{host}/TwoFactorAuth/PairConfirm?token={Uri.EscapeDataString(b64)}";

        // SECURITY [v2.5.6] (U6): generate the QR PNG server-side instead of
        // letting the browser build a third-party URL (api.qrserver.com).
        // The pairing URL contains a 5-minute signed token; even though the
        // confirm step requires the receiving device to be signed-in,
        // there's no need to leak the URL to a third-party QR service.
        using var qrGenU6 = new QRCoder.QRCodeGenerator();
        using var qrDataU6 = qrGenU6.CreateQrCode(url, QRCoder.QRCodeGenerator.ECCLevel.M);
        using var qrPngU6 = new QRCoder.PngByteQRCode(qrDataU6);
        var qrBytesU6 = qrPngU6.GetGraphic(8);
        var qrBase64U6 = Convert.ToBase64String(qrBytesU6);

        return Ok(new
        {
            url,
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry),
            qrPng = "data:image/png;base64," + qrBase64U6,
        });
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
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(429, new { message = $"Too many test requests. Retry in {rl.retryAfterSeconds}s." });
        }
        await _notificationService.NotifyLoginAttemptAsync("__test_user__", "127.0.0.1", "Webhook test", true).ConfigureAwait(false);
        return Ok(new { message = "Test event dispatched. Check your webhook receiver." });
    }
}

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

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

    public TwoFactorAuthController(
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        TotpService totpService,
        EmailOtpService emailOtpService,
        DeviceTokenService deviceTokenService,
        DevicePairingService devicePairingService,
        NotificationService notificationService,
        ISessionManager sessionManager,
        IUserManager userManager)
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
    [Authorize]
    [Produces("text/html")]
    public IActionResult GetSetupPage()
    {
        return ServeEmbeddedPage("setup.html");
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
        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null)
        {
            return BadRequest("Invalid or expired challenge");
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, "Account is locked out due to too many failed attempts");
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        bool valid;

        if (string.Equals(request.Method, "email", StringComparison.OrdinalIgnoreCase))
        {
            valid = _emailOtpService.ValidateCode(request.ChallengeToken, request.Code);
        }
        else
        {
            // Default: totp
            if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
            {
                await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
                return Unauthorized("No TOTP secret configured");
            }

            var decryptedSecret = _totpService.DecryptSecret(userData.EncryptedTotpSecret);
            valid = _totpService.ValidateCode(decryptedSecret, request.Code, challenge.UserId.ToString());
        }

        if (!valid)
        {
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

            return Unauthorized("Invalid 2FA code");
        }

        _challengeStore.ConsumeChallenge(request.ChallengeToken);
        await _store.ResetFailedAttemptsAsync(challenge.UserId).ConfigureAwait(false);
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

        // Generate a placeholder access token. Real Jellyfin session integration
        // should replace this with an authenticated session token from ISessionManager.
        var accessTokenBytes = RandomNumberGenerator.GetBytes(32);
        var accessToken = Convert.ToBase64String(accessTokenBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

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

        return Ok(new VerifyResponse
        {
            AccessToken = accessToken,
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
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        userData.TotpEnabled = false;
        userData.TotpVerified = false;
        userData.EncryptedTotpSecret = null;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        return Ok();
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
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        if (!userData.RegisteredDeviceIds.Contains(request.DeviceId))
        {
            userData.RegisteredDeviceIds.Add(request.DeviceId);
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }

        return Ok();
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
                IsLockedOut = isLockedOut,
            });
        }

        return Ok(result);
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
        userData.TotpEnabled = request.Enabled;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

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
    public async Task<ActionResult<IReadOnlyList<ApiKeyEntry>>> GetApiKeys()
    {
        var keys = await _store.GetApiKeysAsync().ConfigureAwait(false);
        return Ok(keys);
    }

    // -------------------------------------------------------------------------
    // 15. POST /TwoFactorAuth/ApiKeys [Authorize(Policy = "RequiresElevation")]
    // -------------------------------------------------------------------------

    [HttpPost("ApiKeys")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(ApiKeyEntry), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiKeyEntry>> CreateApiKey([FromBody, Required] CreateApiKeyRequest request)
    {
        var rawKeyBytes = RandomNumberGenerator.GetBytes(32);
        var rawKey = Convert.ToBase64String(rawKeyBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        var newEntry = new ApiKeyEntry
        {
            Key = rawKey,
            Label = request.Label,
            CreatedAt = DateTime.UtcNow,
        };

        var keys = await _store.GetApiKeysAsync().ConfigureAwait(false);
        var mutableKeys = keys.ToList();
        mutableKeys.Add(newEntry);
        await _store.SaveApiKeysAsync(mutableKeys).ConfigureAwait(false);

        return Ok(newEntry);
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
        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null)
        {
            return BadRequest("Invalid or expired challenge");
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, "Account is locked out");
        }

        // Email address lookup: Jellyfin's User entity does not expose an Email property
        // directly from IUserManager. Pass null; the EmailOtpService logs the code instead
        // of delivering it until a mail backend is wired up.
        string? email = null;

        var (_, sent) = _emailOtpService.GenerateAndSendCode(
            challenge.UserId,
            challenge.Username,
            email,
            request.ChallengeToken);

        if (!sent)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, "Email OTP rate limited or sending failed");
        }

        return Ok();
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
}

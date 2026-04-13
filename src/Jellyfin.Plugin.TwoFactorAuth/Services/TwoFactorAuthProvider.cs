using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Jellyfin authentication provider that enforces two-factor authentication.
/// It delegates primary password validation to the default Jellyfin auth provider,
/// then gates access behind TOTP / email-OTP when 2FA is enabled for the user.
/// </summary>
public class TwoFactorAuthProvider : IAuthenticationProvider
{
    private readonly IApplicationHost _appHost;
    private readonly IUserManager _userManager;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly BypassEvaluator _bypassEvaluator;
    private readonly NotificationService _notificationService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TwoFactorAuthProvider> _logger;

    public TwoFactorAuthProvider(
        IApplicationHost appHost,
        IUserManager userManager,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        BypassEvaluator bypassEvaluator,
        NotificationService notificationService,
        IHttpContextAccessor httpContextAccessor,
        ILogger<TwoFactorAuthProvider> logger)
    {
        _appHost = appHost;
        _userManager = userManager;
        _store = store;
        _challengeStore = challengeStore;
        _bypassEvaluator = bypassEvaluator;
        _notificationService = notificationService;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    /// <inheritdoc />
    public string Name => "Two-Factor Authentication";

    /// <inheritdoc />
    public bool IsEnabled => true;

    /// <inheritdoc />
    public async Task<ProviderAuthenticationResult> Authenticate(string username, string password)
    {
        var config = Plugin.Instance?.Configuration;

        // ------------------------------------------------------------------
        // 1. Resolve and call the default (password) provider for credential
        //    validation, making sure we don't recurse into ourselves.
        // ------------------------------------------------------------------
        var defaultProvider = _appHost
            .GetExports<IAuthenticationProvider>(false)
            .FirstOrDefault(p => p is not TwoFactorAuthProvider && p.IsEnabled);

        if (defaultProvider is null)
        {
            _logger.LogError("No default authentication provider found — cannot validate credentials");
            throw new AuthenticationException("Authentication provider not available");
        }

        // This throws AuthenticationException if credentials are wrong.
        ProviderAuthenticationResult baseResult = await defaultProvider
            .Authenticate(username, password)
            .ConfigureAwait(false);

        // ------------------------------------------------------------------
        // 2. If the plugin is disabled, return the base result immediately.
        // ------------------------------------------------------------------
        if (config is null || !config.Enabled)
        {
            return baseResult;
        }

        // ------------------------------------------------------------------
        // 3. Resolve the Jellyfin user entity so we have their Id.
        // ------------------------------------------------------------------
        var jellyfinUser = _userManager.GetUserByName(username);
        if (jellyfinUser is null)
        {
            // User authenticated but not found in manager — pass through.
            _logger.LogWarning("User '{Username}' authenticated but not found in IUserManager", username);
            return baseResult;
        }

        var userId = jellyfinUser.Id;

        // ------------------------------------------------------------------
        // 4. Load the user's 2FA configuration.
        // ------------------------------------------------------------------
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        bool userNeeds2Fa = userData.TotpEnabled || config.RequireForAllUsers;

        if (!userNeeds2Fa)
        {
            return baseResult;
        }

        // ------------------------------------------------------------------
        // 5. Check lockout before doing anything else.
        // ------------------------------------------------------------------
        if (await _store.IsLockedOutAsync(userId).ConfigureAwait(false))
        {
            _logger.LogWarning("User '{Username}' is locked out", username);

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = userId,
                Username = username,
                RemoteIp = GetRemoteIp() ?? string.Empty,
                DeviceId = GetHeader("X-Emby-Device-Id") ?? string.Empty,
                DeviceName = GetHeader("X-Emby-Device-Name") ?? string.Empty,
                Result = AuditResult.Locked,
                Method = "login",
                Details = "Account locked out during 2FA gate"
            }).ConfigureAwait(false);

            throw new AuthenticationException("Account is temporarily locked due to too many failed attempts");
        }

        // ------------------------------------------------------------------
        // 6. Extract request context (IP, headers, device info).
        // ------------------------------------------------------------------
        var remoteIp = GetRemoteIp();
        var forwardedFor = GetHeader("X-Forwarded-For");
        var twoFactorToken = GetHeader("X-TwoFactor-Token");
        var embyToken = GetHeader("X-Emby-Token") ?? GetHeader("X-MediaBrowser-Token");
        var deviceId = GetHeader("X-Emby-Device-Id");
        var deviceName = GetHeader("X-Emby-Device-Name") ?? string.Empty;

        // ------------------------------------------------------------------
        // 7. Evaluate bypass rules.
        // ------------------------------------------------------------------
        var apiKeys = await _store.GetApiKeysAsync().ConfigureAwait(false);

        var bypassResult = _bypassEvaluator.Evaluate(
            remoteIp,
            forwardedFor,
            twoFactorToken,
            deviceId,
            embyToken,
            userData.TrustedDevices,
            userData.RegisteredDeviceIds,
            apiKeys);

        if (bypassResult.IsBypassed)
        {
            _logger.LogInformation(
                "2FA bypassed for '{Username}' — reason: {Reason}",
                username,
                bypassResult.Reason);

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = userId,
                Username = username,
                RemoteIp = remoteIp ?? string.Empty,
                DeviceId = deviceId ?? string.Empty,
                DeviceName = deviceName,
                Result = AuditResult.Bypassed,
                Method = bypassResult.Reason ?? "bypass",
                Details = $"2FA bypassed: {bypassResult.Reason}"
            }).ConfigureAwait(false);

            // Fire-and-forget notification; don't let it fail the auth.
            _ = SafeNotifyAsync(() =>
                _notificationService.NotifyLoginAttemptAsync(username, remoteIp ?? "unknown", deviceName, false));

            return baseResult;
        }

        // ------------------------------------------------------------------
        // 8. 2FA is required and no bypass applies — build the available
        //    methods list and issue a challenge token.
        // ------------------------------------------------------------------
        var methods = new List<string>();

        if (userData.TotpEnabled && userData.TotpVerified)
        {
            methods.Add("totp");
        }

        if (config.EmailOtpEnabled)
        {
            methods.Add("email");
        }

        // If somehow no method is configured but RequireForAllUsers is on, fall back
        // to email-only so the user isn't permanently locked out at the UI level.
        if (methods.Count == 0)
        {
            methods.Add("email");
        }

        var challenge = _challengeStore.CreateChallenge(
            userId,
            username,
            methods,
            deviceId,
            deviceName,
            remoteIp);

        _logger.LogInformation(
            "2FA challenge issued for '{Username}' — token: {Token}, methods: {Methods}",
            username,
            challenge.Token,
            string.Join(", ", methods));

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = username,
            RemoteIp = remoteIp ?? string.Empty,
            DeviceId = deviceId ?? string.Empty,
            DeviceName = deviceName,
            Result = AuditResult.ChallengeIssued,
            Method = string.Join(",", methods),
            Details = $"Challenge token: {challenge.Token}"
        }).ConfigureAwait(false);

        _ = SafeNotifyAsync(() =>
            _notificationService.NotifyLoginAttemptAsync(username, remoteIp ?? "unknown", deviceName, true));

        // ------------------------------------------------------------------
        // 9. Signal to the caller that a second factor is required by
        //    throwing with a JSON payload they can parse to redirect the user.
        // ------------------------------------------------------------------
        var responsePayload = new TwoFactorRequiredResponse
        {
            TwoFactorRequired = true,
            ChallengeToken = challenge.Token,
            Methods = methods,
            ChallengePageUrl = $"web/index.html#!/TwoFactorAuthChallenge?challengeToken={Uri.EscapeDataString(challenge.Token)}"
        };

        var json = JsonSerializer.Serialize(responsePayload);
        throw new AuthenticationException(json);
    }

    /// <inheritdoc />
    /// <remarks>
    /// We always report that a password is set; the underlying default provider
    /// handles the real password check in <see cref="Authenticate"/>.
    /// </remarks>
    public bool HasPassword(User user) => true;

    /// <inheritdoc />
    /// <remarks>
    /// Password changes are delegated to Jellyfin's default provider. This
    /// provider only concerns itself with the 2FA gate.
    /// </remarks>
    public Task ChangePassword(User user, string newPassword)
    {
        // Locate the default provider and delegate, same as in Authenticate.
        var defaultProvider = _appHost
            .GetExports<IAuthenticationProvider>(false)
            .FirstOrDefault(p => p is not TwoFactorAuthProvider && p.IsEnabled);

        if (defaultProvider is null)
        {
            _logger.LogError("No default authentication provider found — cannot change password");
            return Task.CompletedTask;
        }

        return defaultProvider.ChangePassword(user, newPassword);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private string? GetRemoteIp()
    {
        var ctx = _httpContextAccessor.HttpContext;
        if (ctx is null)
        {
            return null;
        }

        return ctx.Connection.RemoteIpAddress?.ToString();
    }

    private string? GetHeader(string name)
    {
        var ctx = _httpContextAccessor.HttpContext;
        if (ctx is null)
        {
            return null;
        }

        return ctx.Request.Headers.TryGetValue(name, out var value)
            ? value.ToString()
            : null;
    }

    private static async Task SafeNotifyAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Notification failures must never affect authentication flow.
        }
    }
}

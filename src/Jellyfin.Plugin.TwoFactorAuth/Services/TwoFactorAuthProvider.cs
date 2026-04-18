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
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly BypassEvaluator _bypassEvaluator;
    private readonly NotificationService _notificationService;
    private readonly AppPasswordService _appPasswordService;
    private readonly PendingPairingService _pendingPairings;
    private readonly RateLimiter _rateLimiter;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TwoFactorAuthProvider> _logger;

    // IUserManager is NOT constructor-injected: UserManager itself takes
    // IEnumerable<IAuthenticationProvider>, so injecting it here creates a
    // circular dependency (verified by reading the DI crash log on v1.3.2).
    // We resolve it lazily from IApplicationHost when we actually need it,
    // matching the pattern used by the Jellyfin LDAP-Auth plugin.
    private IUserManager UserManager => _appHost.Resolve<IUserManager>();

    public TwoFactorAuthProvider(
        IApplicationHost appHost,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        BypassEvaluator bypassEvaluator,
        NotificationService notificationService,
        AppPasswordService appPasswordService,
        PendingPairingService pendingPairings,
        RateLimiter rateLimiter,
        IHttpContextAccessor httpContextAccessor,
        ILogger<TwoFactorAuthProvider> logger)
    {
        _appHost = appHost;
        _store = store;
        _challengeStore = challengeStore;
        _bypassEvaluator = bypassEvaluator;
        _notificationService = notificationService;
        _appPasswordService = appPasswordService;
        _pendingPairings = pendingPairings;
        _rateLimiter = rateLimiter;
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
        // 0. APP PASSWORD FAST PATH — check if the submitted password is a
        //    PBKDF2-hashed app password for this user. If so, we synthesize a
        //    successful result without calling the default provider.
        //
        //    SECURITY: Rate-limited per IP (10/min) and gated by lockout to
        //    prevent brute force. Deviceless requests (no X-Emby-Device-Id)
        //    do NOT get pre-verified device scoping — they must still pass
        //    the default provider flow below.
        // ------------------------------------------------------------------
        var earlyUser = UserManager.GetUserByName(username);
        if (earlyUser is not null && !string.IsNullOrEmpty(password))
        {
            // Lockout always takes precedence — if the account is locked, we
            // don't even check app passwords. Matches the fail-closed posture
            // the default provider would produce.
            if (await _store.IsLockedOutAsync(earlyUser.Id).ConfigureAwait(false))
            {
                _logger.LogWarning("[2FA] App-password attempt refused; user {User} is locked out", username);
                throw new AuthenticationException("Account is temporarily locked due to too many failed attempts");
            }

            // Rate-limit BEFORE any PBKDF2 work so attackers can't spin the CPU.
            var apIp = GetRemoteIp() ?? "unknown";
            var apRl = _rateLimiter.CheckAndRecord("ap_provider:" + apIp, 10, TimeSpan.FromMinutes(1));
            if (!apRl.allowed)
            {
                _logger.LogWarning("[2FA] App-password attempt rate-limited for IP {Ip}", apIp);
                throw new AuthenticationException("Too many attempts. Try again later.");
            }

            var earlyData = await _store.GetUserDataAsync(earlyUser.Id).ConfigureAwait(false);
            var matched = _appPasswordService.FindMatch(password, earlyData.AppPasswords);
            if (matched is not null)
            {
                var apDeviceId = GetDeviceHeader("X-Emby-Device-Id", "DeviceId") ?? string.Empty;
                var apDeviceName = GetHeader("X-Emby-Device-Name") ?? "Unknown";
                var apRemoteIp = GetRemoteIp() ?? string.Empty;
                var matchedId = matched.Id;
                var racedOut = false;

                // Re-verify inside the mutate to close the "revoked between
                // read and write" race. If the entry is gone, reject.
                await _store.MutateAsync(earlyUser.Id, ud =>
                {
                    var ap = ud.AppPasswords.FirstOrDefault(x => x.Id == matchedId);
                    if (ap is null) { racedOut = true; return; }
                    ap.LastUsedAt = DateTime.UtcNow;
                    ap.LastDeviceId = apDeviceId;
                    ap.LastDeviceName = apDeviceName;
                }).ConfigureAwait(false);

                if (racedOut)
                {
                    _logger.LogWarning("[2FA] App password '{Label}' was revoked mid-auth for {User}",
                        matched.Label, username);
                    throw new AuthenticationException("Invalid credentials");
                }

                // Pre-verify (user, device). Skip for empty deviceId — the
                // IsDevicePreVerified fallback would otherwise grant bypass
                // to every device of this user for 2 minutes.
                if (!string.IsNullOrEmpty(apDeviceId))
                {
                    _challengeStore.MarkDevicePreVerified(earlyUser.Id, apDeviceId);
                }

                await _store.AddAuditEntryAsync(new AuditEntry
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = earlyUser.Id,
                    Username = username,
                    RemoteIp = apRemoteIp,
                    DeviceId = apDeviceId,
                    DeviceName = apDeviceName,
                    Result = AuditResult.Bypassed,
                    Method = "app_password:" + matched.Label,
                }).ConfigureAwait(false);

                _logger.LogInformation("[2FA] App password '{Label}' matched for {User} — skipping default provider",
                    matched.Label, username);

                return new ProviderAuthenticationResult
                {
                    Username = earlyUser.Username,
                };
            }
        }

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
        var jellyfinUser = UserManager.GetUserByName(username);
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
                DeviceId = GetDeviceHeader("X-Emby-Device-Id", "DeviceId") ?? string.Empty,
                DeviceName = GetDeviceHeader("X-Emby-Device-Name", "Device") ?? string.Empty,
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
        var deviceId = GetDeviceHeader("X-Emby-Device-Id", "DeviceId");
        var deviceName = GetDeviceHeader("X-Emby-Device-Name", "Device") ?? string.Empty;

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

            // Mark device pre-verified so SessionStarted accepts it without challenge.
            _challengeStore.MarkDevicePreVerified(userId, deviceId);
            return baseResult;
        }

        // Paired-device bypass: user has explicitly approved this device ID before.
        if (!string.IsNullOrEmpty(deviceId))
        {
            var paired = userData.PairedDevices.FirstOrDefault(p =>
                BypassEvaluator.DeviceIdMatches(p.DeviceId, deviceId));
            if (paired is not null)
            {
                _logger.LogInformation("2FA paired-device bypass for '{Username}' device={Device}",
                    username, paired.DeviceName);
                var capDev = deviceId;
                var capIp = remoteIp ?? string.Empty;
                await _store.MutateAsync(userId, ud =>
                {
                    var p = ud.PairedDevices.FirstOrDefault(x =>
                        BypassEvaluator.DeviceIdMatches(x.DeviceId, capDev));
                    if (p is not null) { p.LastUsedAt = DateTime.UtcNow; p.LastIp = capIp; }
                }).ConfigureAwait(false);
                await _store.AddAuditEntryAsync(new AuditEntry
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = userId,
                    Username = username,
                    RemoteIp = capIp,
                    DeviceId = deviceId,
                    DeviceName = deviceName,
                    Result = AuditResult.Bypassed,
                    Method = "paired_device",
                }).ConfigureAwait(false);
                _challengeStore.MarkDevicePreVerified(userId, deviceId);
                return baseResult;
            }
        }

        // No bypass matched. This is a password-OK login that hit the 2FA wall.
        // Record as a pending pairing so the user can approve it from Setup.
        if (!string.IsNullOrEmpty(deviceId))
        {
            var clientName = GetHeader("X-Emby-Client")
                ?? ParseClientFromEmbyAuth(GetHeader("X-Emby-Authorization"))
                ?? string.Empty;
            _pendingPairings.Record(userId, deviceId, deviceName, clientName, remoteIp ?? string.Empty);
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

    private static string? ParseClientFromEmbyAuth(string? header)
        => ParseEmbyAuth(header, "Client");

    /// <summary>Pull a key (Client / Device / DeviceId / Version / Token) out
    /// of an X-Emby-Authorization header. Jellyfin Web and Tizen clients pack
    /// the device id in here instead of the dedicated X-Emby-Device-Id header,
    /// and not parsing it made paired-device matching silently fail for them.</summary>
    internal static string? ParseEmbyAuth(string? header, string key)
    {
        if (string.IsNullOrEmpty(header) || string.IsNullOrEmpty(key)) return null;
        var needle = key + "=";
        var idx = header.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        if (idx > 0)
        {
            var prev = header[idx - 1];
            if (prev != ',' && prev != ' ') return null;
        }
        var rest = header.Substring(idx + needle.Length);
        if (rest.StartsWith("\"", StringComparison.Ordinal))
        {
            var end = rest.IndexOf('"', 1);
            return end > 0 ? rest.Substring(1, end - 1) : null;
        }
        var comma = rest.IndexOf(',');
        return (comma > 0 ? rest.Substring(0, comma) : rest).Trim();
    }

    /// <summary>Header-first, then auth-header fallback. Prefer this to GetHeader()
    /// for device identity lookups so TV/Web clients aren't silently treated as
    /// deviceless (which breaks paired-device bypass).</summary>
    private string? GetDeviceHeader(string dedicatedHeader, string authKey)
    {
        var v = GetHeader(dedicatedHeader);
        if (!string.IsNullOrEmpty(v)) return v;
        return ParseEmbyAuth(GetHeader("X-Emby-Authorization"), authKey);
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

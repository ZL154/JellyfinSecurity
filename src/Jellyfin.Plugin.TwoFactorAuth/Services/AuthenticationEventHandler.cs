using System.Linq;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class AuthenticationEventHandler : IHostedService
{
    private readonly ISessionManager _sessionManager;
    private readonly UserTwoFactorStore _store;
    private readonly BypassEvaluator _bypassEvaluator;
    private readonly ChallengeStore _challengeStore;
    private readonly NotificationService _notificationService;
    private readonly PendingPairingService _pendingPairings;
    private readonly ILogger<AuthenticationEventHandler> _logger;

    public AuthenticationEventHandler(
        ISessionManager sessionManager,
        UserTwoFactorStore store,
        BypassEvaluator bypassEvaluator,
        ChallengeStore challengeStore,
        NotificationService notificationService,
        PendingPairingService pendingPairings,
        ILogger<AuthenticationEventHandler> logger)
    {
        _sessionManager = sessionManager;
        _store = store;
        _bypassEvaluator = bypassEvaluator;
        _challengeStore = challengeStore;
        _notificationService = notificationService;
        _pendingPairings = pendingPairings;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _sessionManager.SessionStarted += OnSessionStarted;
        _logger.LogInformation("[2FA] Subscribed to ISessionManager.SessionStarted");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _sessionManager.SessionStarted -= OnSessionStarted;
        return Task.CompletedTask;
    }

    private void OnSessionStarted(object? sender, SessionEventArgs e)
    {
        var info = e.SessionInfo;
        if (info is null)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await HandleSessionAsync(info).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[2FA] Error handling SessionStarted");
            }
        });
    }

    private async Task HandleSessionAsync(SessionInfo info)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled)
        {
            return;
        }

        if (info.UserId == Guid.Empty)
        {
            return;
        }

        _logger.LogInformation("[2FA] SessionStarted for user {Name} (id={Id}) device={Device} ip={Ip}",
            info.UserName, info.UserId, info.DeviceName, info.RemoteEndPoint);

        var userData = await _store.GetUserDataAsync(info.UserId).ConfigureAwait(false);
        _logger.LogInformation("[2FA] User {Name} TotpEnabled={Totp} Verified={Ver} RequireAll={Req}",
            info.UserName, userData.TotpEnabled, userData.TotpVerified, config.RequireForAllUsers);

        if (!userData.TotpEnabled && !config.RequireForAllUsers)
        {
            return;
        }

        // Pre-verified for THIS device+user within the 2-minute window? Normal web
        // 2FA completion path (and trust cookie / app-password bypass) hits this.
        // Scoped to deviceId so a browser's verification can't grant Swiftfin a
        // free pass — a foot-gun that was live in v1.3.0.
        if (_challengeStore.IsDevicePreVerified(info.UserId, info.DeviceId))
        {
            _logger.LogInformation("[2FA] {Name} within device-verified window — session allowed", info.UserName);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = info.UserId,
                Username = info.UserName ?? string.Empty,
                RemoteIp = info.RemoteEndPoint ?? string.Empty,
                DeviceId = info.DeviceId ?? string.Empty,
                DeviceName = info.DeviceName ?? string.Empty,
                Result = AuditResult.Success,
                Method = "totp",
            }).ConfigureAwait(false);
            return;
        }

        // Quick Connect: one-shot flag set when a verified device approves a QC
        // code. The TV's session (with a different deviceId) consumes it once.
        if (_challengeStore.ConsumeQuickConnectPending(info.UserId))
        {
            _logger.LogInformation("[2FA] {Name} QuickConnect-pending consumed — session allowed", info.UserName);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = info.UserId,
                Username = info.UserName ?? string.Empty,
                RemoteIp = info.RemoteEndPoint ?? string.Empty,
                DeviceId = info.DeviceId ?? string.Empty,
                DeviceName = info.DeviceName ?? string.Empty,
                Result = AuditResult.Bypassed,
                Method = "quickconnect",
            }).ConfigureAwait(false);
            return;
        }

        // Paired-device bypass: TV/native client the user has explicitly approved.
        var userDataPaired = userData.PairedDevices.FirstOrDefault(p =>
            !string.IsNullOrEmpty(info.DeviceId) &&
            string.Equals(p.DeviceId, info.DeviceId, StringComparison.OrdinalIgnoreCase));
        if (userDataPaired is not null)
        {
            _logger.LogInformation("[2FA] {Name} paired device {Device} — session allowed",
                info.UserName, userDataPaired.DeviceName);
            await _store.MutateAsync(info.UserId, ud =>
            {
                var p = ud.PairedDevices.FirstOrDefault(x =>
                    string.Equals(x.DeviceId, info.DeviceId, StringComparison.OrdinalIgnoreCase));
                if (p is not null)
                {
                    p.LastUsedAt = DateTime.UtcNow;
                    p.LastIp = info.RemoteEndPoint ?? string.Empty;
                }
            }).ConfigureAwait(false);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = info.UserId,
                Username = info.UserName ?? string.Empty,
                RemoteIp = info.RemoteEndPoint ?? string.Empty,
                DeviceId = info.DeviceId ?? string.Empty,
                DeviceName = info.DeviceName ?? string.Empty,
                Result = AuditResult.Bypassed,
                Method = "paired_device",
            }).ConfigureAwait(false);
            return;
        }

        var apiKeys = await _store.GetApiKeysAsync().ConfigureAwait(false);
        var bypass = _bypassEvaluator.Evaluate(
            info.RemoteEndPoint,
            null,
            null,
            info.DeviceId,
            null,
            userData.TrustedDevices,
            userData.RegisteredDeviceIds,
            apiKeys);

        if (bypass.IsBypassed)
        {
            _logger.LogInformation("[2FA] Bypass applied for {Name} from {Ip} (reason={Reason})",
                info.UserName, info.RemoteEndPoint, bypass.Reason);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = info.UserId,
                Username = info.UserName ?? string.Empty,
                RemoteIp = info.RemoteEndPoint ?? string.Empty,
                DeviceId = info.DeviceId ?? string.Empty,
                DeviceName = info.DeviceName ?? string.Empty,
                Result = AuditResult.Bypassed,
                Method = bypass.Reason ?? "bypass",
            }).ConfigureAwait(false);
            return;
        }

        _logger.LogWarning("[2FA] Blocking {Name} device={Device} until they complete /TwoFactorAuth/Login",
            info.UserName, info.DeviceId);

        // Device-scoped block: only this device gets 401'd. Other signed-in
        // devices on other platforms stay logged in. Previously user-scoped.
        _challengeStore.BlockDevice(info.UserId, info.DeviceId);

        // Record this as a pending pairing so the user can approve it from
        // Setup. Safe because SessionStarted only fires after Jellyfin's own
        // password check has passed.
        _pendingPairings.Record(
            info.UserId,
            info.DeviceId ?? string.Empty,
            info.DeviceName ?? "Unknown",
            info.Client ?? string.Empty,
            info.RemoteEndPoint ?? string.Empty);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = info.UserId,
            Username = info.UserName ?? string.Empty,
            RemoteIp = info.RemoteEndPoint ?? string.Empty,
            DeviceId = info.DeviceId ?? string.Empty,
            DeviceName = info.DeviceName ?? string.Empty,
            Result = AuditResult.ChallengeIssued,
            Method = "blocked",
        }).ConfigureAwait(false);

        // Notify admins of the login attempt that triggered a 2FA prompt
        try
        {
            await _notificationService.NotifyLoginAttemptAsync(
                info.UserName ?? "unknown",
                info.RemoteEndPoint ?? "unknown",
                info.DeviceName ?? "unknown",
                requiresTwoFactor: true).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Notification failed");
        }

        try
        {
            await _sessionManager.ReportSessionEnded(info.Id).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Failed to end session for {Name}", info.UserName);
        }
    }
}

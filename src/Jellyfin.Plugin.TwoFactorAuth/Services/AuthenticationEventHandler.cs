using System.Linq;
using Jellyfin.Data.Queries;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Devices;
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
    private readonly IDeviceManager _deviceManager;
    private readonly ILogger<AuthenticationEventHandler> _logger;

    public AuthenticationEventHandler(
        ISessionManager sessionManager,
        UserTwoFactorStore store,
        BypassEvaluator bypassEvaluator,
        ChallengeStore challengeStore,
        NotificationService notificationService,
        PendingPairingService pendingPairings,
        IDeviceManager deviceManager,
        ILogger<AuthenticationEventHandler> logger)
    {
        _sessionManager = sessionManager;
        _store = store;
        _bypassEvaluator = bypassEvaluator;
        _challengeStore = challengeStore;
        _notificationService = notificationService;
        _pendingPairings = pendingPairings;
        _deviceManager = deviceManager;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _sessionManager.SessionStarted += OnSessionStarted;
        _logger.LogDebug("[2FA] Subscribed to ISessionManager.SessionStarted");
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

        _logger.LogDebug("[2FA] SessionStarted for user {Name} (id={Id}) device={Device} ip={Ip}",
            info.UserName, info.UserId, info.DeviceName, info.RemoteEndPoint);

        // Look up the access token that Jellyfin minted for this session. The
        // middleware's response-intercept runs on a parallel code path and
        // cannot always see DeviceId (Samsung Tizen sends no X-Emby-Authorization).
        // When we decide to ALLOW a session below, we mark its token approved
        // so the middleware won't then overwrite the auth body with a challenge.
        string? approvedToken = null;
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = info.UserId });
            var match = devices.Items.FirstOrDefault(d =>
                !string.IsNullOrEmpty(info.DeviceId)
                && string.Equals(d.DeviceId, info.DeviceId, StringComparison.Ordinal));
            approvedToken = match?.AccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Couldn't look up access token for approved session");
        }

        var userData = await _store.GetUserDataAsync(info.UserId).ConfigureAwait(false);
        _logger.LogDebug("[2FA] User {Name} TotpEnabled={Totp} Verified={Ver} RequireAll={Req}",
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
            _logger.LogDebug("[2FA] {Name} within device-verified window — session allowed", info.UserName);
            if (approvedToken is not null) _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
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
            _logger.LogDebug("[2FA] {Name} QuickConnect-pending consumed — session allowed", info.UserName);
            if (approvedToken is not null) _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
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
        // Reject empty/whitespace stored deviceId — never match a missing id.
        var userDataPaired = userData.PairedDevices.FirstOrDefault(p =>
            !string.IsNullOrWhiteSpace(info.DeviceId)
            && !string.IsNullOrWhiteSpace(p.DeviceId)
            && string.Equals(p.DeviceId, info.DeviceId, StringComparison.Ordinal));
        if (userDataPaired is not null)
        {
            _logger.LogDebug("[2FA] {Name} paired device {Device} — session allowed",
                info.UserName, userDataPaired.DeviceName);
            if (approvedToken is not null) _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
            await _store.MutateAsync(info.UserId, ud =>
            {
                var p = ud.PairedDevices.FirstOrDefault(x =>
                    string.Equals(x.DeviceId, info.DeviceId, StringComparison.Ordinal));
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
            if (approvedToken is not null) _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
            // Same physical browser often hits the server via both LAN (bypassed)
            // and public-IP routes (challenged) within seconds — same deviceId,
            // different IPs (Cloudflare split-horizon, Wi-Fi captive, VPN). To
            // avoid nuisance pending entries for a device the user is actively
            // signing in from on LAN, auto-register the deviceId on LAN-bypass
            // so later non-LAN hits match `registered_device` bypass. Also
            // clear any stale pending for the same device.
            if (!string.IsNullOrEmpty(info.DeviceId))
            {
                _pendingPairings.Remove(info.UserId, info.DeviceId);
                if (string.Equals(bypass.Reason, "lan", StringComparison.OrdinalIgnoreCase)
                    && info.DeviceId!.Length <= 128)
                {
                    // Same 50-device cap as explicit /Devices/Register — prevents
                    // an attacker who controls a LAN device from spamming unique
                    // deviceIds to inflate storage.
                    await _store.MutateAsync(info.UserId, ud =>
                    {
                        if (ud.RegisteredDeviceIds.Count < 50
                            && !ud.RegisteredDeviceIds.Contains(info.DeviceId!))
                        {
                            ud.RegisteredDeviceIds.Add(info.DeviceId!);
                        }
                    }).ConfigureAwait(false);
                }
            }
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

        _logger.LogInformation("[2FA] 2FA required for {Name} — middleware will replace response with challenge",
            info.UserName);

        // Record pending pairing here (in addition to the middleware) because
        // SessionInfo.DeviceId is authoritative whereas the middleware's
        // header-parsed deviceId can come up null for clients that use
        // unusual auth header formats. PendingPairingService uses AddOrUpdate,
        // so double-recording is a safe idempotent merge — not a dupe.
        _pendingPairings.Record(
            info.UserId,
            info.DeviceId ?? string.Empty,
            info.DeviceName ?? "Unknown",
            info.Client ?? string.Empty,
            info.RemoteEndPoint ?? string.Empty);

        // We DO NOT block/revoke the access token. The middleware's response
        // intercept replaces the auth body with a challenge JSON BEFORE it
        // reaches the client. The client never sees the token unless they
        // complete 2FA via Verify (which replays the stashed body). Blocking
        // or logging out the token produced edge cases where Verify then
        // handed back a dead token, causing the infamous login loop.

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

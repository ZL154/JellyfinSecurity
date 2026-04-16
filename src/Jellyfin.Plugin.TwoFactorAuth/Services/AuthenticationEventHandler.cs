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
    private readonly ILogger<AuthenticationEventHandler> _logger;

    public AuthenticationEventHandler(
        ISessionManager sessionManager,
        UserTwoFactorStore store,
        BypassEvaluator bypassEvaluator,
        ChallengeStore challengeStore,
        ILogger<AuthenticationEventHandler> logger)
    {
        _sessionManager = sessionManager;
        _store = store;
        _bypassEvaluator = bypassEvaluator;
        _challengeStore = challengeStore;
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

        // Check if user is inside the 2-minute verification window — they typed password + code
        // Non-consuming so multiple sessions (WebSocket + HTTP) from the same login attempt all pass.
        if (_challengeStore.IsUserPreVerified(info.UserId))
        {
            _logger.LogInformation("[2FA] User {Name} within verification window — session allowed", info.UserName);
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

        // "Remember for 30 days" — if the user has ANY trusted device record created
        // within the last 30 days, they've done 2FA recently enough. Since device IDs
        // don't always match across Jellyfin's internal session types, we just check
        // that the user has an active trust record.
        var trustCutoff = DateTime.UtcNow.AddDays(-30);
        var hasRecentTrust = userData.TrustedDevices.Any(t => t.LastUsedAt >= trustCutoff || t.CreatedAt >= trustCutoff);
        if (hasRecentTrust)
        {
            _logger.LogInformation("[2FA] {Name} within 30-day trust window — session allowed", info.UserName);
            // Bump LastUsedAt on the most recent trust record
            var mostRecent = userData.TrustedDevices.OrderByDescending(t => t.LastUsedAt).FirstOrDefault();
            if (mostRecent is not null)
            {
                mostRecent.LastUsedAt = DateTime.UtcNow;
                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
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
                Method = "recent_2fa",
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

        _logger.LogWarning("[2FA] Blocking {Name} until they complete verification via /TwoFactorAuth/Login",
            info.UserName);

        _challengeStore.BlockUser(info.UserId);

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

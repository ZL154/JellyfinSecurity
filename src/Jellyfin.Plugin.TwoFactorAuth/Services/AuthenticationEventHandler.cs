using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Hosted service that subscribes to Jellyfin's SessionStarted event.
/// When a session starts for a user with 2FA enabled (and no bypass applies),
/// we immediately revoke the session. The user must then verify via 2FA to get a new session.
/// </summary>
public class AuthenticationEventHandler : IHostedService
{
    private readonly ISessionManager _sessionManager;
    private readonly UserTwoFactorStore _store;
    private readonly BypassEvaluator _bypassEvaluator;
    private readonly ILogger<AuthenticationEventHandler> _logger;

    public AuthenticationEventHandler(
        ISessionManager sessionManager,
        UserTwoFactorStore store,
        BypassEvaluator bypassEvaluator,
        ILogger<AuthenticationEventHandler> logger)
    {
        _sessionManager = sessionManager;
        _store = store;
        _bypassEvaluator = bypassEvaluator;
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

        _logger.LogWarning("[2FA] Revoking session for {Name} — 2FA required. User must complete verification via /TwoFactorAuth/Setup",
            info.UserName);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = info.UserId,
            Username = info.UserName ?? string.Empty,
            RemoteIp = info.RemoteEndPoint ?? string.Empty,
            DeviceId = info.DeviceId ?? string.Empty,
            DeviceName = info.DeviceName ?? string.Empty,
            Result = AuditResult.ChallengeIssued,
            Method = "event_revoke",
        }).ConfigureAwait(false);

        try
        {
            await _sessionManager.ReportSessionEnded(info.Id).ConfigureAwait(false);
            _logger.LogInformation("[2FA] Session ended for {Name}", info.UserName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] Failed to end session for {Name}", info.UserName);
        }
    }
}

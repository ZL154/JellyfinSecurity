using System.Linq;
using Jellyfin.Data.Queries;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Centralised "kill sessions and clear bypass state" helper. Used by:
///  - Emergency self-service lockout (user clicked "I lost my phone")
///  - Admin force-logout button on a user row
///  - Concurrent-session cap eviction (boot the oldest when over limit)
///  - Trusted/paired device revoke (kill the specific token tied to that device)
///
/// Centralising this prevents three bugs from drifting out of sync, and means
/// "what does revocation do?" has exactly one answer to read.
/// </summary>
public class SessionTerminationService
{
    private readonly ISessionManager _sessionManager;
    private readonly IDeviceManager _deviceManager;
    private readonly ChallengeStore _challengeStore;
    private readonly ILogger<SessionTerminationService> _logger;

    public SessionTerminationService(
        ISessionManager sessionManager,
        IDeviceManager deviceManager,
        ChallengeStore challengeStore,
        ILogger<SessionTerminationService> logger)
    {
        _sessionManager = sessionManager;
        _deviceManager = deviceManager;
        _challengeStore = challengeStore;
        _logger = logger;
    }

    /// <summary>Logout every access token belonging to the user and wipe all
    /// in-memory pre-verify / blocked-device flags. Returns the number of
    /// sessions terminated. Does NOT modify the user's persisted 2FA data
    /// (paired devices, trusted devices) — caller decides what to wipe.</summary>
    public async Task<int> LogoutAllForUserAsync(Guid userId)
    {
        if (userId == Guid.Empty) return 0;
        int killed = 0;
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
            foreach (var d in devices.Items.Where(d => !string.IsNullOrEmpty(d.AccessToken)))
            {
                try
                {
                    await _sessionManager.Logout(d.AccessToken).ConfigureAwait(false);
                    killed++;
                }
                catch (Exception inner)
                {
                    _logger.LogDebug(inner, "[2FA] Failed to logout token for device {Dev}", d.DeviceId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] LogoutAllForUserAsync failed enumerating devices for {UserId}", userId);
        }

        _challengeStore.WipeAllForUser(userId);
        return killed;
    }

    /// <summary>Logout the single Jellyfin device record matching the given
    /// deviceId (case-sensitive Ordinal — the same comparison used in the
    /// bypass evaluator). Used by trusted/paired device revoke handlers.</summary>
    public async Task LogoutDeviceAsync(Guid userId, string? deviceId)
    {
        if (userId == Guid.Empty || string.IsNullOrWhiteSpace(deviceId)) return;
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
            foreach (var d in devices.Items.Where(d =>
                !string.IsNullOrEmpty(d.DeviceId)
                && string.Equals(d.DeviceId, deviceId, StringComparison.Ordinal)
                && !string.IsNullOrEmpty(d.AccessToken)))
            {
                try { await _sessionManager.Logout(d.AccessToken).ConfigureAwait(false); }
                catch (Exception inner) { _logger.LogDebug(inner, "[2FA] LogoutDeviceAsync token logout failed"); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] LogoutDeviceAsync failed enumerating devices");
        }

        _challengeStore.ConsumeDevicePreVerified(userId, deviceId);
    }

    /// <summary>Enforce a per-user concurrent-session cap. Counts non-paired
    /// device records for this user (paired TVs are excluded — a user with
    /// 6 paired devices and a cap of 3 should not lose them on every login).
    /// If over the cap, evicts the oldest by DateLastActivity until under.
    /// </summary>
    public async Task EnforceSessionCapAsync(Guid userId, int cap, IReadOnlySet<string> pairedDeviceIds)
    {
        if (userId == Guid.Empty || cap <= 0) return;
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
            var nonPaired = devices.Items
                .Where(d => !string.IsNullOrEmpty(d.AccessToken)
                            && !string.IsNullOrEmpty(d.DeviceId)
                            && !pairedDeviceIds.Contains(d.DeviceId!))
                .OrderBy(d => d.DateLastActivity)
                .ToList();

            var over = nonPaired.Count - cap;
            if (over <= 0) return;

            foreach (var d in nonPaired.Take(over))
            {
                try
                {
                    await _sessionManager.Logout(d.AccessToken!).ConfigureAwait(false);
                    _logger.LogInformation("[2FA] Evicted oldest session for user {UserId} (cap={Cap})", userId, cap);
                }
                catch (Exception inner)
                {
                    _logger.LogDebug(inner, "[2FA] EnforceSessionCapAsync logout failed");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] EnforceSessionCapAsync failed");
        }
    }
}

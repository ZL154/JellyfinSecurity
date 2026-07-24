using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Jellyfin.Data.Queries;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix",
    Justification = "EventHandler suffix is reserved for delegate types but this class subscribes to ISessionManager events at startup; the suffix accurately describes its role. Renaming would churn callers without improving clarity.")]
public class AuthenticationEventHandler : IHostedService
{
    private readonly ISessionManager _sessionManager;
    private readonly UserTwoFactorStore _store;
    private readonly BypassEvaluator _bypassEvaluator;
    private readonly ChallengeStore _challengeStore;
    private readonly NotificationService _notificationService;
    private readonly PendingPairingService _pendingPairings;
    private readonly IDeviceManager _deviceManager;
    private readonly IUserManager _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthenticationEventHandler> _logger;

    public AuthenticationEventHandler(
        ISessionManager sessionManager,
        UserTwoFactorStore store,
        BypassEvaluator bypassEvaluator,
        ChallengeStore challengeStore,
        NotificationService notificationService,
        PendingPairingService pendingPairings,
        IDeviceManager deviceManager,
        IUserManager userManager,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuthenticationEventHandler> logger)
    {
        _sessionManager = sessionManager;
        _store = store;
        _bypassEvaluator = bypassEvaluator;
        _challengeStore = challengeStore;
        _notificationService = notificationService;
        _pendingPairings = pendingPairings;
        _deviceManager = deviceManager;
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
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

        // Issue #35 follow-up (v2.4.11): capture the inbound request's
        // X-Forwarded-For header NOW, while HttpContext is still alive.
        // SessionStarted fires synchronously during request processing, but
        // the Task.Run below outlives the request — reading the header
        // inside HandleSessionAsync would race with request completion and
        // see HttpContext=null. Without this snapshot the bypass evaluator's
        // LAN-bypass path was called with forwardedFor=null on every
        // authentication event, so Trust X-Forwarded-For + Trusted Proxy
        // CIDRs had no effect on the session-start bypass decision — every
        // reverse-proxy request whose peer IP fell inside a LAN-bypass CIDR
        // was treated as a LAN client regardless of the real upstream
        // client IP, silently skipping 2FA for users behind a proxy.
        string? forwardedFor = null;
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is not null)
        {
            var xff = httpContext.Request.Headers["X-Forwarded-For"].ToString();
            if (!string.IsNullOrWhiteSpace(xff))
            {
                forwardedFor = xff;
            }
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await HandleSessionAsync(info, forwardedFor).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[2FA] Error handling SessionStarted");
            }
        });
    }

    private async Task HandleSessionAsync(SessionInfo info, string? forwardedFor)
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
            approvedToken = SelectMostRecentAccessToken(
                info.DeviceId,
                devices.Items.Select(d => (d.DeviceId, d.AccessToken, d.DateLastActivity)));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Couldn't look up access token for approved session");
        }

        var userData = await _store.GetUserDataAsync(info.UserId).ConfigureAwait(false);
        _logger.LogDebug("[2FA] User {Name} TotpEnabled={Totp} Verified={Ver} RequireAll={Req}",
            info.UserName, userData.TotpEnabled, userData.TotpVerified, config.RequireForAllUsers);

        // SECURITY [v2.5.6]: align fail-safe gate with the modern policy.
        // Prior version only checked TotpEnabled + the legacy
        // RequireForAllUsers flag, ignoring (a) passkey enrolment and (b)
        // the v2.4+ EnforcementScope (Admins / All). A passkey-only user
        // signing in via Jellyfin's native /Users/AuthenticateByName would
        // hit this handler with TotpEnabled=false and (under modern
        // EnforcementScope.All but legacy flag false) get an early-return,
        // bypassing 2FA on the SessionStarted fail-safe.
        //
        // [v2.5.12] (#81, cpb34): resolve whether THIS user is actually required
        // to do 2FA, honouring admin status. Earlier this couldn't check isAdmin,
        // so under EnforcementScope.Admins it conservatively did NOT early-return
        // for non-admins either — their session then fell through to the block
        // path and hung ("Server Unavailable") even though Admins-only 2FA
        // shouldn't touch them. Now we look up admin status (IUserManager) and
        // exempt non-admins under Admins scope. FAIL SAFE: if the user can't be
        // resolved, treat as required so a real admin can never be exempted.
        var hasPasskey = userData.Passkeys.Count > 0;
        var has2fa = userData.TotpEnabled || hasPasskey;
        bool requiredByScope;
        if (config.RequireForAllUsers || config.EnforcementScope == Configuration.EnforcementScope.All)
        {
            requiredByScope = true;
        }
        else if (config.EnforcementScope == Configuration.EnforcementScope.Admins)
        {
            var u = _userManager.GetUserById(info.UserId);
            requiredByScope = u is null || u.HasPermission(PermissionKind.IsAdministrator);
        }
        else
        {
            requiredByScope = false; // Optional
        }
        if (!has2fa && !requiredByScope)
        {
            // No enrolled factor AND not required by policy for this user → 2FA
            // doesn't apply; let the session proceed untouched.
            return;
        }

        // Pre-verified for THIS device+user within the 2-minute window? Normal web
        // 2FA completion path (and trust cookie / app-password bypass) hits this.
        // Scoped to deviceId so a browser's verification can't grant Swiftfin a
        // free pass — a foot-gun that was live in v1.3.0.
        if (_challengeStore.IsDevicePreVerified(info.UserId, info.DeviceId))
        {
            _logger.LogDebug("[2FA] {Name} within device-verified window — session allowed", info.UserName);
            // [v2.5.17] (#107): the app-password fast path in TwoFactorAuthProvider
            // arms BOTH a device pre-verify AND the user-scoped one-shot below (the
            // session's deviceId may differ from the auth request's). When THIS
            // device matches the pre-verify, the one-shot is never reached by its
            // own branch — so consume it here too. Otherwise it lingers up to its
            // TTL and the next session for the same user (even an unrelated
            // real-password login on another device) would wrongly bypass 2FA.
            _challengeStore.ConsumeAppPasswordPending(info.UserId);
            if (approvedToken is not null)
            {
                _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
                // Mark verified so subsequent SessionStarted events (websocket
                // reconnects, new tabs, idle-resume) don't re-block this token
                // if conditions shift (e.g. Cloudflare Tunnel rotates the edge
                // IP and BypassEvaluator returns a different result). Issue #35.
                _challengeStore.MarkTokenVerified(approvedToken);
            }
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
            if (approvedToken is not null)
            {
                _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
                // See issue #35: subsequent SessionStarted events must not
                // re-block this legitimately-bypassed token.
                _challengeStore.MarkTokenVerified(approvedToken);
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
                Method = "quickconnect",
            }).ConfigureAwait(false);
            return;
        }

        // [v2.5.17] (#107, #102) App-password one-shot flag: set by the app-password
        // fast path in TwoFactorAuthProvider. The session Jellyfin created for that
        // login can carry a different deviceId than the auth request, so the
        // deviceId-scoped pre-verify above may miss; consume the user-scoped flag
        // here to verify the token, otherwise every follow-up request is blocked.
        if (_challengeStore.ConsumeAppPasswordPending(info.UserId))
        {
            _logger.LogDebug("[2FA] {Name} app-password session — allowed (app password is the factor)", info.UserName);
            if (approvedToken is not null)
            {
                _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
                _challengeStore.MarkTokenVerified(approvedToken);
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
                Method = "app_password",
            }).ConfigureAwait(false);
            return;
        }

        // Paired-device bypass: TV/native client the user has explicitly approved.
        // DeviceIdMatches normalises Jellyfin Web UA-hash ids (Tizen/SmartTV)
        // so the per-session timestamp suffix doesn't break matching across
        // app restarts.
        //
        // SECURITY [v2.5.9]: gate this behind BareDeviceIdBypassEnabled
        // (default false), exactly like TwoFactorAuthProvider (~line 512) and
        // TwoFactorEnforcementMiddleware (~line 522). A bare DeviceId is
        // client-supplied and not a secret; honouring it here unconditionally
        // re-opened the very bypass the provider/middleware paths already
        // close. With the flag off, paired devices must still pass the normal
        // challenge.
        var bareDevBypassEnabled = config.BareDeviceIdBypassEnabled && !string.IsNullOrEmpty(info.DeviceId);
        var userDataPaired = bareDevBypassEnabled
            ? userData.PairedDevices.FirstOrDefault(p =>
                BypassEvaluator.DeviceIdMatches(p.DeviceId, info.DeviceId))
            : null;
        if (userDataPaired is not null)
        {
            _logger.LogDebug("[2FA] {Name} paired device {Device} — session allowed",
                info.UserName, userDataPaired.DeviceName);
            if (approvedToken is not null)
            {
                _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
                // See issue #35: subsequent SessionStarted events must not
                // re-block this legitimately-bypassed token.
                _challengeStore.MarkTokenVerified(approvedToken);
            }
            await _store.MutateAsync(info.UserId, ud =>
            {
                var p = ud.PairedDevices.FirstOrDefault(x =>
                    BypassEvaluator.DeviceIdMatches(x.DeviceId, info.DeviceId));
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
        // SECURITY [v2.5.5] (F12): apply registered-device expiry filter
        // before passing the list to BypassEvaluator. When
        // RegisteredDeviceMaxAgeDays > 0, an entry is "active" only if it
        // exists in RegisteredDeviceEntries with a RegisteredAt timestamp
        // newer than the cutoff. Entries that exist only in the legacy
        // RegisteredDeviceIds list (no timestamped sibling) are passed
        // through unchanged for backwards compatibility — admins clearing
        // the list and re-registering after the v2.5.5 upgrade get fresh
        // timestamped entries automatically.
        var maxAgeDays = Plugin.Instance?.Configuration?.RegisteredDeviceMaxAgeDays ?? 0;
        var activeRegisteredIds = maxAgeDays > 0
            ? FilterActiveRegisteredDeviceIds(userData.RegisteredDeviceIds, userData.RegisteredDeviceEntries, maxAgeDays)
            : userData.RegisteredDeviceIds;
        // forwardedFor was captured synchronously in OnSessionStarted (see
        // there) so BypassEvaluator can walk X-Forwarded-For right-to-left
        // and resolve the real client IP behind a trusted reverse proxy.
        var bypass = _bypassEvaluator.Evaluate(
            info.RemoteEndPoint,
            forwardedFor,
            null,
            info.DeviceId,
            null,
            userData.TrustedDevices,
            activeRegisteredIds,
            apiKeys);

        if (bypass.IsBypassed)
        {
            _logger.LogInformation("[2FA] Bypass applied for {Name} from {Ip} (reason={Reason})",
                info.UserName, info.RemoteEndPoint, bypass.Reason);
            if (approvedToken is not null)
            {
                _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
                // CORE FIX FOR ISSUE #35: subsequent SessionStarted events
                // (websocket reconnects, new tabs, idle-resume) must not
                // re-block this legitimately-bypassed token. Critical for
                // Cloudflare Tunnel / reverse-proxy setups where the
                // RemoteIpAddress can shift between firings — making
                // BypassEvaluator return "not bypassed" on the second hit
                // and falling through to BlockToken at line 337, locking
                // the user out 5-10 minutes after login.
                _challengeStore.MarkTokenVerified(approvedToken);
            }
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
                        // SECURITY [v2.5.5] (F12): also populate the
                        // timestamped entry list so RegisteredDeviceMaxAgeDays
                        // can expire this entry later.
                        if (!ud.RegisteredDeviceEntries.Any(e =>
                                string.Equals(e.DeviceId, info.DeviceId!, StringComparison.Ordinal)))
                        {
                            ud.RegisteredDeviceEntries.Add(new Models.RegisteredDeviceEntry
                            {
                                DeviceId = info.DeviceId!,
                                RegisteredAt = DateTime.UtcNow,
                            });
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

        // Issue #27 fix: SessionStarted fires not only on initial login but
        // also on websocket reconnects, new tabs, and idle-resume — all of
        // which happen outside the 2-minute pre-verify window. If this token
        // has already completed 2FA at least once, we are NOT looking at a
        // fresh login; re-blocking it would 401 every subsequent request and
        // log the user out every few minutes. Treat verified-token
        // SessionStarted events as a reconnect: allow the session through.
        if (!string.IsNullOrEmpty(approvedToken)
            && _challengeStore.IsTokenVerified(approvedToken))
        {
            _logger.LogDebug("[2FA] {Name} SessionStarted on previously-verified token — reconnect, session allowed",
                info.UserName);
            _challengeStore.ApproveToken(approvedToken, info.UserId, info.DeviceId);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = info.UserId,
                Username = info.UserName ?? string.Empty,
                RemoteIp = info.RemoteEndPoint ?? string.Empty,
                DeviceId = info.DeviceId ?? string.Empty,
                DeviceName = info.DeviceName ?? string.Empty,
                Result = AuditResult.Success,
                Method = "reconnect",
            }).ConfigureAwait(false);
            return;
        }

        _logger.LogInformation("[2FA] 2FA required for {Name} — middleware will replace response with challenge",
            info.UserName);

        // #124: Jellyfin can emit duplicate SessionStarted events for the same
        // native-client token while opening websocket/playback sessions. Only
        // the first event owns the challenge side effects. When Jellyfin does
        // not expose a token, SessionInfo.Id plus user/device still gives a
        // stable identity for the life of that session.
        var challengeIdentity = !string.IsNullOrEmpty(approvedToken)
            ? "token:" + approvedToken
            : $"session:{info.UserId:N}|{info.DeviceId ?? string.Empty}|{info.Id ?? string.Empty}";
        if (!_challengeStore.TryBeginSessionChallenge(challengeIdentity))
        {
            _logger.LogDebug(
                "[2FA] Duplicate SessionStarted challenge suppressed for {Name} device={Device}",
                info.UserName,
                info.DeviceName);
            return;
        }

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

        // Fail closed if the response-intercept middleware misses this auth
        // response. The Verify endpoint unblocks the stashed token after a
        // successful 2FA challenge, so blocking here protects leaked tokens
        // without revoking the session out from under the normal challenge flow.
        // Note: the IsTokenVerified check above already returned for tokens
        // that have completed 2FA, so reaching here means this is genuinely
        // a fresh / unverified token.
        if (!string.IsNullOrEmpty(approvedToken))
        {
            _challengeStore.BlockToken(approvedToken);
        }

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

        // Notify admins only when this provider/middleware/session path owns
        // the shared logical-device notification. #124: native clients can
        // traverse more than one path and can rotate public IP during the
        // same playback session; neither should produce a notification storm.
        if (_challengeStore.TryBeginLoginNotification(
            info.UserId,
            info.DeviceId,
            info.DeviceName))
        {
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

    /// <summary>SECURITY [v2.5.5] (F12) + [v2.5.6] (third-audit F5+F6):
    /// filter registered-device IDs by expiry. Returns the subset of
    /// <paramref name="legacyIds"/> that either (a) has no parallel
    /// <see cref="Models.RegisteredDeviceEntry"/> (legacy entry, treated
    /// as indefinite for back-compat) or (b) has a parallel entry whose
    /// RegisteredAt is within <paramref name="maxAgeDays"/> of now.
    /// Expired entries are skipped — the user re-registers naturally on
    /// the next sign-in via the LAN-auto-register path.
    /// Promoted to <c>internal static</c> in v2.5.6 so that
    /// <see cref="TwoFactorAuthProvider"/> and
    /// <see cref="TwoFactorEnforcementMiddleware"/> can apply the same
    /// filter before passing the list to <see cref="BypassEvaluator"/> —
    /// the v2.5.5 batch-3 release only filtered in this handler, leaving
    /// the feature half-broken on the other two enforcement paths.</summary>
    internal static List<string> FilterActiveRegisteredDeviceIds(
        List<string> legacyIds,
        List<Models.RegisteredDeviceEntry> entries,
        int maxAgeDays)
    {
        var cutoff = DateTime.UtcNow.AddDays(-maxAgeDays);
        var entryById = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        foreach (var e in entries)
        {
            if (!string.IsNullOrEmpty(e.DeviceId)) entryById[e.DeviceId] = e.RegisteredAt;
        }
        var result = new List<string>(legacyIds.Count);
        foreach (var id in legacyIds)
        {
            if (entryById.TryGetValue(id, out var registeredAt))
            {
                if (registeredAt >= cutoff) result.Add(id);
                // else: expired, skip
            }
            else
            {
                // No timestamp — legacy entry, allow.
                result.Add(id);
            }
        }
        return result;
    }

    /// <summary>
    /// Resolve the token belonging to the current Jellyfin session. Multiple
    /// device records may share a DeviceId; the most recently active record is
    /// the current token, while FirstOrDefault can select a stale login.
    /// </summary>
    internal static string? SelectMostRecentAccessToken(
        string? sessionDeviceId,
        IEnumerable<(string DeviceId, string AccessToken, DateTime DateLastActivity)> candidates)
    {
        if (string.IsNullOrWhiteSpace(sessionDeviceId)) return null;

        return candidates
            .Where(c => string.Equals(c.DeviceId, sessionDeviceId, StringComparison.Ordinal)
                && !string.IsNullOrEmpty(c.AccessToken))
            .OrderByDescending(c => c.DateLastActivity)
            .Select(c => c.AccessToken)
            .FirstOrDefault();
    }
}

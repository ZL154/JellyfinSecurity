using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class ChallengeStore : IDisposable
{
    private readonly ConcurrentDictionary<string, ChallengeData> _challenges = new();

    // SECURITY [v2.5.9]: hard ceiling on outstanding challenges (DoS
    // resistance). Enforced in CreateChallenge: prune expired/consumed, then
    // evict oldest. Far above any real concurrent-login volume.
    private const int MaxChallenges = 5000;

    // Pre-verified keyed by (userId, deviceId). Prevents Swiftfin/TV sessions
    // from piggy-backing on a web sign-in's 2-minute verification window.
    private readonly ConcurrentDictionary<string, DateTime> _preVerifiedDevices = new();

    // Quick Connect needs a user-scoped SINGLE-CONSUME flag because the TV
    // session that completes after phone approval has a different device id.
    private readonly ConcurrentDictionary<Guid, DateTime> _quickConnectPending = new();

    // [v2.5.17] (#107, #102) One-shot, user-scoped "the next session for this user
    // is 2FA-satisfied because they just authenticated with an app password".
    // App passwords ARE the 2FA factor for native / third-party clients, but the
    // deviceId the app-password login carried doesn't always match the deviceId
    // Jellyfin assigns the resulting session (Symfonium et al.), so the deviceId-
    // scoped pre-verify can miss and the new token gets blocked. This flag is the
    // same device-id-independent escape hatch used for Quick Connect.
    private readonly ConcurrentDictionary<Guid, DateTime> _appPasswordPending = new();

    // Blocked devices — only the specific device that failed 2FA gets 401'd.
    // Previously user-scoped, which signed every other device out on failure.
    private readonly ConcurrentDictionary<string, DateTime> _blockedDevices = new();

    // Blocked by access token — Jellyfin Web doesn't send X-Emby-Device-Id on
    // most requests (verified via diagnostic logging), so the device-keyed
    // block silently missed every request. Tokens are always present in
    // X-Emby-Token so we block-by-token as the actual enforcement mechanism.
    private readonly ConcurrentDictionary<string, DateTime> _blockedTokens = new();

    /// <summary>SECURITY [v2.5.9] (audit TT#4, option c): set by
    /// SessionTerminationService at construction. Invoked by the cleanup
    /// sweep for each blocked token that reaches expiry while STILL blocked
    /// — which means 2FA was never completed (the success path calls
    /// UnblockToken). Rather than let the short in-memory block silently
    /// lapse into a usable token, the revoker logs the access token out at
    /// Jellyfin's session layer. Takes the token itself (the block key),
    /// which is the X-Emby-Token, so no deviceId is needed — Jellyfin Web
    /// often doesn't send one. A delegate (not constructor injection)
    /// because STS already depends on ChallengeStore — a back-reference
    /// would be a DI cycle. Null until wired.</summary>
    public Action<string>? TokenRevoker { get; set; }

    // Tokens the event handler has already approved (paired device / preVerified /
    // IP bypass). The middleware checks this before issuing a challenge so a
    // response whose paired-device status can only be determined via SessionInfo
    // (e.g. Samsung Tizen, which sends no X-Emby-Authorization) doesn't get
    // re-challenged after the event handler already said yes. Short expiry —
    // these are one-shot per /Authenticate response intercept.
    private readonly ConcurrentDictionary<string, DateTime> _approvedTokens = new();

    // Tokens that have completed 2FA at least once in this process lifetime.
    // SessionStarted fires not only on initial login but also on websocket
    // reconnects, new tabs, idle-resume, and reverse-proxy WS drops. Without
    // tracking this set, AuthenticationEventHandler's failsafe BlockToken
    // re-blocks an already-verified token whenever SessionStarted fires
    // outside the 2-minute pre-verify window, causing RequestBlockerMiddleware
    // to 401 every subsequent request — the "logged out every couple minutes"
    // loop reported in issue #27. 30-day TTL covers typical session lifetimes;
    // on process restart users re-prompt once per device which is acceptable.
    private readonly ConcurrentDictionary<string, DateTime> _verifiedTokens = new();

    // A single Jellyfin login can raise SessionStarted more than once (native
    // client reconnects, websocket setup, playback sessions). Keep the
    // challenge side effects atomic per token/session identity so those
    // duplicate events cannot repeatedly block, audit, notify and end the same
    // login. Entries share the blocked-token lifetime and are swept below.
    private readonly ConcurrentDictionary<string, DateTime> _startedSessionChallenges = new();

    // #124: one logical device login can traverse the authentication provider,
    // response middleware and SessionStarted handler, sometimes repeatedly
    // during native-client playback. All three paths share this gate so every
    // notification backend sees one event instead of a storm. The key excludes
    // RemoteIp because mobile-carrier / tunnel addresses can rotate inside the
    // same session. Successful challenge consumption clears the key so a later
    // genuine login on the same device can notify again.
    private readonly ConcurrentDictionary<string, DateTime> _loginNotifications = new();

    // PERF-P2: TCS waiters keyed by (userId, deviceId, token). The middleware
    // races SessionStarted (which runs in parallel during Jellyfin auth);
    // before this fix, the middleware polled _approvedTokens every 50ms up to
    // 500ms which added 50–500ms of latency to every successful login. Now
    // ApproveToken signals any matching waiter, and the middleware awaits
    // with a short cancellation timeout. Worst-case latency is the actual
    // race time, not 50ms-quantized.
    private readonly ConcurrentDictionary<string, TaskCompletionSource<bool>> _approvalWaiters = new();

    // PERF-P10: soft caps so a botnet can't OOM us by grabbing a billion
    // entries before the 60s cleanup sweep catches up. Under steady state
    // these caps are never hit. On overflow we drop the oldest expired
    // entries; if everything is still live, we drop the lowest-expiry entries.
    private const int SoftCapPerDict = 100_000;

    private readonly Timer _cleanupTimer;
    private bool _disposed;

    // SEC v2.4 L7: IsNullOrWhiteSpace instead of IsNullOrEmpty so a deviceId
    // of " " (single space) or "\t" can't sneak past the deviceless guard and
    // grant a user-wide pre-verify bypass.
    private static string DeviceKey(Guid userId, string? deviceId)
        => string.IsNullOrWhiteSpace(deviceId) ? $"user:{userId:N}" : $"{userId:N}|{deviceId}";

    /// <summary>
    /// Mark a specific (user, device) pair as pre-verified — the next session
    /// created for this combo within 2 minutes is allowed. Scoping to deviceId
    /// prevents other devices of the same user from silently bypassing 2FA.
    /// Deviceless / whitespace-only calls are IGNORED to avoid granting a
    /// user-wide bypass.
    /// </summary>
    public void MarkDevicePreVerified(Guid userId, string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            // Refuse to set a deviceless pre-verified mark — it would grant
            // a free-pass window to every other device of this user.
            return;
        }
        var seconds = Math.Clamp(
            Plugin.Instance?.Configuration?.PreVerifyWindowSeconds ?? 120, 30, 900);
        _preVerifiedDevices[DeviceKey(userId, deviceId)] = DateTime.UtcNow.AddSeconds(seconds);
        EnforceCap(_preVerifiedDevices);
    }

    public bool IsDevicePreVerified(Guid userId, string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        return _preVerifiedDevices.TryGetValue(DeviceKey(userId, deviceId), out var exp)
            && exp > DateTime.UtcNow;
    }

    public void ConsumeDevicePreVerified(Guid userId, string? deviceId)
    {
        _preVerifiedDevices.TryRemove(DeviceKey(userId, deviceId), out _);
    }

    /// <summary>Mark that this admin completed a fresh 2FA challenge for a
    /// sensitive action. Valid for StepUpWindowSeconds (clamped 60-900).</summary>
    public void MarkStepUpVerified(Guid userId)
    {
        var seconds = Math.Clamp(
            Plugin.Instance?.Configuration?.StepUpWindowSeconds ?? 300, 60, 900);
        _stepUpVerified[$"stepup:{userId:N}"] = DateTime.UtcNow.AddSeconds(seconds);
        EnforceCap(_stepUpVerified);
    }

    public bool IsStepUpVerified(Guid userId)
        => _stepUpVerified.TryGetValue($"stepup:{userId:N}", out var exp) && exp > DateTime.UtcNow;

    public void ClearStepUp(Guid userId)
        => _stepUpVerified.TryRemove($"stepup:{userId:N}", out _);

    // [v2.5.6] (round-5c): user-self step-up tokens. Distinct from
    // _stepUpVerified (which is admin-scope, set by MarkStepUpVerified)
    // because user-self step-ups should NOT be reused across distinct
    // factor mutations — they expire after one consume so a stolen
    // session can't ride a single verification for multiple takeovers.
    // Each token is single-use, 60s TTL, opaque random string keyed to
    // its issuing user.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (Guid UserId, DateTime ExpiresAt)> _userStepUpTokens = new();

    /// <summary>Mint a single-use 60-second user step-up token after the
    /// user proved possession of a current factor (TOTP code, recovery
    /// code, or passkey assertion). The token is consumed by
    /// <see cref="ConsumeUserStepUpToken"/> on the subsequent factor-
    /// mutation request.</summary>
    public string MintUserStepUpToken(Guid userId)
    {
        var token = System.Convert.ToHexString(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        _userStepUpTokens[token] = (userId, DateTime.UtcNow.AddSeconds(60));
        // EnforceCap is typed for ConcurrentDictionary<string, DateTime> so it
        // can't be reused here. Inline a small cap: if we drift over 4096
        // outstanding tokens evict any already-expired entries (we don't pre-
        // emptively evict valid ones — they expire on their own in <= 60s).
        if (_userStepUpTokens.Count > 4096)
        {
            var now = DateTime.UtcNow;
            foreach (var kv in _userStepUpTokens)
            {
                if (kv.Value.ExpiresAt <= now) _userStepUpTokens.TryRemove(kv.Key, out _);
            }
        }
        return token;
    }

    /// <summary>Validate + consume a user step-up token. Returns true iff
    /// the token exists, was minted for <paramref name="userId"/>, and is
    /// not expired. TryRemove makes consumption atomic — a race between
    /// two requests both submitting the same token will result in exactly
    /// one win, matching the single-use semantic.</summary>
    public bool ConsumeUserStepUpToken(string? token, Guid userId)
    {
        if (string.IsNullOrEmpty(token)) return false;
        if (!_userStepUpTokens.TryRemove(token, out var entry)) return false;
        if (entry.UserId != userId) return false;
        if (entry.ExpiresAt <= DateTime.UtcNow) return false;
        return true;
    }

    /// <summary>Mark a pending cross-device Quick Connect acceptance. Single consume.</summary>
    public void MarkQuickConnectPending(Guid userId)
    {
        _quickConnectPending[userId] = DateTime.UtcNow.AddMinutes(2);
    }

    public bool ConsumeQuickConnectPending(Guid userId)
    {
        if (_quickConnectPending.TryRemove(userId, out var exp) && exp > DateTime.UtcNow)
            return true;
        return false;
    }

    /// <summary>[v2.5.17] (#107) Mark that this user just authenticated with an app
    /// password, so the next session created for them is treated as 2FA-satisfied.
    /// Single consume, 2-minute window.</summary>
    public void MarkAppPasswordPending(Guid userId)
    {
        _appPasswordPending[userId] = DateTime.UtcNow.AddMinutes(2);
    }

    public bool ConsumeAppPasswordPending(Guid userId)
    {
        if (_appPasswordPending.TryRemove(userId, out var exp) && exp > DateTime.UtcNow)
            return true;
        return false;
    }

    public void BlockDevice(Guid userId, string? deviceId)
    {
        _blockedDevices[DeviceKey(userId, deviceId)] = DateTime.UtcNow.AddHours(24);
        EnforceCap(_blockedDevices);
    }

    public void UnblockDevice(Guid userId, string? deviceId)
    {
        _blockedDevices.TryRemove(DeviceKey(userId, deviceId), out _);
    }

    /// <summary>Clear block for ALL devices of this user — used after /Authenticate succeeds.</summary>
    public void UnblockAllForUser(Guid userId)
    {
        var prefix = $"{userId:N}|";
        var userless = DeviceKey(userId, null);
        foreach (var kv in _blockedDevices)
        {
            if (kv.Key.StartsWith(prefix, StringComparison.Ordinal) || kv.Key == userless)
            {
                _blockedDevices.TryRemove(kv.Key, out _);
            }
        }
    }

    /// <summary>Wipe ALL in-memory challenge state for a user — pre-verified,
    /// blocked, and quick-connect-pending. Call on 2FA disable so a security
    /// response fully revokes every form of bypass immediately.</summary>
    public void WipeAllForUser(Guid userId)
    {
        UnblockAllForUser(userId);
        _quickConnectPending.TryRemove(userId, out _);
        _appPasswordPending.TryRemove(userId, out _);
        var prefix = $"{userId:N}|";
        var userless = $"user:{userId:N}";
        foreach (var kv in _preVerifiedDevices)
        {
            if (kv.Key.StartsWith(prefix, StringComparison.Ordinal) || kv.Key == userless)
            {
                _preVerifiedDevices.TryRemove(kv.Key, out _);
            }
        }
    }

    public bool IsDeviceBlocked(Guid userId, string? deviceId)
    {
        var key = DeviceKey(userId, deviceId);
        if (_blockedDevices.TryGetValue(key, out var exp))
        {
            if (exp > DateTime.UtcNow) return true;
            _blockedDevices.TryRemove(key, out _);
        }
        return false;
    }

    /// <summary>Block a specific access token. Middleware 401s every request
    /// using it until the user completes 2FA and UnblockToken is called.
    /// Short expiry (10 min) so a token that never gets verified is unblocked
    /// by timeout — at which point the cleanup sweep should Logout the token
    /// anyway. Previously 24h, which caused stale blocks that 401'd legitimate
    /// sessions after testing.</summary>
    public void BlockToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _blockedTokens[token] = DateTime.UtcNow.AddMinutes(10);
        EnforceCap(_blockedTokens);
    }

    public void UnblockToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _blockedTokens.TryRemove(token, out _);
    }

    public bool IsTokenBlocked(string token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        if (_blockedTokens.TryGetValue(token, out var exp))
        {
            if (exp > DateTime.UtcNow) return true;
            _blockedTokens.TryRemove(token, out _);
        }
        return false;
    }

    /// <summary>Mark an access token as having completed 2FA. Called from the
    /// /Authenticate success path and from the /Verify completion path.
    /// AuthenticationEventHandler checks this before its failsafe BlockToken
    /// so it doesn't re-block a token that has already been verified — without
    /// which SessionStarted reconnects 3+ minutes after login cause a logout
    /// loop (issue #27).</summary>
    public void MarkTokenVerified(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _verifiedTokens[token] = DateTime.UtcNow.AddDays(30);
        EnforceCap(_verifiedTokens);
        // [v2.5.7] (issue #52): also persist a SHA-256 hash so the verified
        // state survives a Jellyfin restart. See VerifiedTokenPersistence.
        _verifiedTokenPersistence?.MarkVerified(token);
    }

    public bool IsTokenVerified(string token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        if (_verifiedTokens.TryGetValue(token, out var exp))
        {
            if (exp > DateTime.UtcNow) return true;
            _verifiedTokens.TryRemove(token, out _);
        }
        // [v2.5.7] (issue #52): fall back to the persistent hash store. On a
        // fresh process the in-memory dict is empty for every existing token,
        // so without this check the failsafe BlockToken would re-block every
        // already-verified session. Re-hydrate the in-memory dict on hit so
        // subsequent checks stay on the fast path.
        if (_verifiedTokenPersistence?.IsVerified(token) == true)
        {
            _verifiedTokens[token] = DateTime.UtcNow.AddDays(30);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Atomically begin the challenge side effects for one access-token or
    /// session identity. Returns false when another SessionStarted handler has
    /// already begun the same challenge during the ten-minute block window.
    /// </summary>
    public bool TryBeginSessionChallenge(string identity)
    {
        if (string.IsNullOrWhiteSpace(identity)) return false;

        var now = DateTime.UtcNow;
        while (true)
        {
            if (_startedSessionChallenges.TryGetValue(identity, out var expiry))
            {
                if (expiry > now) return false;
                _startedSessionChallenges.TryRemove(identity, out _);
            }

            if (_startedSessionChallenges.TryAdd(identity, now.AddMinutes(10)))
            {
                EnforceCap(_startedSessionChallenges);
                return true;
            }
        }
    }

    public bool TryBeginLoginNotification(Guid userId, string? deviceId, string? deviceName)
    {
        if (userId == Guid.Empty) return false;

        var key = LoginNotificationKey(userId, deviceId, deviceName);
        var now = DateTime.UtcNow;
        while (true)
        {
            if (_loginNotifications.TryGetValue(key, out var expiry))
            {
                if (expiry > now) return false;
                _loginNotifications.TryRemove(key, out _);
            }

            if (_loginNotifications.TryAdd(key, now.AddMinutes(10)))
            {
                EnforceCap(_loginNotifications);
                return true;
            }
        }
    }

    /// <summary>Mark an access token as pre-approved by the event handler so the
    /// response-intercept middleware won't overwrite the auth body with a 2FA
    /// challenge. Approval is bound to (userId, deviceId, token) so a stale
    /// flag on a recycled token can't leak bypass across users/devices.
    /// Short 30s TTL — only needs to survive the single /Authenticate round trip.
    /// PERF-P2: also signals any TCS waiter the middleware registered, so the
    /// middleware wakes immediately instead of polling.</summary>
    public void ApproveToken(string token, Guid userId, string? deviceId)
    {
        if (string.IsNullOrEmpty(token)) return;
        var key = ApprovalKey(token, userId, deviceId);
        _approvedTokens[key] = DateTime.UtcNow.AddSeconds(30);
        EnforceCap(_approvedTokens);
        // Signal any waiter immediately. TrySetResult is cheap if no waiter.
        if (_approvalWaiters.TryRemove(key, out var tcs))
        {
            tcs.TrySetResult(true);
        }
    }

    /// <summary>Single-use read — removes the flag atomically so a second call
    /// with the same key returns false. This prevents a stale approval from
    /// surviving into a second auth request reusing the same access token.</summary>
    public bool ConsumeTokenApproval(string token, Guid userId, string? deviceId)
    {
        if (string.IsNullOrEmpty(token)) return false;
        var key = ApprovalKey(token, userId, deviceId);
        if (_approvedTokens.TryRemove(key, out var exp) && exp > DateTime.UtcNow)
        {
            return true;
        }
        return false;
    }

    /// <summary>PERF-P2: register a one-shot waiter that completes when
    /// ApproveToken is called for the same key, or after the timeout elapses.
    /// Returns true if approval came in, false on timeout.
    ///
    /// Called by the response-intercept middleware AFTER ConsumeTokenApproval
    /// returns false (covers the race where SessionStarted hasn't completed
    /// yet). Replaces the earlier 50ms-tick polling loop. The waiter is removed
    /// when ApproveToken signals it, or when the timeout cleanup fires.</summary>
    public async Task<bool> WaitForApprovalAsync(string token, Guid userId, string? deviceId, TimeSpan timeout)
    {
        if (string.IsNullOrEmpty(token)) return false;
        var key = ApprovalKey(token, userId, deviceId);

        // Check first — if approval already arrived, no need to wait.
        if (ConsumeTokenApproval(token, userId, deviceId)) return true;

        // RunContinuationsAsynchronously prevents the ApproveToken caller from
        // running our continuation synchronously on its thread (which could
        // deadlock if the caller holds locks).
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var registered = _approvalWaiters.GetOrAdd(key, tcs);
        // If another concurrent caller registered first, await theirs instead.
        // Either way, ApproveToken will signal whichever TCS won.
        var winner = registered;

        // Re-check approval AFTER registering the waiter to close the
        // register-then-approve race: ApproveToken might have run in the
        // microsecond between the first check and GetOrAdd.
        if (ConsumeTokenApproval(token, userId, deviceId))
        {
            // We won the race against ApproveToken; tear our waiter down.
            if (_approvalWaiters.TryRemove(key, out var stale)) stale.TrySetResult(false);
            return true;
        }

        try
        {
            using var cts = new System.Threading.CancellationTokenSource(timeout);
            await using var _ = cts.Token.Register(() =>
            {
                if (_approvalWaiters.TryRemove(key, out var t)) t.TrySetResult(false);
            });
            return await winner.Task.ConfigureAwait(false);
        }
        catch
        {
            // On any unexpected error, treat as no-approval; middleware falls
            // through to issuing a challenge (the safe default).
            return false;
        }
    }

    private static string ApprovalKey(string token, Guid userId, string? deviceId)
        => $"{userId:N}|{deviceId ?? string.Empty}|{token}";

    /// <summary>PERF-P10: enforce SoftCapPerDict on a DateTime-valued
    /// ConcurrentDictionary. Cheap fast path: if under cap, return. Slow
    /// path runs only on the unhappy case where a botnet outraced the 60s
    /// sweep. We drop entries whose expiry is nearest (oldest first).</summary>
    private static void EnforceCap(ConcurrentDictionary<string, DateTime> dict)
    {
        if (dict.Count <= SoftCapPerDict) return;
        // Snapshot, sort by expiry ascending, evict the bottom 10% to amortise.
        var snapshot = dict.ToArray();
        Array.Sort(snapshot, (a, b) => a.Value.CompareTo(b.Value));
        var evictCount = snapshot.Length / 10;
        for (var i = 0; i < evictCount; i++)
        {
            dict.TryRemove(snapshot[i].Key, out _);
        }
    }

    // v2.5.0: short-lived per-admin "recently re-authenticated for a sensitive
    // action" markers. Reuses this class's cleanup timer + cap infrastructure.
    private readonly ConcurrentDictionary<string, DateTime> _stepUpVerified = new();

    // Seen PairConfirm signatures — prevents an attacker with a captured
    // signed QR-pair link from replaying it inside the 5-minute TTL window
    // after the user unpaired/paired anew.
    private readonly ConcurrentDictionary<string, DateTime> _seenPairTokens = new();

    /// <summary>Try to mark this pair-confirm token as consumed. Returns false
    /// if the exact signature was seen before (replay).</summary>
    public bool TryConsumePairToken(string signature)
    {
        if (string.IsNullOrEmpty(signature)) return true;
        // 10-minute window covers the 5-minute token TTL with generous margin.
        return _seenPairTokens.TryAdd(signature, DateTime.UtcNow.AddMinutes(10));
    }

    public void UnblockAllTokensForUser(Guid userId, IEnumerable<string> userTokens)
    {
        foreach (var t in userTokens)
        {
            if (!string.IsNullOrEmpty(t)) _blockedTokens.TryRemove(t, out _);
        }
    }

    // [v2.5.7] (issue #52, derpacco): optional persistence layer for the
    // verified-token set. Injected by DI when available; null is tolerated
    // so the parameterless ctor (tests / fuzz harness) still works.
    private readonly VerifiedTokenPersistence? _verifiedTokenPersistence;

    public ChallengeStore()
        : this(null)
    {
    }

    public ChallengeStore(VerifiedTokenPersistence? verifiedTokenPersistence)
    {
        _verifiedTokenPersistence = verifiedTokenPersistence;
        // Run cleanup every 60 seconds
        _cleanupTimer = new Timer(
            _ => RemoveExpiredChallenges(),
            null,
            TimeSpan.FromSeconds(60),
            TimeSpan.FromSeconds(60));
    }

    public ChallengeData CreateChallenge(
        Guid userId,
        string username,
        List<string> methods,
        string? deviceId,
        string? deviceName,
        string? remoteIp,
        bool enrollmentRequired = false)
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
        var token = Base64UrlEncode(tokenBytes);

        int ttlSeconds = Plugin.Instance?.Configuration?.ChallengeTokenTtlSeconds ?? 300;
        var now = DateTime.UtcNow;

        var challenge = new ChallengeData
        {
            Token = token,
            UserId = userId,
            Username = username,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            AvailableMethods = methods,
            EnrollmentRequired = enrollmentRequired,
            DeviceId = deviceId,
            DeviceName = deviceName,
            RemoteIp = remoteIp,
            IsConsumed = false
        };

        // SECURITY [v2.5.9]: hard cap on the in-memory challenge map for DoS
        // resistance. TTL + the periodic sweep already bound it; this makes
        // the ceiling explicit. Prune expired/consumed first, then evict the
        // oldest if still at the cap. 5000 is far above real concurrent
        // login volume on a self-hosted instance.
        if (_challenges.Count >= MaxChallenges)
        {
            var nowCap = DateTime.UtcNow;
            foreach (var kv in _challenges)
            {
                if (kv.Value.IsConsumed || kv.Value.ExpiresAt <= nowCap) _challenges.TryRemove(kv.Key, out _);
            }
            while (_challenges.Count >= MaxChallenges)
            {
                string? oldestKey = null;
                var oldestExp = DateTime.MaxValue;
                foreach (var kv in _challenges)
                {
                    if (kv.Value.ExpiresAt < oldestExp) { oldestExp = kv.Value.ExpiresAt; oldestKey = kv.Key; }
                }
                if (oldestKey is null) break;
                _challenges.TryRemove(oldestKey, out _);
            }
        }

        _challenges[token] = challenge;
        return challenge;
    }

    public ChallengeData? GetChallenge(string token)
    {
        if (!_challenges.TryGetValue(token, out var challenge))
        {
            return null;
        }

        if (challenge.IsConsumed || challenge.ExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        return challenge;
    }

    public bool ConsumeChallenge(string token)
    {
        if (!_challenges.TryGetValue(token, out var challenge))
        {
            return false;
        }

        if (challenge.ExpiresAt <= DateTime.UtcNow)
        {
            return false;
        }

        // SEC v2.4 L2: atomic claim. Previously this was check-then-set which
        // allowed two concurrent /Verify requests against the same challenge
        // token to both succeed and mint two sessions from one OTP code.
        var consumed = challenge.TryConsume();
        if (consumed)
        {
            ClearLoginNotification(challenge);
        }
        return consumed;
    }

    public void RemoveChallenge(string token)
    {
        if (_challenges.TryRemove(token, out var challenge))
        {
            ClearLoginNotification(challenge);
        }
    }

    private void RemoveExpiredChallenges()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in _challenges)
        {
            if (kvp.Value.IsConsumed || kvp.Value.ExpiresAt <= now)
            {
                _challenges.TryRemove(kvp.Key, out _);
            }
        }
        foreach (var kv in _preVerifiedDevices)
        {
            if (kv.Value <= now) _preVerifiedDevices.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _quickConnectPending)
        {
            if (kv.Value <= now) _quickConnectPending.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _appPasswordPending)
        {
            if (kv.Value <= now) _appPasswordPending.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _blockedDevices)
        {
            if (kv.Value <= now) _blockedDevices.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _blockedTokens)
        {
            if (kv.Value <= now)
            {
                _blockedTokens.TryRemove(kv.Key, out _);
                // SECURITY [v2.5.9] (audit TT#4, option c): still-blocked at
                // expiry == 2FA was never completed (the success path calls
                // UnblockToken). Rather than let the block silently lapse into
                // a usable token, actively log the access token out at
                // Jellyfin's session layer via the wired revoker. Best-effort.
                if (TokenRevoker is { } revoke)
                {
                    try { revoke(kv.Key); }
                    catch { /* best-effort revoke; never let the sweep throw */ }
                }
            }
        }
        foreach (var kv in _approvedTokens)
        {
            if (kv.Value <= now) _approvedTokens.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _verifiedTokens)
        {
            if (kv.Value <= now) _verifiedTokens.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _loginNotifications)
        {
            if (kv.Value <= now) _loginNotifications.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _startedSessionChallenges)
        {
            if (kv.Value <= now) _startedSessionChallenges.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _seenPairTokens)
        {
            if (kv.Value <= now) _seenPairTokens.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _stepUpVerified)
        {
            if (kv.Value <= now) _stepUpVerified.TryRemove(kv.Key, out _);
        }
        // [v2.5.6] (round-5c): also evict expired user step-up tokens so the
        // dict doesn't grow unbounded if users mint without consuming.
        foreach (var kv in _userStepUpTokens)
        {
            if (kv.Value.ExpiresAt <= now) _userStepUpTokens.TryRemove(kv.Key, out _);
        }
    }

    private static string LoginNotificationKey(
        Guid userId,
        string? deviceId,
        string? deviceName)
    {
        var identity = !string.IsNullOrWhiteSpace(deviceId)
            ? deviceId.Trim()
            : !string.IsNullOrWhiteSpace(deviceName)
                ? "name:" + deviceName.Trim()
                : "unknown";
        return $"{userId:N}|{identity}";
    }

    private void ClearLoginNotification(ChallengeData challenge)
        => _loginNotifications.TryRemove(
            LoginNotificationKey(
                challenge.UserId,
                challenge.DeviceId,
                challenge.DeviceName),
            out _);

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cleanupTimer.Dispose();
        GC.SuppressFinalize(this);
    }
}

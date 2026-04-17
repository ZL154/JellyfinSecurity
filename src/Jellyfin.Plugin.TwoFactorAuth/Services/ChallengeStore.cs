using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class ChallengeStore : IDisposable
{
    private readonly ConcurrentDictionary<string, ChallengeData> _challenges = new();

    // Pre-verified keyed by (userId, deviceId). Prevents Swiftfin/TV sessions
    // from piggy-backing on a web sign-in's 2-minute verification window.
    private readonly ConcurrentDictionary<string, DateTime> _preVerifiedDevices = new();

    // Quick Connect needs a user-scoped SINGLE-CONSUME flag because the TV
    // session that completes after phone approval has a different device id.
    private readonly ConcurrentDictionary<Guid, DateTime> _quickConnectPending = new();

    // Blocked devices — only the specific device that failed 2FA gets 401'd.
    // Previously user-scoped, which signed every other device out on failure.
    private readonly ConcurrentDictionary<string, DateTime> _blockedDevices = new();

    // Blocked by access token — Jellyfin Web doesn't send X-Emby-Device-Id on
    // most requests (verified via diagnostic logging), so the device-keyed
    // block silently missed every request. Tokens are always present in
    // X-Emby-Token so we block-by-token as the actual enforcement mechanism.
    private readonly ConcurrentDictionary<string, DateTime> _blockedTokens = new();

    // Tokens the event handler has already approved (paired device / preVerified /
    // IP bypass). The middleware checks this before issuing a challenge so a
    // response whose paired-device status can only be determined via SessionInfo
    // (e.g. Samsung Tizen, which sends no X-Emby-Authorization) doesn't get
    // re-challenged after the event handler already said yes. Short expiry —
    // these are one-shot per /Authenticate response intercept.
    private readonly ConcurrentDictionary<string, DateTime> _approvedTokens = new();

    private readonly Timer _cleanupTimer;
    private bool _disposed;

    private static string DeviceKey(Guid userId, string? deviceId)
        => string.IsNullOrEmpty(deviceId) ? $"user:{userId:N}" : $"{userId:N}|{deviceId}";

    /// <summary>
    /// Mark a specific (user, device) pair as pre-verified — the next session
    /// created for this combo within 2 minutes is allowed. Scoping to deviceId
    /// prevents other devices of the same user from silently bypassing 2FA.
    /// Deviceless calls are IGNORED to avoid granting a user-wide bypass.
    /// </summary>
    public void MarkDevicePreVerified(Guid userId, string? deviceId)
    {
        if (string.IsNullOrEmpty(deviceId))
        {
            // Refuse to set a deviceless pre-verified mark — it would grant
            // a 2-minute free-pass to every other device of this user.
            return;
        }
        _preVerifiedDevices[DeviceKey(userId, deviceId)] = DateTime.UtcNow.AddMinutes(2);
    }

    public bool IsDevicePreVerified(Guid userId, string? deviceId)
    {
        if (string.IsNullOrEmpty(deviceId)) return false;
        return _preVerifiedDevices.TryGetValue(DeviceKey(userId, deviceId), out var exp)
            && exp > DateTime.UtcNow;
    }

    public void ConsumeDevicePreVerified(Guid userId, string? deviceId)
    {
        _preVerifiedDevices.TryRemove(DeviceKey(userId, deviceId), out _);
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

    public void BlockDevice(Guid userId, string? deviceId)
    {
        _blockedDevices[DeviceKey(userId, deviceId)] = DateTime.UtcNow.AddHours(24);
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

    /// <summary>Mark an access token as pre-approved by the event handler so the
    /// response-intercept middleware won't overwrite the auth body with a 2FA
    /// challenge. Approval is bound to (userId, deviceId, token) so a stale
    /// flag on a recycled token can't leak bypass across users/devices.
    /// Short 30s TTL — only needs to survive the single /Authenticate round trip.</summary>
    public void ApproveToken(string token, Guid userId, string? deviceId)
    {
        if (string.IsNullOrEmpty(token)) return;
        _approvedTokens[ApprovalKey(token, userId, deviceId)] = DateTime.UtcNow.AddSeconds(30);
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

    private static string ApprovalKey(string token, Guid userId, string? deviceId)
        => $"{userId:N}|{deviceId ?? string.Empty}|{token}";

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

    public ChallengeStore()
    {
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
        string? remoteIp)
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
            DeviceId = deviceId,
            DeviceName = deviceName,
            RemoteIp = remoteIp,
            IsConsumed = false
        };

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

        if (challenge.IsConsumed || challenge.ExpiresAt <= DateTime.UtcNow)
        {
            return false;
        }

        challenge.IsConsumed = true;
        return true;
    }

    public void RemoveChallenge(string token)
    {
        _challenges.TryRemove(token, out _);
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
        foreach (var kv in _blockedDevices)
        {
            if (kv.Value <= now) _blockedDevices.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _blockedTokens)
        {
            if (kv.Value <= now) _blockedTokens.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _approvedTokens)
        {
            if (kv.Value <= now) _approvedTokens.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _seenPairTokens)
        {
            if (kv.Value <= now) _seenPairTokens.TryRemove(kv.Key, out _);
        }
    }

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

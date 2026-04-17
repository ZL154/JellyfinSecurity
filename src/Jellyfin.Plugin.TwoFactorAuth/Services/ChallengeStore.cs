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

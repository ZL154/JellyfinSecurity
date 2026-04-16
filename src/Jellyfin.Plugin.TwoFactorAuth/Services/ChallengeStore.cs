using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class ChallengeStore : IDisposable
{
    private readonly ConcurrentDictionary<string, ChallengeData> _challenges = new();
    private readonly ConcurrentDictionary<Guid, DateTime> _preVerifiedUsers = new();
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    /// <summary>
    /// Mark a user as pre-verified — the next session created for this user
    /// (within 2 minutes) will be allowed to persist by the auth event handler.
    /// </summary>
    public void MarkUserPreVerified(Guid userId)
    {
        _preVerifiedUsers[userId] = DateTime.UtcNow.AddMinutes(2);
    }

    /// <summary>
    /// Consume the pre-verified flag for a user. Returns true once, then false
    /// on subsequent calls. Used by event handler to allow one session per verification.
    /// </summary>
    public bool ConsumeUserPreVerified(Guid userId)
    {
        if (_preVerifiedUsers.TryRemove(userId, out var expiry) && expiry > DateTime.UtcNow)
        {
            return true;
        }
        return false;
    }

    /// <summary>
    /// Check whether a user has the pre-verified flag set, without consuming it.
    /// Used to allow ALL sessions created within the verification window
    /// (browser may open WebSocket + multiple connections, each creating a session).
    /// </summary>
    public bool IsUserPreVerified(Guid userId)
    {
        if (_preVerifiedUsers.TryGetValue(userId, out var expiry) && expiry > DateTime.UtcNow)
        {
            return true;
        }
        return false;
    }

    // Users blocked by 2FA requirement — their authenticated requests return 401
    // until they complete verification via /TwoFactorAuth/Login.
    private readonly ConcurrentDictionary<Guid, DateTime> _blockedUsers = new();

    public void BlockUser(Guid userId)
    {
        _blockedUsers[userId] = DateTime.UtcNow.AddHours(24);
    }

    public void UnblockUser(Guid userId)
    {
        _blockedUsers.TryRemove(userId, out _);
    }

    public bool IsUserBlocked(Guid userId)
    {
        if (_blockedUsers.TryGetValue(userId, out var expiry))
        {
            if (expiry > DateTime.UtcNow) return true;
            _blockedUsers.TryRemove(userId, out _);
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

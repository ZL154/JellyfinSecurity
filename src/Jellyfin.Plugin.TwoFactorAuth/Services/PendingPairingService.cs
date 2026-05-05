using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Tracks devices that hit the 2FA wall on a passwordless / native-client login.
/// Admin/user can approve them from the Setup page, which adds them to the
/// user's PairedDevices list. Strictly in-memory; entries expire after 30 min.
/// </summary>
public class PendingPairingService : IDisposable
{
    private readonly ConcurrentDictionary<string, PendingEntry> _entries = new();
    // PERF-P8: O(1) per-user count instead of LINQ-Count over up to 5000
    // entries on every Record. Kept in sync with _entries by Record/Remove/
    // RemoveAllForUser/Cleanup.
    private readonly ConcurrentDictionary<Guid, int> _perUserCount = new();
    private readonly Timer _cleanup;
    private readonly ILogger<PendingPairingService> _logger;
    private bool _disposed;

    public PendingPairingService(ILogger<PendingPairingService> logger)
    {
        _logger = logger;
        _cleanup = new Timer(_ => Cleanup(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    private const int MaxGlobal = 5000;
    private const int MaxPerUser = 50;

    public void Record(Guid userId, string deviceId, string deviceName, string appName, string remoteIp)
    {
        if (userId == Guid.Empty || string.IsNullOrEmpty(deviceId)) return;
        if (_entries.Count >= MaxGlobal) return;
        // PERF-P8: O(1) per-user count via maintained counter (replaces LINQ
        // Count over the full _entries collection on every Record).
        if (_perUserCount.TryGetValue(userId, out var userCount) && userCount >= MaxPerUser) return;
        var key = $"{userId:N}|{deviceId}";
        var added = false;
        _entries.AddOrUpdate(key,
            _ =>
            {
                added = true;
                return new PendingEntry
                {
                    UserId = userId,
                    DeviceId = deviceId,
                    DeviceName = deviceName ?? string.Empty,
                    AppName = appName ?? string.Empty,
                    RemoteIp = remoteIp ?? string.Empty,
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(30),
                };
            },
            (_, existing) =>
            {
                existing.DeviceName = deviceName ?? existing.DeviceName;
                existing.AppName = appName ?? existing.AppName;
                existing.RemoteIp = remoteIp ?? existing.RemoteIp;
                existing.LastSeen = DateTime.UtcNow;
                existing.ExpiresAt = DateTime.UtcNow.AddMinutes(30);
                return existing;
            });
        if (added)
        {
            _perUserCount.AddOrUpdate(userId, 1, (_, n) => n + 1);
        }
        _logger.LogDebug("[2FA] Pending pairing recorded user={UserId} device={DeviceName} app={AppName}",
            userId, deviceName, appName);
    }

    public IReadOnlyList<PendingEntry> ListForUser(Guid userId)
    {
        var now = DateTime.UtcNow;
        return _entries.Values
            .Where(e => e.UserId == userId && e.ExpiresAt > now)
            .OrderByDescending(e => e.LastSeen)
            .ToList()
            .AsReadOnly();
    }

    public PendingEntry? Get(Guid userId, string deviceId)
    {
        return _entries.TryGetValue($"{userId:N}|{deviceId}", out var e) && e.ExpiresAt > DateTime.UtcNow
            ? e
            : null;
    }

    public bool Remove(Guid userId, string deviceId)
    {
        if (_entries.TryRemove($"{userId:N}|{deviceId}", out _))
        {
            // PERF-P8: keep _perUserCount in sync.
            DecrementPerUser(userId);
            return true;
        }
        return false;
    }

    public void RemoveAllForUser(Guid userId)
    {
        foreach (var kv in _entries)
        {
            if (kv.Value.UserId == userId && _entries.TryRemove(kv.Key, out _))
            {
                DecrementPerUser(userId);
            }
        }
    }

    private void Cleanup()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _entries)
        {
            if (kv.Value.ExpiresAt <= now && _entries.TryRemove(kv.Key, out var removed))
            {
                DecrementPerUser(removed.UserId);
            }
        }
    }

    private void DecrementPerUser(Guid userId)
    {
        // Decrement; remove the slot when zero so the dictionary doesn't grow
        // unboundedly. Race-tolerant: a parallel Increment/Decrement may
        // briefly observe stale values but the system corrects itself on the
        // next Record/Remove. Worst case is over- or under-counting by one
        // for a few microseconds — never breaking the cap badly.
        _perUserCount.AddOrUpdate(userId, 0, (_, n) => Math.Max(0, n - 1));
        if (_perUserCount.TryGetValue(userId, out var n) && n <= 0)
        {
            _perUserCount.TryRemove(userId, out _);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cleanup.Dispose();
        GC.SuppressFinalize(this);
    }
}

public class PendingEntry
{
    public Guid UserId { get; set; }
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string AppName { get; set; } = string.Empty;
    public string RemoteIp { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public DateTime ExpiresAt { get; set; }
}

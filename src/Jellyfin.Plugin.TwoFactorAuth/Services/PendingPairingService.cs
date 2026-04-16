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
        var userCount = _entries.Values.Count(e => e.UserId == userId);
        if (userCount >= MaxPerUser) return;
        var key = $"{userId:N}|{deviceId}";
        _entries[key] = new PendingEntry
        {
            UserId = userId,
            DeviceId = deviceId,
            DeviceName = deviceName ?? string.Empty,
            AppName = appName ?? string.Empty,
            RemoteIp = remoteIp ?? string.Empty,
            FirstSeen = _entries.TryGetValue(key, out var existing) ? existing.FirstSeen : DateTime.UtcNow,
            LastSeen = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
        };
        _logger.LogInformation("[2FA] Pending pairing recorded user={UserId} device={DeviceName} app={AppName}",
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
        return _entries.TryRemove($"{userId:N}|{deviceId}", out _);
    }

    public void RemoveAllForUser(Guid userId)
    {
        foreach (var kv in _entries)
        {
            if (kv.Value.UserId == userId)
            {
                _entries.TryRemove(kv.Key, out _);
            }
        }
    }

    private void Cleanup()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _entries)
        {
            if (kv.Value.ExpiresAt <= now)
            {
                _entries.TryRemove(kv.Key, out _);
            }
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

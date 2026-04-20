using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Common.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Brute-force IP banning, Fail2Ban-style. Tracks failed auth
/// attempts per source IP across ALL users; when an IP exceeds the threshold
/// in the configured window, it's auto-banned for the configured duration.
/// Bans are persisted to disk so they survive restart.
///
/// IPs in the LAN bypass list, the trusted-proxy list, and the explicit
/// IpBanExemptCidrs list are never banned.</summary>
public class IpBanService : IDisposable
{
    private readonly string _bansFilePath;
    private readonly ILogger<IpBanService> _logger;
    private readonly ConcurrentDictionary<string, IpBanEntry> _activeBans = new();
    private readonly ConcurrentDictionary<string, List<DateTime>> _failures = new();
    private readonly Timer _sweepTimer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private bool _disposed;

    public IpBanService(IApplicationPaths paths, ILogger<IpBanService> logger)
    {
        _logger = logger;
        var dataDir = Path.Combine(paths.PluginConfigurationsPath, "TwoFactorAuth");
        Directory.CreateDirectory(dataDir);
        _bansFilePath = Path.Combine(dataDir, "ip-bans.json");
        Load();
        _sweepTimer = new Timer(_ => Sweep(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>Should this request be rejected? Returns the active ban entry
    /// if so, or null to allow.</summary>
    public IpBanEntry? CheckBanned(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return null;
        if (_activeBans.TryGetValue(ip, out var ban))
        {
            if (ban.ExpiresAt > DateTime.UtcNow) return ban;
            _activeBans.TryRemove(ip, out _);
            _ = SaveAsync();
        }
        return null;
    }

    /// <summary>Record a failed sign-in attempt from this IP. Auto-bans if
    /// the threshold is hit. Exempt IPs (LAN, trusted proxies, explicit
    /// allowlist) are silently ignored.</summary>
    public void RecordFailure(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return;
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.IpBanEnabled) return;
        if (IsExempt(ip, config)) return;

        var window = TimeSpan.FromMinutes(Math.Max(1, config.IpBanFailureWindowMinutes));
        var cutoff = DateTime.UtcNow - window;
        var bucket = _failures.GetOrAdd(ip, _ => new List<DateTime>());
        lock (bucket)
        {
            bucket.RemoveAll(t => t < cutoff);
            bucket.Add(DateTime.UtcNow);
            if (bucket.Count >= config.IpBanFailureThreshold)
            {
                bucket.Clear();
                Ban(ip, "auto", $"Auto-banned after {config.IpBanFailureThreshold} failed attempts in {config.IpBanFailureWindowMinutes}min", config.IpBanDurationHours);
            }
        }
    }

    /// <summary>Manually ban an IP from the admin UI. Hours = how long.</summary>
    public IpBanEntry Ban(string ip, string source, string note, int hours)
    {
        var entry = new IpBanEntry
        {
            Ip = ip,
            BannedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(Math.Max(1, hours)),
            FailureCount = 0,
            Source = source,
            Note = note,
        };
        _activeBans[ip] = entry;
        _logger.LogWarning("[2FA] Banned IP {Ip} for {Hours}h ({Note})", ip, hours, note);
        _ = SaveAsync();
        return entry;
    }

    public bool Unban(string ip)
    {
        if (_activeBans.TryRemove(ip, out _))
        {
            _failures.TryRemove(ip, out _);
            _ = SaveAsync();
            return true;
        }
        return false;
    }

    public IReadOnlyList<IpBanEntry> ListActive()
    {
        var now = DateTime.UtcNow;
        return _activeBans.Values.Where(b => b.ExpiresAt > now)
            .OrderByDescending(b => b.BannedAt).ToList();
    }

    /// <summary>Reset failure counter for an IP (e.g. after a successful sign-in).</summary>
    public void RecordSuccess(string ip)
    {
        if (!string.IsNullOrEmpty(ip)) _failures.TryRemove(ip, out _);
    }

    private static bool IsExempt(string ip, Configuration.PluginConfiguration config)
    {
        foreach (var c in config.IpBanExemptCidrs)
        {
            if (BypassEvaluator.IsIpInCidr(ip, c)) return true;
        }
        // LAN ranges are also exempt — never ban an internal client.
        foreach (var c in config.LanBypassCidrs)
        {
            if (BypassEvaluator.IsIpInCidr(ip, c)) return true;
        }
        // Trusted proxies — banning the proxy itself would lock out everyone.
        foreach (var c in config.TrustedProxyCidrs)
        {
            if (BypassEvaluator.IsIpInCidr(ip, c)) return true;
        }
        return false;
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_bansFilePath)) return;
            var json = File.ReadAllText(_bansFilePath);
            var entries = JsonSerializer.Deserialize<List<IpBanEntry>>(json);
            if (entries is null) return;
            var now = DateTime.UtcNow;
            foreach (var e in entries.Where(e => e.ExpiresAt > now))
            {
                _activeBans[e.Ip] = e;
            }
            _logger.LogInformation("[2FA] Loaded {Count} active IP bans from disk", _activeBans.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Failed to load ip-bans.json");
        }
    }

    private async Task SaveAsync()
    {
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Serialize(_activeBans.Values.ToList(),
                new JsonSerializerOptions { WriteIndented = true });
            var tmp = _bansFilePath + ".tmp";
            await File.WriteAllTextAsync(tmp, json).ConfigureAwait(false);
            File.Move(tmp, _bansFilePath, true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Failed to save ip-bans.json");
        }
        finally { _writeLock.Release(); }
    }

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        var changed = false;
        foreach (var kv in _activeBans)
        {
            if (kv.Value.ExpiresAt <= now)
            {
                _activeBans.TryRemove(kv.Key, out _);
                changed = true;
            }
        }
        // Also age out failure-bucket dictionary entries that no longer have data
        foreach (var kv in _failures)
        {
            lock (kv.Value)
            {
                kv.Value.RemoveAll(t => t < now.AddHours(-1));
                if (kv.Value.Count == 0) _failures.TryRemove(kv.Key, out _);
            }
        }
        if (changed) _ = SaveAsync();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _sweepTimer.Dispose();
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }
}

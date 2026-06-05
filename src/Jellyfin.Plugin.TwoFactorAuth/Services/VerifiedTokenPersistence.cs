using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [v2.5.7] (issue #52, derpacco): persists SHA-256 hashes of access
/// tokens that have completed 2FA so the verified-state survives a
/// Jellyfin restart.
///
/// Without persistence, <c>ChallengeStore._verifiedTokens</c> is empty
/// after every process restart. AuthenticationEventHandler's failsafe
/// then fires <c>BlockToken</c> for each existing session as soon as
/// SessionStarted arrives (which happens on every websocket reconnect /
/// new tab / idle resume), and RequestBlockerMiddleware 403s every
/// subsequent request. The user gets soft-bricked — can't even reach
/// /Logout — and has to wipe local storage.
///
/// SECURITY: stored as SHA-256 hex digests, never plaintext. A leaked
/// sidecar gives an attacker no usable session tokens (the hash is
/// one-way and the input space is 256-bit random tokens). Cap at
/// 5000 most-recent + 30-day TTL bounds disk usage and limits exposure
/// to long-abandoned sessions.
/// </summary>
public class VerifiedTokenPersistence : IDisposable
{
    private const int MaxEntries = 5000;
    private static readonly TimeSpan PersistTtl = TimeSpan.FromDays(30);
    private static readonly TimeSpan WriteDebounce = TimeSpan.FromSeconds(30);

    private readonly ILogger<VerifiedTokenPersistence> _logger;
    private readonly string _path;
    private readonly ConcurrentDictionary<string, DateTime> _hashes = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private DateTime _nextWriteAt = DateTime.MinValue;

    public VerifiedTokenPersistence(ILogger<VerifiedTokenPersistence> logger)
    {
        _logger = logger;
        var dataFolder = Plugin.Instance?.DataFolderPath
            ?? Path.Combine(Path.GetTempPath(), "JellyfinSecurity");
        _path = Path.Combine(dataFolder, "verified_tokens.json");
        Load();
    }

    public void MarkVerified(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        var hash = ComputeHash(token);
        _hashes[hash] = DateTime.UtcNow.Add(PersistTtl);
        EnforceCap();
        ScheduleWrite();
    }

    public bool IsVerified(string token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        var hash = ComputeHash(token);
        if (!_hashes.TryGetValue(hash, out var exp)) return false;
        if (exp <= DateTime.UtcNow)
        {
            _hashes.TryRemove(hash, out _);
            return false;
        }
        return true;
    }

    /// <summary>Drop a hash on explicit logout / token revocation. Cheap
    /// belt-and-braces — 256-bit token collisions are astronomically
    /// unlikely but enforcing this keeps the cap honest.</summary>
    public void Forget(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _hashes.TryRemove(ComputeHash(token), out _);
        ScheduleWrite();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var json = File.ReadAllText(_path);
            var doc = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(json);
            if (doc is null) return;
            var now = DateTime.UtcNow;
            var loaded = 0;
            foreach (var (h, exp) in doc)
            {
                if (string.IsNullOrEmpty(h) || h.Length != 64) continue;
                if (exp > now) { _hashes[h] = exp; loaded++; }
            }
            _logger.LogInformation("[2FA] Loaded {Count} verified-token hashes from {Path}", loaded, _path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Failed to load verified-token sidecar at {Path} — starting empty", _path);
        }
    }

    private void EnforceCap()
    {
        if (_hashes.Count <= MaxEntries) return;
        var dropCount = _hashes.Count - MaxEntries;
        var victims = _hashes
            .OrderBy(kv => kv.Value)
            .Take(dropCount)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var k in victims) _hashes.TryRemove(k, out _);
    }

    private void ScheduleWrite()
    {
        // Debounce: at most one write per WriteDebounce window. Fire-and-forget
        // so the hot path (MarkTokenVerified during login) isn't blocked on
        // disk I/O. Crash before flush only loses up to WriteDebounce of
        // verifications — those sessions reprompt once on next login, which
        // is the same fallback the in-memory dict had before persistence.
        var now = DateTime.UtcNow;
        if (now < _nextWriteAt) return;
        _nextWriteAt = now.Add(WriteDebounce);
        _ = Task.Run(WriteAsync);
    }

    private async Task WriteAsync()
    {
        if (!await _writeLock.WaitAsync(0).ConfigureAwait(false)) return;
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var snapshot = _hashes.ToDictionary(kv => kv.Key, kv => kv.Value);
            var json = JsonSerializer.Serialize(snapshot);
            var tmp = _path + ".tmp";
            await File.WriteAllTextAsync(tmp, json).ConfigureAwait(false);
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Failed to persist verified-token sidecar to {Path}", _path);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static string ComputeHash(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    public void Dispose()
    {
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }
}

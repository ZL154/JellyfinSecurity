using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Common.Configuration;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class UserTwoFactorStore : IDisposable
{
    // PERF-P4: hot files (users/*.json, audit.json) write compact JSON.
    // api-keys.json keeps WriteIndented for admin readability via separate options.
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly JsonSerializerOptions ApiKeysJsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _dataPath;
    private readonly string _usersPath;
    private readonly string _auditFilePath;
    private readonly string _apiKeysFilePath;

    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _userLocks = new();
    private readonly SemaphoreSlim _auditLock = new(1, 1);
    private readonly SemaphoreSlim _apiKeysLock = new(1, 1);

    // PERF-P1: in-memory cache of user records. Populated lazily on first read.
    // SaveUserDataAsync writes-through (file + cache update). MutateAsync still
    // takes the per-user semaphore for atomic read-modify-write. GetUserDataAsync
    // returns a defensive deep-clone so callers can't poison the cache by
    // mutating without going through Save/Mutate.
    private readonly ConcurrentDictionary<Guid, UserTwoFactorData> _userCache = new();

    // PERF-P3: audit log lives in memory after first load. Adds append to the
    // list under _auditLock; a background timer flushes to disk every 5s if
    // dirty. Reads return a snapshot from memory — no disk I/O on hot paths.
    private List<AuditEntry>? _auditEntries;
    private bool _auditDirty;
    private readonly Timer _auditFlushTimer;

    private bool _disposed;

    public UserTwoFactorStore(IApplicationPaths applicationPaths)
    {
        _dataPath = Path.Combine(applicationPaths.PluginConfigurationsPath, "TwoFactorAuth");
        _usersPath = Path.Combine(_dataPath, "users");
        _auditFilePath = Path.Combine(_dataPath, "audit.json");
        _apiKeysFilePath = Path.Combine(_dataPath, "api-keys.json");

        Directory.CreateDirectory(_usersPath);

        _auditFlushTimer = new Timer(_ => _ = FlushAuditAsync(),
            null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    // -------------------------------------------------------------------------
    // User data
    // -------------------------------------------------------------------------

    private SemaphoreSlim GetUserLock(Guid userId)
        => _userLocks.GetOrAdd(userId, _ => new SemaphoreSlim(1, 1));

    private string UserFilePath(Guid userId)
        => Path.Combine(_usersPath, $"{userId}.json");

    public async Task<UserTwoFactorData> GetUserDataAsync(Guid userId)
    {
        // PERF-P1: cache fast path. Returns a clone so the caller can mutate
        // freely; mutations only persist via SaveUserDataAsync / MutateAsync.
        if (_userCache.TryGetValue(userId, out var cached))
        {
            return CloneUserData(cached);
        }

        var sem = GetUserLock(userId);
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_userCache.TryGetValue(userId, out cached))
            {
                return CloneUserData(cached);
            }
            var data = await ReadUserFileAsync(userId).ConfigureAwait(false);
            // Cache the canonical (un-cloned) copy; clone for the caller.
            _userCache[userId] = data;
            return CloneUserData(data);
        }
        finally
        {
            sem.Release();
        }
    }

    public async Task SaveUserDataAsync(UserTwoFactorData data)
    {
        var sem = GetUserLock(data.UserId);
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            await WriteUserFileAsync(data).ConfigureAwait(false);
            // Cache stores its own clone so the caller can keep mutating.
            _userCache[data.UserId] = CloneUserData(data);
        }
        finally
        {
            sem.Release();
        }
    }

    /// <summary>
    /// Atomic read-modify-write under the per-user semaphore. Use this when
    /// multiple requests can mutate the same user concurrently (auth bypass
    /// updates LastUsedAt while the user is also editing app passwords from
    /// the Setup page). Naïve Get/mutate/Save loses updates.
    /// </summary>
    public async Task MutateAsync(Guid userId, Action<UserTwoFactorData> mutator)
    {
        var sem = GetUserLock(userId);
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            // PERF-P1: prefer cached canonical copy under the lock; fall back
            // to disk only when uncached. The mutator runs against the canonical
            // copy directly, then we write-through to disk + update cache.
            if (!_userCache.TryGetValue(userId, out var data))
            {
                data = await ReadUserFileAsync(userId).ConfigureAwait(false);
            }
            mutator(data);
            await WriteUserFileAsync(data).ConfigureAwait(false);
            _userCache[userId] = data;
        }
        finally
        {
            sem.Release();
        }
    }

    public async Task<bool> IsLockedOutAsync(Guid userId)
    {
        var data = await GetUserDataAsync(userId).ConfigureAwait(false);
        if (data.LockoutEnd.HasValue && data.LockoutEnd.Value > DateTime.UtcNow)
        {
            return true;
        }

        return false;
    }

    public async Task RecordFailedAttemptAsync(Guid userId)
    {
        // Use MutateAsync so cache + file stay consistent.
        await MutateAsync(userId, ud =>
        {
            ud.FailedAttemptCount++;
            var config = Plugin.Instance?.Configuration;
            int maxAttempts = config?.MaxFailedAttempts ?? 5;
            int lockoutMinutes = config?.LockoutDurationMinutes ?? 15;
            if (ud.FailedAttemptCount >= maxAttempts)
            {
                ud.LockoutEnd = DateTime.UtcNow.AddMinutes(lockoutMinutes);
            }
        }).ConfigureAwait(false);
    }

    public async Task ResetFailedAttemptsAsync(Guid userId)
    {
        await MutateAsync(userId, ud =>
        {
            ud.FailedAttemptCount = 0;
            ud.LockoutEnd = null;
        }).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<UserTwoFactorData>> GetAllUsersAsync()
    {
        // PERF-P1+P7: enumerate disk once to discover user IDs that aren't
        // cached, populate cache, then return cached snapshots. Subsequent
        // calls (passkey uniqueness, OIDC sub-lookup, stats, diagnostics)
        // are cache-only.
        var files = Directory.GetFiles(_usersPath, "*.json");
        foreach (var file in files)
        {
            if (!Guid.TryParse(Path.GetFileNameWithoutExtension(file), out var userId)) continue;
            if (!_userCache.ContainsKey(userId))
            {
                try
                {
                    // GetUserDataAsync handles the cache-miss path with proper locking.
                    await GetUserDataAsync(userId).ConfigureAwait(false);
                }
                catch
                {
                    // Skip corrupt files
                }
            }
        }

        var results = new List<UserTwoFactorData>(_userCache.Count);
        foreach (var kv in _userCache)
        {
            results.Add(CloneUserData(kv.Value));
        }
        return results.AsReadOnly();
    }

    /// <summary>PERF-P1: deep clone via JSON round-trip. Cheap for the data
    /// shape (a few KB at most) and bulletproof — the canonical cached copy
    /// can never be mutated by a caller because they only ever see clones.
    /// Avoids the bug-class where a service calls GetUserDataAsync, mutates
    /// the result, forgets to call Save, and the cache silently advertises
    /// the mutation to other readers.</summary>
    private static UserTwoFactorData CloneUserData(UserTwoFactorData source)
    {
        var json = JsonSerializer.Serialize(source, JsonOptions);
        return JsonSerializer.Deserialize<UserTwoFactorData>(json, JsonOptions)
            ?? new UserTwoFactorData { UserId = source.UserId };
    }

    // -------------------------------------------------------------------------
    // Audit log
    // -------------------------------------------------------------------------

    public async Task AddAuditEntryAsync(AuditEntry entry)
    {
        await _auditLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // PERF-P3: load once into memory on first access; subsequent
            // appends are pure list-add. Background timer flushes to disk.
            _auditEntries ??= await ReadAuditFileAsync().ConfigureAwait(false);

            // Hash chain: tie the new entry's PreviousHash to the prior entry's
            // EntryHash, then compute and stamp this entry's EntryHash.
            var prior = _auditEntries.Count > 0 ? _auditEntries[^1].EntryHash : string.Empty;
            entry.PreviousHash = string.IsNullOrEmpty(prior) ? new string('0', 64) : prior;
            entry.EntryHash = ComputeAuditEntryHash(entry);

            _auditEntries.Add(entry);

            int maxEntries = Plugin.Instance?.Configuration?.AuditLogMaxEntries ?? 1000;
            if (_auditEntries.Count > maxEntries)
            {
                _auditEntries.RemoveRange(0, _auditEntries.Count - maxEntries);
            }

            _auditDirty = true;
        }
        finally
        {
            _auditLock.Release();
        }
    }

    /// <summary>Canonical hash for audit entries. Includes every persisted field
    /// EXCEPT EntryHash itself (otherwise the value would depend on itself).
    /// PreviousHash IS included so tampering with one entry cascades.</summary>
    internal static string ComputeAuditEntryHash(AuditEntry e)
    {
        var canonical = string.Join("\x1F",
            e.PreviousHash,
            e.Timestamp.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            e.UserId.ToString("N"),
            e.Username ?? string.Empty,
            e.RemoteIp ?? string.Empty,
            e.DeviceId ?? string.Empty,
            e.DeviceName ?? string.Empty,
            ((int)e.Result).ToString(System.Globalization.CultureInfo.InvariantCulture),
            e.Method ?? string.Empty,
            e.Details ?? string.Empty);
        var bytes = System.Text.Encoding.UTF8.GetBytes(canonical);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
    }

    public async Task<IReadOnlyList<AuditEntry>> GetAuditLogAsync(int? limit = null)
    {
        await _auditLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // PERF-P3: serve from memory.
            _auditEntries ??= await ReadAuditFileAsync().ConfigureAwait(false);

            if (limit.HasValue && limit.Value < _auditEntries.Count)
            {
                return _auditEntries.Skip(_auditEntries.Count - limit.Value).ToList().AsReadOnly();
            }

            // Return a snapshot so callers can iterate without lock contention.
            return _auditEntries.ToList().AsReadOnly();
        }
        finally
        {
            _auditLock.Release();
        }
    }

    /// <summary>PERF-P3: flush in-memory audit log to disk if dirty. Called
    /// by the periodic timer. Skips work when nothing changed.</summary>
    private async Task FlushAuditAsync()
    {
        if (_disposed) return;
        List<AuditEntry>? snapshot = null;
        await _auditLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_auditDirty || _auditEntries is null) return;
            snapshot = _auditEntries.ToList();
            _auditDirty = false;
        }
        finally
        {
            _auditLock.Release();
        }

        try
        {
            var json = JsonSerializer.Serialize(snapshot, JsonOptions);
            await AtomicWriteAsync(_auditFilePath, json).ConfigureAwait(false);
        }
        catch
        {
            // Re-mark dirty so the next tick retries. Don't log per-tick to
            // avoid log spam if the disk is full.
            await _auditLock.WaitAsync().ConfigureAwait(false);
            try { _auditDirty = true; } finally { _auditLock.Release(); }
        }
    }

    // -------------------------------------------------------------------------
    // API keys
    // -------------------------------------------------------------------------

    public async Task<IReadOnlyList<ApiKeyEntry>> GetApiKeysAsync()
    {
        await _apiKeysLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var keys = await ReadApiKeysFileAsync().ConfigureAwait(false);

            // One-shot migration: any legacy entry with a plaintext Key and
            // no KeyHash gets hashed in place. After this we re-save so the
            // raw key is wiped from disk. Idempotent — subsequent loads skip.
            var migrated = false;
            foreach (var k in keys)
            {
                if (string.IsNullOrEmpty(k.KeyHash) && !string.IsNullOrEmpty(k.Key))
                {
                    k.KeyHash = BypassEvaluator.HashApiKey(k.Key);
                    if (string.IsNullOrEmpty(k.KeyPreview))
                    {
                        k.KeyPreview = k.Key.Length > 6 ? k.Key.Substring(0, 6) + "…" : k.Key;
                    }
                    k.Key = string.Empty;
                    migrated = true;
                }
            }
            if (migrated)
            {
                var json = JsonSerializer.Serialize(keys, ApiKeysJsonOptions);
                await AtomicWriteAsync(_apiKeysFilePath, json).ConfigureAwait(false);
            }

            return keys;
        }
        finally
        {
            _apiKeysLock.Release();
        }
    }

    public async Task SaveApiKeysAsync(List<ApiKeyEntry> keys)
    {
        await _apiKeysLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Serialize(keys, ApiKeysJsonOptions);
            await AtomicWriteAsync(_apiKeysFilePath, json).ConfigureAwait(false);
        }
        finally
        {
            _apiKeysLock.Release();
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private async Task<UserTwoFactorData> ReadUserFileAsync(Guid userId)
    {
        var path = UserFilePath(userId);
        if (!File.Exists(path))
        {
            return new UserTwoFactorData { UserId = userId };
        }

        try
        {
            var json = await File.ReadAllTextAsync(path).ConfigureAwait(false);
            return JsonSerializer.Deserialize<UserTwoFactorData>(json, JsonOptions)
                   ?? new UserTwoFactorData { UserId = userId };
        }
        catch (Exception)
        {
            return new UserTwoFactorData { UserId = userId };
        }
    }

    private async Task WriteUserFileAsync(UserTwoFactorData data)
    {
        var path = UserFilePath(data.UserId);
        var json = JsonSerializer.Serialize(data, JsonOptions);
        await AtomicWriteAsync(path, json).ConfigureAwait(false);
    }

    /// <summary>
    /// Write to a temp file then atomically replace the target. Prevents corruption
    /// if Jellyfin crashes mid-write. Critical for user data — losing a file could
    /// lock a user out of their TOTP secret.
    /// </summary>
    private static async Task AtomicWriteAsync(string path, string content)
    {
        var tmp = path + ".tmp";
        await File.WriteAllTextAsync(tmp, content).ConfigureAwait(false);
        File.Move(tmp, path, overwrite: true);
    }

    private async Task<List<AuditEntry>> ReadAuditFileAsync()
    {
        if (!File.Exists(_auditFilePath))
        {
            return new List<AuditEntry>();
        }

        try
        {
            var json = await File.ReadAllTextAsync(_auditFilePath).ConfigureAwait(false);
            var entries = JsonSerializer.Deserialize<List<AuditEntry>>(json, JsonOptions)
                          ?? new List<AuditEntry>();

            // Prune entries older than 90 days on first load.
            var cutoff = DateTime.UtcNow.AddDays(-90);
            entries = entries.Where(e => e.Timestamp >= cutoff).ToList();

            return entries;
        }
        catch (Exception)
        {
            return new List<AuditEntry>();
        }
    }

    private async Task<List<ApiKeyEntry>> ReadApiKeysFileAsync()
    {
        if (!File.Exists(_apiKeysFilePath))
        {
            return new List<ApiKeyEntry>();
        }

        try
        {
            var json = await File.ReadAllTextAsync(_apiKeysFilePath).ConfigureAwait(false);
            return JsonSerializer.Deserialize<List<ApiKeyEntry>>(json, ApiKeysJsonOptions)
                   ?? new List<ApiKeyEntry>();
        }
        catch (Exception)
        {
            return new List<ApiKeyEntry>();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _auditFlushTimer.Dispose();
        // Best-effort final flush so no entries are lost on shutdown.
        try { FlushAuditAsync().GetAwaiter().GetResult(); } catch { /* shutdown */ }
        GC.SuppressFinalize(this);
    }
}

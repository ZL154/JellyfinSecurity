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

public class UserTwoFactorStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
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

    private bool _auditPruned;

    public UserTwoFactorStore(IApplicationPaths applicationPaths)
    {
        _dataPath = Path.Combine(applicationPaths.PluginConfigurationsPath, "TwoFactorAuth");
        _usersPath = Path.Combine(_dataPath, "users");
        _auditFilePath = Path.Combine(_dataPath, "audit.json");
        _apiKeysFilePath = Path.Combine(_dataPath, "api-keys.json");

        Directory.CreateDirectory(_usersPath);
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
        var sem = GetUserLock(userId);
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            return await ReadUserFileAsync(userId).ConfigureAwait(false);
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
            var data = await ReadUserFileAsync(userId).ConfigureAwait(false);
            mutator(data);
            await WriteUserFileAsync(data).ConfigureAwait(false);
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
        var sem = GetUserLock(userId);
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            var data = await ReadUserFileAsync(userId).ConfigureAwait(false);
            data.FailedAttemptCount++;

            var config = Plugin.Instance?.Configuration;
            int maxAttempts = config?.MaxFailedAttempts ?? 5;
            int lockoutMinutes = config?.LockoutDurationMinutes ?? 15;

            if (data.FailedAttemptCount >= maxAttempts)
            {
                data.LockoutEnd = DateTime.UtcNow.AddMinutes(lockoutMinutes);
            }

            await WriteUserFileAsync(data).ConfigureAwait(false);
        }
        finally
        {
            sem.Release();
        }
    }

    public async Task ResetFailedAttemptsAsync(Guid userId)
    {
        var sem = GetUserLock(userId);
        await sem.WaitAsync().ConfigureAwait(false);
        try
        {
            var data = await ReadUserFileAsync(userId).ConfigureAwait(false);
            data.FailedAttemptCount = 0;
            data.LockoutEnd = null;
            await WriteUserFileAsync(data).ConfigureAwait(false);
        }
        finally
        {
            sem.Release();
        }
    }

    public async Task<IReadOnlyList<UserTwoFactorData>> GetAllUsersAsync()
    {
        var files = Directory.GetFiles(_usersPath, "*.json");
        var results = new List<UserTwoFactorData>(files.Length);

        foreach (var file in files)
        {
            if (!Guid.TryParse(Path.GetFileNameWithoutExtension(file), out var userId))
            {
                continue;
            }

            try
            {
                var data = await GetUserDataAsync(userId).ConfigureAwait(false);
                results.Add(data);
            }
            catch (Exception)
            {
                // Skip corrupt files
            }
        }

        return results.AsReadOnly();
    }

    // -------------------------------------------------------------------------
    // Audit log
    // -------------------------------------------------------------------------

    public async Task AddAuditEntryAsync(AuditEntry entry)
    {
        await _auditLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var entries = await ReadAuditFileAsync().ConfigureAwait(false);
            entries.Add(entry);

            int maxEntries = Plugin.Instance?.Configuration?.AuditLogMaxEntries ?? 1000;

            // Prune to max entries (keep most recent)
            if (entries.Count > maxEntries)
            {
                entries = entries.Skip(entries.Count - maxEntries).ToList();
            }

            await WriteAuditFileAsync(entries).ConfigureAwait(false);
        }
        finally
        {
            _auditLock.Release();
        }
    }

    public async Task<IReadOnlyList<AuditEntry>> GetAuditLogAsync(int? limit = null)
    {
        await _auditLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var entries = await ReadAuditFileAsync().ConfigureAwait(false);

            if (limit.HasValue && limit.Value < entries.Count)
            {
                return entries.Skip(entries.Count - limit.Value).ToList().AsReadOnly();
            }

            return entries.AsReadOnly();
        }
        finally
        {
            _auditLock.Release();
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
            return await ReadApiKeysFileAsync().ConfigureAwait(false);
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
            var json = JsonSerializer.Serialize(keys, JsonOptions);
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

            // Prune entries older than 90 days on first load
            if (!_auditPruned)
            {
                _auditPruned = true;
                var cutoff = DateTime.UtcNow.AddDays(-90);
                entries = entries.Where(e => e.Timestamp >= cutoff).ToList();
            }

            return entries;
        }
        catch (Exception)
        {
            return new List<AuditEntry>();
        }
    }

    private async Task WriteAuditFileAsync(List<AuditEntry> entries)
    {
        var json = JsonSerializer.Serialize(entries, JsonOptions);
        await AtomicWriteAsync(_auditFilePath, json).ConfigureAwait(false);
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
            return JsonSerializer.Deserialize<List<ApiKeyEntry>>(json, JsonOptions)
                   ?? new List<ApiKeyEntry>();
        }
        catch (Exception)
        {
            return new List<ApiKeyEntry>();
        }
    }
}

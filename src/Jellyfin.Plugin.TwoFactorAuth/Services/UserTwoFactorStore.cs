using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;

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

    // [v2.5.10] (issue #55): IUserManager is resolved LAZILY via IServiceProvider,
    // NOT injected directly. UserManager depends on
    // IEnumerable<IAuthenticationProvider> → TwoFactorAuthProvider →
    // UserTwoFactorStore, so a direct IUserManager ctor dependency here closes
    // a DI cycle and the container fails to build the graph at startup. We only
    // need IUserManager at auth time (lockout checks), long after the graph is
    // constructed, so we resolve + cache it on first use instead.
    private readonly IServiceProvider _services;
    private IUserManager? _userManagerCached;

    public UserTwoFactorStore(IApplicationPaths applicationPaths, IServiceProvider services)
    {
        _services = services;
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
        // [v2.5.7] (issue #55, Dasnap): refuse to mutate the empty-Guid slot.
        // Some failure-recording call site (likely a brute-force path during
        // Dasnap's testing) was reaching us with Guid.Empty and creating
        // 2faData_00000000-0000-0000-0000-000000000000.json. That file then
        // crashed the entire /TwoFactorAuth/Users listing because
        // UserManager.GetUserById throws ArgumentException on empty ids.
        // Refusing the write at the store boundary stops new corruption;
        // the GetUsers loop also skips any preexisting junk row.
        if (userId == Guid.Empty)
        {
            return;
        }
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

    /// <summary>[v2.5.10] (issue #55, Dasnap): true when this user must NOT be
    /// locked out by the failed-attempt counter — i.e. they're a Jellyfin
    /// administrator AND the admin-lockout exemption is enabled (default). This
    /// closes the admin-lockout DoS where anyone who knows the admin username
    /// can fail logins to lock the real admin out. The per-IP brute-force ban
    /// and 2FA enforcement still protect the admin; only the per-account
    /// auto-lockout is suppressed. Resolution is best-effort: any lookup
    /// failure falls through to "not exempt" (fail-closed — lockout applies).</summary>
    private bool IsLockoutExempt(Guid userId)
    {
        if (Plugin.Instance?.Configuration?.ExemptAdministratorsFromLockout != true)
        {
            return false;
        }

        try
        {
            var userManager = _userManagerCached ??= _services.GetService(typeof(IUserManager)) as IUserManager;
            if (userManager is null)
            {
                return false;
            }

            var user = userManager.GetUserById(userId);
            return user is not null && user.HasPermission(PermissionKind.IsAdministrator);
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> IsLockedOutAsync(Guid userId)
    {
        // Exempt admins are never reported as locked out, even if a stale
        // LockoutEnd was written before the exemption was enabled.
        if (IsLockoutExempt(userId))
        {
            return false;
        }

        var data = await GetUserDataAsync(userId).ConfigureAwait(false);
        if (data.LockoutEnd.HasValue && data.LockoutEnd.Value > DateTime.UtcNow)
        {
            return true;
        }

        return false;
    }

    public async Task RecordFailedAttemptAsync(Guid userId)
    {
        // [v2.5.10] (issue #55): resolve admin-exemption ONCE outside the
        // mutate lambda (the lambda is hot + lock-held; GetUserById shouldn't
        // run under it). We still increment the counter for exempt admins so
        // the failed-attempt notification/audit thresholds fire and the
        // brute-force attempt stays visible — we just never set LockoutEnd.
        var exempt = IsLockoutExempt(userId);

        // Use MutateAsync so cache + file stay consistent.
        await MutateAsync(userId, ud =>
        {
            ud.FailedAttemptCount++;
            if (exempt)
            {
                return;
            }

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
    /// PreviousHash IS included so tampering with one entry cascades.
    ///
    /// SECURITY [v2.5.5] (Finding 22): length-prefix each field instead of
    /// joining on \x1F. Prior versions used a unit-separator join, which
    /// meant a field containing 0x1F could shift segment boundaries and
    /// collide with a different entry whose fields were laid out
    /// differently. Length-prefixing makes the encoding unambiguous
    /// regardless of field content. NOTE: this changes the hash output for
    /// every existing entry, so the chain validity reset happens on the
    /// first read after upgrade. Admins can run /Admin/RebuildAuditChain
    /// once to re-anchor.</summary>
    internal static string ComputeAuditEntryHash(AuditEntry e)
    {
        var sb = new System.Text.StringBuilder();
        AppendField(sb, e.PreviousHash);
        AppendField(sb, e.Timestamp.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        AppendField(sb, e.UserId.ToString("N"));
        AppendField(sb, e.Username);
        AppendField(sb, e.RemoteIp);
        AppendField(sb, e.DeviceId);
        AppendField(sb, e.DeviceName);
        AppendField(sb, ((int)e.Result).ToString(System.Globalization.CultureInfo.InvariantCulture));
        AppendField(sb, e.Method);
        AppendField(sb, e.Details);
        var bytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
    }

    private static void AppendField(System.Text.StringBuilder sb, string? value)
    {
        var v = value ?? string.Empty;
        // Length-prefixed encoding: <len>:<value>: — unambiguously decodable
        // regardless of what characters the value contains. Closes the
        // \x1F-injection collision class the prior canonical join had.
        sb.Append(v.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        sb.Append(':');
        sb.Append(v);
        sb.Append(':');
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

    /// <summary>
    /// v2.5.0: rebuilds the audit log hash chain from the current entries,
    /// treating the present state as the new baseline. Use after detecting
    /// chain corruption (broken EntryHash on one or more rows) to clear the
    /// diagnostic warning. NOTE: this erases tampering evidence — admin-only
    /// operation, gated by the destructive-tier step-up policy.
    ///
    /// Returns the number of entries that were re-hashed (zero when the log
    /// is empty). Persists the rewritten list to disk inline rather than
    /// waiting on the periodic flush timer, so the operation is atomic from
    /// the admin's point of view.
    /// </summary>
    public async Task<int> RebuildAuditChainAsync()
    {
        await _auditLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Force the in-memory list to exist before we walk it. Lazy load
            // mirrors AddAuditEntryAsync / GetAuditLogAsync so callers don't
            // have to pre-warm the cache.
            _auditEntries ??= await ReadAuditFileAsync().ConfigureAwait(false);

            if (_auditEntries.Count == 0) return 0;

            // Walk the list in order, re-tying each entry's PreviousHash to
            // the prior entry's freshly-computed EntryHash. The first row
            // anchors to the all-zero "genesis" string, same convention as
            // AddAuditEntryAsync.
            string prev = string.Empty;
            foreach (var e in _auditEntries)
            {
                e.PreviousHash = string.IsNullOrEmpty(prev) ? new string('0', 64) : prev;
                e.EntryHash = ComputeAuditEntryHash(e);
                prev = e.EntryHash;
            }

            // Persist inline. AtomicWriteAsync gives us a temp-file + rename so
            // a crash mid-write leaves the previous audit.json intact.
            var json = JsonSerializer.Serialize(_auditEntries, JsonOptions);
            await AtomicWriteAsync(_auditFilePath, json).ConfigureAwait(false);
            _auditDirty = false;

            // SECURITY [v2.5.6] (F5-A1): append a side-channel rebuild
            // record to audit_rebuild_meta.json — outside the chain that
            // gets rebuilt — so SIEM tools / future forensic review can
            // detect "the chain was rebuilt" events even if the main file
            // looks intact. Append-only on the meta file so a subsequent
            // RebuildAuditChain can't silence its own prior entries.
            try
            {
                var metaPath = Path.Combine(Path.GetDirectoryName(_auditFilePath) ?? string.Empty, "audit_rebuild_meta.json");
                var metaLine = JsonSerializer.Serialize(new
                {
                    rebuiltAt = DateTime.UtcNow,
                    entryCount = _auditEntries.Count,
                    firstHash = _auditEntries.Count > 0 ? _auditEntries[0].EntryHash : null,
                    lastHash = _auditEntries.Count > 0 ? _auditEntries[^1].EntryHash : null,
                });
                await File.AppendAllTextAsync(metaPath, metaLine + Environment.NewLine).ConfigureAwait(false);
            }
            catch
            {
                // Meta-log failure is non-fatal — rebuild itself succeeded.
            }

            return _auditEntries.Count;
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

        string json;
        try
        {
            json = await File.ReadAllTextAsync(path).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // SECURITY [v2.5.6] (ext review #4): treat I/O errors on an
            // existing user file as fail-CLOSED. Prior code returned a
            // blank UserTwoFactorData for any read failure, which silently
            // disables TOTP / passkeys for that user and lets them sign in
            // without 2FA — a bypass. Throwing here makes the auth path
            // refuse the sign-in until the transient I/O issue clears or
            // the admin investigates.
            throw new InvalidOperationException(
                $"Could not read 2FA data for user {userId} from disk; sign-in denied (fail-closed).",
                ex);
        }

        try
        {
            return JsonSerializer.Deserialize<UserTwoFactorData>(json, JsonOptions)
                   ?? throw new JsonException("Deserializer returned null for non-empty 2FA data.");
        }
        catch (JsonException ex)
        {
            // SECURITY [v2.5.6] (ext review #4): the file exists but is
            // not valid JSON. Returning blank data here would treat a user
            // with TOTP / passkeys enabled as if they had no 2FA, which is
            // a bypass — exactly what an attacker who can corrupt one byte
            // of the user file would want. Fail closed instead.
            //
            // Quarantine the bad file so the admin can inspect it. We do
            // NOT delete it (the user might have non-recoverable state in
            // there). Quarantine renames to "<userId>.json.corrupt-<utc>";
            // the on-disk file is gone after this, so subsequent reads
            // return a fresh empty record. This deliberately surfaces the
            // problem on the FIRST sign-in attempt rather than letting it
            // silently disable 2FA forever.
            try
            {
                var quarantined = $"{path}.corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Move(path, quarantined);
            }
            catch
            {
                // Quarantine itself failed — log via the exception we throw.
            }
            throw new InvalidOperationException(
                $"2FA data for user {userId} is corrupt and cannot be parsed. Sign-in denied; admin must investigate. Original file quarantined alongside the user folder.",
                ex);
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

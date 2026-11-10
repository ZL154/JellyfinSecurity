using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Net;
using MaxMind.Db;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Snapshot of one GeoIP database for the Diagnostics tab and the
/// log. <see cref="Failure"/> is null while the reader is open.</summary>
public sealed record GeoIpDatabaseStatus(
    string Name,
    string ConfiguredPath,
    bool Loaded,
    DateTime? LoadedAt,
    DateTime? LastAttemptAt,
    string? Failure);

/// <summary>
/// One MaxMind .mmdb file: the configured path, the open reader, and the
/// reason it is not open.
///
/// [#51] The loaders used to pin the configured path before trying to open
/// it, so a file that was missing, unreadable or refused by the filesystem at
/// first touch stayed "Fail" until the path changed or Jellyfin restarted,
/// and a missing file left no trace in the log. Every failure is now kept
/// with its reason, a failed load is retried (every <see cref="RetryInterval"/>,
/// or at once when asked), and an open that memory mapping refuses falls back
/// to reading the file into memory.
///
/// [#351] A file replaced under the same path (MaxMind's geoipupdate, a cron
/// job) is reopened. The reader used to keep the copy it opened until
/// Jellyfin restarted. The file's size and modification time are now
/// compared once per <see cref="RetryInterval"/>, and a changed file is
/// opened before the old reader closes, so lookups never go without a
/// database and a replacement that does not open leaves the last good copy
/// in use.
/// </summary>
public sealed class GeoIpDatabase : IDisposable
{
    public static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    /// <summary>The account the Jellyfin process runs as. Shown next to
    /// "not found" so a container running as a non-root user is visible in
    /// the diagnostics instead of being guessed at.</summary>
    public static readonly string ProcessUser = SafeUserName();

    private readonly string _name;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private Reader? _reader;
    private string _configuredPath = string.Empty;
    private DateTime? _loadedAt;
    private DateTime? _lastAttemptAt;
    private string? _failure;
    private string? _lastLoggedFailure;
    private FileStamp? _openedStamp;
    private DateTime? _lastChangeCheckAt;
    private string? _lastLoggedReload;
    private bool _disposed;

    public GeoIpDatabase(string name, ILogger logger)
    {
        _name = name;
        _logger = logger;
    }

    public string Name => _name;

    public bool Loaded
    {
        get { lock (_gate) { return _reader is not null; } }
    }

    public GeoIpDatabaseStatus Status
    {
        get
        {
            lock (_gate)
            {
                return new GeoIpDatabaseStatus(_name, _configuredPath, _reader is not null, _loadedAt, _lastAttemptAt, _failure);
            }
        }
    }

    /// <summary>Bring the reader in line with the configured path. While the
    /// path is unchanged and the reader is open, it only checks whether the
    /// file was replaced, once per <see cref="RetryInterval"/>; a failed load
    /// is retried after the same interval. <paramref name="force"/> does
    /// either right away (the Diagnostics tab sets it).</summary>
    public void Sync(string? configuredPath, DateTime utcNow, bool force = false)
    {
        var path = (configuredPath ?? string.Empty).Trim();
        lock (_gate)
        {
            if (_disposed) return;

            if (!string.Equals(path, _configuredPath, StringComparison.Ordinal))
            {
                _reader?.Dispose();
                _reader = null;
                _loadedAt = null;
                _lastAttemptAt = null;
                _failure = null;
                _lastLoggedFailure = null;
                _openedStamp = null;
                _lastChangeCheckAt = null;
                _lastLoggedReload = null;
                _configuredPath = path;
            }

            if (path.Length == 0)
            {
                _failure = "not configured";
                return;
            }

            if (_reader is not null)
            {
                ReloadIfReplaced(path, utcNow, force);
                return;
            }

            if (!ShouldRetry(false, _lastAttemptAt, utcNow, force)) return;
            Attempt(path, utcNow);
        }
    }

    /// <summary>Whether a load should be tried now: never while a reader is
    /// open, always on the first touch or when forced, otherwise once the
    /// retry interval has passed since the last failed attempt.</summary>
    public static bool ShouldRetry(bool loaded, DateTime? lastAttemptAt, DateTime utcNow, bool force)
    {
        if (loaded) return false;
        if (lastAttemptAt is null || force) return true;
        return utcNow - lastAttemptAt.Value >= RetryInterval;
    }

    /// <summary>Look an address up in the open reader; null when the reader
    /// is not open or the address is not in the database.</summary>
    public T? Find<T>(IPAddress address) where T : class
    {
        lock (_gate)
        {
            return _reader?.Find<T>(address);
        }
    }

    /// <summary>One line for the log: the name plus <see cref="DescribeDetail"/>.</summary>
    public static string Describe(GeoIpDatabaseStatus status) => $"{status.Name}: {DescribeDetail(status)}";

    /// <summary>The state without the name, for a Diagnostics row that
    /// already carries the database name in its label.</summary>
    public static string DescribeDetail(GeoIpDatabaseStatus status)
    {
        if (status.Loaded)
        {
            var at = status.LoadedAt.HasValue ? status.LoadedAt.Value.ToString("u", System.Globalization.CultureInfo.InvariantCulture) : "unknown time";
            return $"loaded from {status.ConfiguredPath} at {at}";
        }

        return status.Failure ?? "not loaded";
    }

    private void Attempt(string path, DateTime utcNow)
    {
        _lastAttemptAt = utcNow;
        _failure = null;

        // Taken before the open: a file replaced in between is then seen as
        // changed on the next look and opened again, never missed.
        var stamp = Stamp(path);
        if (!TryOpen(path, out var reader, out var failure))
        {
            Fail(failure);
            return;
        }

        _reader = reader;
        _openedStamp = stamp;
        _lastChangeCheckAt = utcNow;
        _loadedAt = utcNow;
        _lastLoggedFailure = null;
        _lastLoggedReload = null;
        _logger.LogInformation("[2FA] Loaded {Name} from {Path}", _name, path);
    }

    /// <summary>[#351] Reopen the file when something replaced it under the
    /// same path, looked at once per <see cref="RetryInterval"/> or when
    /// forced. A file that is gone keeps the open copy, which still reads; a
    /// replacement that does not open keeps it too, and the next look tries
    /// again, so an updater that is still writing is picked up once it is
    /// done.</summary>
    private void ReloadIfReplaced(string path, DateTime utcNow, bool force)
    {
        if (!force && _lastChangeCheckAt is { } checkedAt && utcNow - checkedAt < RetryInterval) return;
        _lastChangeCheckAt = utcNow;

        var stamp = Stamp(path);
        if (stamp is null || stamp == _openedStamp) return;

        if (!TryOpen(path, out var fresh, out var failure))
        {
            var loadedAt = _loadedAt?.ToString("u", CultureInfo.InvariantCulture) ?? "an unknown time";
            var note = $"{path} changed on disk but did not open ({failure}); still using the copy loaded at {loadedAt}";
            if (!string.Equals(note, _lastLoggedReload, StringComparison.Ordinal))
            {
                _lastLoggedReload = note;
                _logger.LogWarning("[2FA] GeoIP {Name}: {Note}", _name, note);
            }

            return;
        }

        var stale = _reader;
        _reader = fresh;
        _openedStamp = stamp;
        _loadedAt = utcNow;
        _lastLoggedReload = null;
        stale?.Dispose();
        _logger.LogInformation("[2FA] Reloaded {Name} from {Path}: the file changed on disk", _name, path);
    }

    /// <summary>The checks and the open shared by the first load and a reload:
    /// the path rules, whether the Jellyfin process sees the file (and as
    /// which user), and memory mapping with an in-memory fallback.</summary>
    private bool TryOpen(string path, [NotNullWhen(true)] out Reader? reader, [NotNullWhen(false)] out string? failure)
    {
        reader = null;
        if (!GeoIpService.TryValidatePath(path, out var reason))
        {
            failure = $"rejected ({reason}): {path}";
            return false;
        }

        if (!File.Exists(path))
        {
            var dir = Path.GetDirectoryName(path);
            var dirVisible = !string.IsNullOrEmpty(dir) && Directory.Exists(dir);
            failure = dirVisible
                ? $"not found at {path} (the directory is visible, the file is not; checked as user {ProcessUser})"
                : $"not found at {path} (its directory is not visible to the Jellyfin process; checked as user {ProcessUser})";
            return false;
        }

        try
        {
            reader = new Reader(path);
        }
        catch (Exception mapped)
        {
            try
            {
                reader = new Reader(path, FileAccessMode.Memory);
                _logger.LogInformation(
                    "[2FA] {Name}: memory mapping {Path} failed ({Reason}); opened it in memory instead",
                    _name, path, mapped.Message);
            }
            catch (Exception ex)
            {
                failure = $"open failed at {path}: {ex.Message}";
                return false;
            }
        }

        failure = null;
        return true;
    }

    // Size and modification time, which an updater that writes a new file
    // and renames it over the old one always changes. Null when the file is
    // not there or cannot be read.
    private static FileStamp? Stamp(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists ? new FileStamp(info.LastWriteTimeUtc, info.Length) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Record a failure; the log gets a warning the first time a
    /// given reason shows up for the current path and a debug line on the
    /// retries, so a permanently wrong path does not flood the log.</summary>
    private void Fail(string failure)
    {
        _failure = failure;
        if (!string.Equals(failure, _lastLoggedFailure, StringComparison.Ordinal))
        {
            _lastLoggedFailure = failure;
            _logger.LogWarning("[2FA] GeoIP {Name}: {Failure}", _name, failure);
        }
        else
        {
            _logger.LogDebug("[2FA] GeoIP {Name} still failing: {Failure}", _name, failure);
        }
    }

    /// <summary>The account name, or the numeric uid when the process runs
    /// as an id with no passwd entry (a container started with `user: 1000:1000`),
    /// which is exactly the case worth showing in a "not found" row.</summary>
    private static string SafeUserName()
    {
        try
        {
            if (!string.IsNullOrEmpty(Environment.UserName)) return Environment.UserName;
        }
        catch
        {
            // fall through to the uid
        }

        try
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/self/status"))
            {
                foreach (var line in File.ReadLines("/proc/self/status"))
                {
                    if (!line.StartsWith("Uid:", StringComparison.Ordinal)) continue;
                    var parts = line.Substring(4).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0) return "uid " + parts[0];
                }
            }
        }
        catch
        {
            // no readable status file: report unknown below
        }

        return "unknown";
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _reader?.Dispose();
            _reader = null;
        }
    }

    private readonly record struct FileStamp(DateTime WriteTimeUtc, long Length);
}

using System;
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

    /// <summary>Bring the reader in line with the configured path. A no-op
    /// while the path is unchanged and the reader is open; a failed load is
    /// retried after <see cref="RetryInterval"/>, or right away when
    /// <paramref name="force"/> is set (the Diagnostics tab does that).</summary>
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
                _configuredPath = path;
            }

            if (path.Length == 0)
            {
                _failure = "not configured";
                return;
            }

            if (!ShouldRetry(_reader is not null, _lastAttemptAt, utcNow, force)) return;
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

        if (!GeoIpService.TryValidatePath(path, out var reason))
        {
            Fail($"rejected ({reason}): {path}");
            return;
        }

        if (!File.Exists(path))
        {
            var dir = Path.GetDirectoryName(path);
            var dirVisible = !string.IsNullOrEmpty(dir) && Directory.Exists(dir);
            Fail(dirVisible
                ? $"not found at {path} (the directory is visible, the file is not; checked as user {ProcessUser})"
                : $"not found at {path} (its directory is not visible to the Jellyfin process; checked as user {ProcessUser})");
            return;
        }

        try
        {
            _reader = new Reader(path);
        }
        catch (Exception mapped)
        {
            try
            {
                _reader = new Reader(path, FileAccessMode.Memory);
                _logger.LogInformation(
                    "[2FA] {Name}: memory mapping {Path} failed ({Reason}); opened it in memory instead",
                    _name, path, mapped.Message);
            }
            catch (Exception ex)
            {
                Fail($"open failed at {path}: {ex.Message}");
                return;
            }
        }

        _loadedAt = utcNow;
        _lastLoggedFailure = null;
        _logger.LogInformation("[2FA] Loaded {Name} from {Path}", _name, path);
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
}

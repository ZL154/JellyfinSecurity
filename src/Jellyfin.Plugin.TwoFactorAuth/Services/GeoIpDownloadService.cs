using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using MaxMind.Db;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Net;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#351] The three GeoIP databases the detectors read: ASN and
/// Country for suspicious-login detection, City for impossible travel.</summary>
public enum GeoIpEdition
{
    Asn,
    Country,
    City,
}

/// <summary>[#351] What one update run did with one database.</summary>
public enum GeoIpDownloadOutcome
{
    /// <summary>A newer release was downloaded, checked and put in place.</summary>
    Installed,

    /// <summary>The newest published release was already on disk.</summary>
    UpToDate,

    /// <summary>The download or the check failed; the release already on
    /// disk, if any, stays in use.</summary>
    Failed,
}

/// <summary>[#351] One database in an update run. <see cref="Release"/> is the
/// release on disk after the run (year and month, "2026-11"), or null when
/// there is none; <see cref="Failure"/> is the reason a failed one failed.</summary>
public sealed record GeoIpEditionResult(GeoIpEdition Edition, GeoIpDownloadOutcome Outcome, string? Release, string? Failure);

/// <summary>[#351] A finished update run, kept for the Diagnostics tab.</summary>
public sealed record GeoIpDownloadRun(DateTime FinishedAt, IReadOnlyList<GeoIpEditionResult> Editions)
{
    public bool Failed => Editions.Any(e => e.Outcome == GeoIpDownloadOutcome.Failed);
}

/// <summary>
/// [#351] Downloads DB-IP's free Lite databases (IP to ASN, Country and City
/// in MaxMind DB format, Creative Commons Attribution 4.0, no account) for a
/// server that turns on <see cref="PluginConfiguration.GeoIpAutoUpdate"/>, so
/// the admin no longer places the .mmdb files by hand and replaces them every
/// month. The "Update GeoIP databases" scheduled task
/// (<see cref="GeoIpUpdateTask"/>) runs it.
///
/// DB-IP publishes one file per database and month at a fixed address
/// (dbip-city-lite-2026-11.mmdb.gz) and answers 404 for a month it has not
/// published yet, so a run asks for the current month and, until it exists,
/// keeps the previous one. With the current release on disk a run makes no
/// request at all.
///
/// Each release is kept under its own name in the plugin's data folder, so a
/// new release never overwrites a file a detector has open: Windows refuses
/// to replace a mapped file, and a reader must never see its file change
/// underneath it. The new file is written next to the old one, checked, and
/// then found by <see cref="ResolvePath"/>, and <see cref="GeoIpDatabase"/>
/// reopens because the path changed. Older releases are deleted afterwards;
/// one Windows still holds open goes on a later run.
/// </summary>
public sealed class GeoIpDownloadService : IDisposable
{
    /// <summary>Where DB-IP publishes the Lite databases.</summary>
    internal const string BaseUrl = "https://download.db-ip.com/free/";

    /// <summary>The most the plugin writes for one database. DB-IP's City Lite
    /// is about 127 MB unpacked (November 2026); this leaves room for it to
    /// grow and bounds what a broken or hostile answer can write to disk.</summary>
    internal const long MaxDatabaseBytes = 512L * 1024 * 1024;

    /// <summary>Suffix of a file still being written. It never matches a
    /// release name, so nothing reads it as a database.</summary>
    internal const string PartialSuffix = ".download";

    private const string DatabaseExtension = ".mmdb";

    // City Lite is about 60 MB compressed: generous for a slow uplink, and it
    // still ends a transfer that stalls.
    private static readonly TimeSpan DefaultDownloadTimeout = TimeSpan.FromMinutes(15);

    private static readonly GeoIpEdition[] AllEditions = { GeoIpEdition.Asn, GeoIpEdition.Country, GeoIpEdition.City };

    // An address every release resolves (Google's public resolver), used to
    // check that a downloaded file carries the fields the detectors read and
    // not only a valid header.
    private static readonly IPAddress Probe = IPAddress.Parse("8.8.8.8");

    private readonly Func<HttpClient> _httpClient;
    private readonly ILogger _logger;
    private readonly Func<DateTime> _utcNow;
    private readonly long _maxDatabaseBytes;
    private readonly TimeSpan _downloadTimeout;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile GeoIpDownloadRun? _lastRun;

    public GeoIpDownloadService(IHttpClientFactory httpClientFactory, IApplicationPaths paths, ILogger<GeoIpDownloadService> logger)
        : this(() => httpClientFactory.CreateClient(NamedClient.Default), DirectoryFor(paths), logger, () => DateTime.UtcNow)
    {
    }

    // Test seam: tests hand in a fake DB-IP, a temporary folder, the clock and
    // smaller limits.
    internal GeoIpDownloadService(
        Func<HttpClient> httpClient,
        string downloadDirectory,
        ILogger logger,
        Func<DateTime> utcNow,
        long maxDatabaseBytes = MaxDatabaseBytes,
        TimeSpan? downloadTimeout = null)
    {
        _httpClient = httpClient;
        DownloadDirectory = downloadDirectory;
        _logger = logger;
        _utcNow = utcNow;
        _maxDatabaseBytes = maxDatabaseBytes;
        _downloadTimeout = downloadTimeout ?? DefaultDownloadTimeout;
    }

    /// <summary>The folder the downloaded databases are kept in.</summary>
    public string DownloadDirectory { get; }

    /// <summary>The last finished run since the server started, or null.</summary>
    public GeoIpDownloadRun? LastRun => _lastRun;

    /// <summary>The "geoip" folder inside the plugin's data folder, next to
    /// the plugin's other files, where a plugin update leaves it alone.</summary>
    public static string DirectoryFor(IApplicationPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return Path.Combine(paths.PluginConfigurationsPath, "TwoFactorAuth", "geoip");
    }

    /// <summary>The databases the enabled detectors read, in download order:
    /// ASN and Country while suspicious-login detection is on, City while
    /// impossible-travel detection is on.</summary>
    public static IReadOnlyList<GeoIpEdition> EditionsFor(PluginConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var editions = new List<GeoIpEdition>(AllEditions.Length);
        if (config.SuspiciousLoginEnabled)
        {
            editions.Add(GeoIpEdition.Asn);
            editions.Add(GeoIpEdition.Country);
        }

        if (config.ImpossibleTravelEnabled)
        {
            editions.Add(GeoIpEdition.City);
        }

        return editions;
    }

    /// <summary>
    /// The file a database is read from. With automatic updates off, the path
    /// the admin set. With them on, the newest release in
    /// <paramref name="downloadDirectory"/>, or an empty path before the first
    /// download; the admin's paths are kept for when the setting goes off
    /// again, but not read.
    /// </summary>
    public static string ResolvePath(PluginConfiguration config, GeoIpEdition edition, string? downloadDirectory)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!config.GeoIpAutoUpdate)
        {
            var configured = edition switch
            {
                GeoIpEdition.Asn => config.GeoIpAsnDbPath,
                GeoIpEdition.Country => config.GeoIpCountryDbPath,
                GeoIpEdition.City => config.GeoIpCityDbPath,
                _ => throw new ArgumentOutOfRangeException(nameof(edition)),
            };
            return configured ?? string.Empty;
        }

        if (string.IsNullOrEmpty(downloadDirectory))
        {
            return string.Empty;
        }

        return NewestRelease(downloadDirectory, edition)?.FullPath ?? string.Empty;
    }

    /// <summary>
    /// Brings every database the enabled detectors read up to DB-IP's newest
    /// release. Returns null while automatic updates are off, without a
    /// request or a write. One database failing does not stop the others, and
    /// its release already on disk stays in use. Runs one at a time.
    /// </summary>
    public async Task<GeoIpDownloadRun?> UpdateAsync(PluginConfiguration config, IProgress<double>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!config.GeoIpAutoUpdate)
        {
            return null;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var setupFailure = PrepareDirectory();
            var editions = EditionsFor(config);
            var now = _utcNow();

            // The current month first; until DB-IP publishes it, the previous one.
            var releases = new[] { ReleaseOf(now), ReleaseOf(now.AddMonths(-1)) };
            var results = new List<GeoIpEditionResult>(editions.Count);
            for (var i = 0; i < editions.Count; i++)
            {
                results.Add(setupFailure is null
                    ? await UpdateEditionAsync(editions[i], releases, cancellationToken).ConfigureAwait(false)
                    : new GeoIpEditionResult(editions[i], GeoIpDownloadOutcome.Failed, null, setupFailure));
                progress?.Report(100.0 * (i + 1) / editions.Count);
            }

            if (editions.Count == 0)
            {
                progress?.Report(100);
            }

            var run = new GeoIpDownloadRun(_utcNow(), results);
            _lastRun = run;
            return run;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Whether a saved configuration needs a database not downloaded yet, so
    /// the update should run now rather than at its next scheduled time:
    /// automatic updates were just turned on, or a detector was turned on
    /// while they are on (it reads a database the last run skipped).
    /// </summary>
    public static bool ShouldRunAfterSave(PluginConfiguration? before, PluginConfiguration after)
    {
        ArgumentNullException.ThrowIfNull(after);
        if (!after.GeoIpAutoUpdate)
        {
            return false;
        }

        if (before is null || !before.GeoIpAutoUpdate)
        {
            return true;
        }

        return (after.SuspiciousLoginEnabled && !before.SuspiciousLoginEnabled)
            || (after.ImpossibleTravelEnabled && !before.ImpossibleTravelEnabled);
    }

    /// <summary>The newest release of a database in
    /// <paramref name="downloadDirectory"/> ("2026-11"), or null when there
    /// is none.</summary>
    public static string? InstalledRelease(string downloadDirectory, GeoIpEdition edition)
        => NewestRelease(downloadDirectory, edition)?.Release;

    /// <summary>"ASN", "Country" or "City", for messages.</summary>
    internal static string Label(GeoIpEdition edition) => edition switch
    {
        GeoIpEdition.Asn => "ASN",
        GeoIpEdition.Country => "Country",
        GeoIpEdition.City => "City",
        _ => throw new ArgumentOutOfRangeException(nameof(edition)),
    };

    /// <summary>
    /// Opens a downloaded file the way the detectors will and checks that it
    /// is the expected database with the fields they read. Throws
    /// <see cref="InvalidDataException"/> (or the reader's own exception for a
    /// file that is not a MaxMind database) with the reason.
    /// </summary>
    internal static void Verify(string path, GeoIpEdition edition)
    {
        var label = Label(edition);
        using var reader = new Reader(path);
        var type = reader.Metadata.DatabaseType ?? string.Empty;
        if (!type.Contains(label, StringComparison.OrdinalIgnoreCase))
        {
            var article = edition == GeoIpEdition.Asn ? "an" : "a";
            throw new InvalidDataException($"expected {article} {label} database, got \"{type}\"");
        }

        var record = reader.Find<Dictionary<string, object>>(Probe);
        var missing = edition switch
        {
            GeoIpEdition.Asn => record is not null && record.ContainsKey("autonomous_system_number") ? null : "autonomous_system_number",
            GeoIpEdition.Country => HasChild(record, "country", "iso_code") ? null : "country.iso_code",
            GeoIpEdition.City => HasChild(record, "location", "latitude") && HasChild(record, "location", "longitude")
                ? null
                : "location.latitude and location.longitude",
            _ => throw new ArgumentOutOfRangeException(nameof(edition)),
        };
        if (missing is not null)
        {
            throw new InvalidDataException($"the {label} database has no {missing} for {Probe}");
        }
    }

    private static bool HasChild(Dictionary<string, object>? record, string parent, string key)
        => record is not null
            && record.TryGetValue(parent, out var node)
            && node is Dictionary<string, object> child
            && child.ContainsKey(key);

    private static string ReleaseOf(DateTime utc) => utc.ToString("yyyy-MM", CultureInfo.InvariantCulture);

    private static string Token(GeoIpEdition edition) => edition switch
    {
        GeoIpEdition.Asn => "asn",
        GeoIpEdition.Country => "country",
        GeoIpEdition.City => "city",
        _ => throw new ArgumentOutOfRangeException(nameof(edition)),
    };

    // DB-IP's own name without the .gz: dbip-city-lite-2026-11.mmdb.
    private static string FileName(GeoIpEdition edition, string release) => $"dbip-{Token(edition)}-lite-{release}{DatabaseExtension}";

    // The release in a file name this service writes, or null for any other
    // name: a partial download, a renamed copy, a malformed month.
    private static string? ReleaseIn(string fileName, GeoIpEdition edition)
    {
        var prefix = $"dbip-{Token(edition)}-lite-";
        if (!fileName.StartsWith(prefix, StringComparison.Ordinal) || !fileName.EndsWith(DatabaseExtension, StringComparison.Ordinal))
        {
            return null;
        }

        var release = fileName.Substring(prefix.Length, fileName.Length - prefix.Length - DatabaseExtension.Length);
        return release.Length == 7
            && release[4] == '-'
            && DateTime.TryParseExact(release, "yyyy-MM", CultureInfo.InvariantCulture, DateTimeStyles.None, out _)
            ? release
            : null;
    }

    private static List<(string FullPath, string Release)> Releases(string directory, GeoIpEdition edition)
    {
        var found = new List<(string FullPath, string Release)>();
        if (!Directory.Exists(directory))
        {
            return found;
        }

        foreach (var file in Directory.EnumerateFiles(directory, "dbip-*" + DatabaseExtension))
        {
            var release = ReleaseIn(Path.GetFileName(file), edition);
            if (release is not null)
            {
                found.Add((file, release));
            }
        }

        return found;
    }

    private static (string FullPath, string Release)? NewestRelease(string directory, GeoIpEdition edition)
    {
        try
        {
            (string FullPath, string Release)? newest = null;
            foreach (var candidate in Releases(directory, edition))
            {
                if (newest is null || string.CompareOrdinal(candidate.Release, newest.Value.Release) > 0)
                {
                    newest = candidate;
                }
            }

            return newest;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The update run reports a folder it cannot use; a lookup only
            // finds no database.
            return null;
        }
    }

    private static async Task CopyBoundedAsync(Stream source, Stream destination, long maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                throw new InvalidDataException(TooLarge(maxBytes));
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private static string TooLarge(long maxBytes)
        => maxBytes >= 1024 * 1024
            ? $"the database is larger than the {maxBytes / (1024 * 1024)} MB limit"
            : $"the database is larger than the {maxBytes} byte limit";

    // Creates the folder and clears partial downloads a crash or a restart
    // left behind. Returns why the folder cannot be used, or null.
    private string? PrepareDirectory()
    {
        try
        {
            Directory.CreateDirectory(DownloadDirectory);
            foreach (var partial in Directory.EnumerateFiles(DownloadDirectory, "*" + PartialSuffix))
            {
                TryDelete(partial);
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("[2FA] GeoIP: cannot use {Directory} for downloads: {Reason}", DownloadDirectory, ex.Message);
            return $"cannot use {DownloadDirectory}: {ex.Message}";
        }
    }

    private async Task<GeoIpEditionResult> UpdateEditionAsync(GeoIpEdition edition, string[] releases, CancellationToken cancellationToken)
    {
        var installed = NewestRelease(DownloadDirectory, edition)?.Release;
        try
        {
            foreach (var release in releases)
            {
                if (installed is not null && string.CompareOrdinal(installed, release) >= 0)
                {
                    // Also on a run with nothing to download: Windows refuses
                    // to delete a release a reader still had open when the
                    // next one arrived, so the delete is tried again here.
                    DeleteReleasesBefore(edition, installed);
                    return new GeoIpEditionResult(edition, GeoIpDownloadOutcome.UpToDate, installed, null);
                }

                if (await TryInstallAsync(edition, release, cancellationToken).ConfigureAwait(false))
                {
                    DeleteReleasesBefore(edition, release);
                    _logger.LogInformation("[2FA] GeoIP: installed DB-IP {Edition} Lite {Release}", Label(edition), release);
                    return new GeoIpEditionResult(edition, GeoIpDownloadOutcome.Installed, release, null);
                }
            }

            throw new InvalidDataException(
                $"DB-IP has published neither {FileName(edition, releases[0])}.gz nor {FileName(edition, releases[1])}.gz");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[2FA] GeoIP: updating DB-IP {Edition} Lite failed: {Reason}", Label(edition), ex.Message);
            return new GeoIpEditionResult(edition, GeoIpDownloadOutcome.Failed, installed, ex.Message);
        }
    }

    // Downloads, unpacks and checks one release and moves it into place.
    // False when DB-IP has not published it (404); throws for anything else.
    private async Task<bool> TryInstallAsync(GeoIpEdition edition, string release, CancellationToken cancellationToken)
    {
        var fileName = FileName(edition, release);
        var target = Path.Combine(DownloadDirectory, fileName);
        var partial = target + PartialSuffix;
        var source = new Uri(BaseUrl + fileName + ".gz", UriKind.Absolute);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_downloadTimeout);
        try
        {
            using var client = _httpClient();
            using var response = await client.GetAsync(source, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return false;
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"DB-IP answered {(int)response.StatusCode} ({response.ReasonPhrase}) for {fileName}.gz",
                    null,
                    response.StatusCode);
            }

            if (response.Content.Headers.ContentLength > _maxDatabaseBytes)
            {
                throw new InvalidDataException(TooLarge(_maxDatabaseBytes));
            }

            using (var body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false))
            using (var unpacked = new GZipStream(body, CompressionMode.Decompress))
            using (var file = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                await CopyBoundedAsync(unpacked, file, _maxDatabaseBytes, timeout.Token).ConfigureAwait(false);

                // On disk before the rename, so a crash cannot leave an empty
                // file under the release name.
                file.Flush(flushToDisk: true);
            }

            Verify(partial, edition);
            File.Move(partial, target, overwrite: true);
            return true;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            var limit = _downloadTimeout.TotalMinutes >= 1
                ? $"{_downloadTimeout.TotalMinutes:0} minutes"
                : $"{_downloadTimeout.TotalSeconds:0.#} seconds";
            throw new TimeoutException($"{fileName}.gz did not finish downloading within {limit}");
        }
        finally
        {
            TryDelete(partial);
        }
    }

    private void DeleteReleasesBefore(GeoIpEdition edition, string release)
    {
        foreach (var older in Releases(DownloadDirectory, edition))
        {
            if (string.CompareOrdinal(older.Release, release) < 0)
            {
                TryDelete(older.FullPath);
            }
        }
    }

    private void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Windows keeps a file a reader still has mapped; the next run
            // deletes it.
            _logger.LogDebug("[2FA] GeoIP: could not delete {Path} yet: {Reason}", path, ex.Message);
        }
    }

    public void Dispose() => _gate.Dispose();
}

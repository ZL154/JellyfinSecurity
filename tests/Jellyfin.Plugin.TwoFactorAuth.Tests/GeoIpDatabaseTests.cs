using System;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#51] The GeoIP loader must say why a database is not open, retry a failed
// load instead of pinning the path, and keep the path safety rules.
public class GeoIpDatabaseTests
{
    private static readonly DateTime T0 = new(2026, 9, 11, 1, 0, 0, DateTimeKind.Utc);

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "jfsec-geoip-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Empty_path_means_not_configured_and_nothing_is_attempted()
    {
        using var db = new GeoIpDatabase("GeoLite2-ASN", NullLogger.Instance);
        db.Sync("   ", T0);

        var status = db.Status;
        Assert.False(status.Loaded);
        Assert.Equal("not configured", status.Failure);
        Assert.Null(status.LastAttemptAt);
        Assert.Equal("GeoLite2-ASN: not configured", GeoIpDatabase.Describe(status));
    }

    [Fact]
    public void Missing_file_is_reported_with_the_process_user_and_retried_after_the_interval()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "GeoLite2-Country.mmdb");
            using var db = new GeoIpDatabase("GeoLite2-Country", NullLogger.Instance);

            db.Sync(path, T0);
            var first = db.Status;
            Assert.False(first.Loaded);
            Assert.Equal(T0, first.LastAttemptAt);
            Assert.StartsWith("not found at " + path, first.Failure);
            Assert.Contains("the directory is visible", first.Failure);
            Assert.Contains("checked as user " + GeoIpDatabase.ProcessUser, first.Failure);
            Assert.Equal("GeoLite2-Country: " + first.Failure, GeoIpDatabase.Describe(first));

            // Same path, inside the interval: no new attempt.
            db.Sync(path, T0.AddSeconds(10));
            Assert.Equal(T0, db.Status.LastAttemptAt);

            // After the interval the loader tries again on its own.
            db.Sync(path, T0.AddSeconds(31));
            Assert.Equal(T0.AddSeconds(31), db.Status.LastAttemptAt);

            // A forced sync (Diagnostics re-run) does not wait.
            db.Sync(path, T0.AddSeconds(32), force: true);
            Assert.Equal(T0.AddSeconds(32), db.Status.LastAttemptAt);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Missing_directory_is_called_out_separately()
    {
        var path = Path.Combine(Path.GetTempPath(), "jfsec-geoip-does-not-exist-" + Guid.NewGuid().ToString("N"), "GeoLite2-ASN.mmdb");
        using var db = new GeoIpDatabase("GeoLite2-ASN", NullLogger.Instance);
        db.Sync(path, T0);
        Assert.Contains("its directory is not visible to the Jellyfin process", db.Status.Failure);
    }

    [Fact]
    public void Rejected_path_carries_the_reason()
    {
        using var db = new GeoIpDatabase("GeoLite2-ASN", NullLogger.Instance);
        db.Sync("geoip/GeoLite2-ASN.mmdb", T0);
        Assert.StartsWith("rejected (not absolute): ", db.Status.Failure);

        Assert.False(GeoIpService.TryValidatePath("/config/../etc/x.mmdb", out var reason));
        Assert.Equal("contains '..'", reason);
        Assert.False(GeoIpService.TryValidatePath("/config/geoip/GeoLite2-ASN.txt", out reason));
        Assert.Equal("must end with .mmdb", reason);
        Assert.False(GeoIpService.TryValidatePath("/etc/geoip/x.mmdb", out reason));
        Assert.Equal("sensitive system path '/etc/'", reason);
        Assert.False(GeoIpService.TryValidatePath("//nas/share/x.mmdb", out reason));
        Assert.Equal("UNC/network path", reason);
        Assert.True(GeoIpService.TryValidatePath("/config/geoip/GeoLite2-ASN.mmdb", out reason));
        Assert.Equal(string.Empty, reason);
    }

    [Fact]
    public void Unreadable_database_reports_the_open_error_and_waits_before_retrying()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "broken.mmdb");
            File.WriteAllBytes(path, new byte[64]);
            using var db = new GeoIpDatabase("GeoLite2-ASN", NullLogger.Instance);

            db.Sync(path, T0);
            var status = db.Status;
            Assert.False(status.Loaded);
            Assert.StartsWith("open failed at " + path + ": ", status.Failure);

            db.Sync(path, T0.AddSeconds(5));
            Assert.Equal(T0, db.Status.LastAttemptAt);

            // A new path resets the state and is tried at once.
            var other = Path.Combine(dir, "other.mmdb");
            db.Sync(other, T0.AddSeconds(6));
            Assert.Equal(T0.AddSeconds(6), db.Status.LastAttemptAt);
            Assert.StartsWith("not found at " + other, db.Status.Failure);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Describe_reports_a_loaded_database_with_its_path_and_time()
    {
        var status = new GeoIpDatabaseStatus("GeoLite2-City", "/config/geoip/GeoLite2-City.mmdb", true, T0, T0, null);
        Assert.Equal("GeoLite2-City: loaded from /config/geoip/GeoLite2-City.mmdb at 2026-09-11 01:00:00Z", GeoIpDatabase.Describe(status));
        Assert.Equal("loaded from /config/geoip/GeoLite2-City.mmdb at 2026-09-11 01:00:00Z", GeoIpDatabase.DescribeDetail(status));
    }

    [Fact]
    public void Diagnostics_emit_one_row_per_configured_database_and_point_a_missing_file_at_the_data_directory()
    {
        var statuses = new[]
        {
            new GeoIpDatabaseStatus("GeoLite2-ASN", "/config/geoip/GeoLite2-ASN.mmdb", true, T0, T0, null),
            new GeoIpDatabaseStatus("GeoLite2-Country", "/volume1/docker/geoip/GeoLite2-Country.mmdb", false, null, T0,
                "not found at /volume1/docker/geoip/GeoLite2-Country.mmdb (its directory is not visible to the Jellyfin process; checked as user abc)"),
            new GeoIpDatabaseStatus("GeoLite2-City", string.Empty, false, null, null, "not configured"),
        };

        var rows = DiagnosticsService.GeoIpChecks(statuses, "/config").ToList();

        Assert.Equal(2, rows.Count);
        Assert.Equal("geoip_asn", rows[0].Id);
        Assert.Equal("GeoIP GeoLite2-ASN database", rows[0].Label);
        Assert.Equal(DiagnosticsService.CheckStatus.Ok, rows[0].Status);
        Assert.Equal("loaded from /config/geoip/GeoLite2-ASN.mmdb at 2026-09-11 01:00:00Z", rows[0].Detail);
        Assert.Equal("geoip_country", rows[1].Id);
        Assert.Equal(DiagnosticsService.CheckStatus.Fail, rows[1].Status);
        Assert.EndsWith("checked as user abc); Jellyfin's data directory is /config", rows[1].Detail);
    }

    [Theory]
    [InlineData(true, 0, false, false)]   // open: never retry
    [InlineData(false, -1, false, true)]  // never tried
    [InlineData(false, 10, false, false)] // failed 10 s ago
    [InlineData(false, 30, false, true)]  // interval reached
    [InlineData(false, 1, true, true)]    // forced
    public void ShouldRetry_follows_the_interval_unless_forced(bool loaded, int secondsAgo, bool force, bool expected)
    {
        DateTime? last = secondsAgo < 0 ? null : T0.AddSeconds(-secondsAgo);
        Assert.Equal(expected, GeoIpDatabase.ShouldRetry(loaded, last, T0, force));
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MaxMind.Db;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#351] Automatic GeoIP updates: the plugin downloads DB-IP's free Lite
// databases, one file per database and month, checks each file before it is
// used, and keeps only the newest release. DB-IP is played here by a fake
// HTTP handler that serves tiny databases built by TestMmdb.
public sealed class GeoIpDownloadServiceTests : IDisposable
{
    // November 2026: the current release is 2026-11 and the previous 2026-10.
    private static readonly DateTime Now = new(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);

    private readonly string _root;
    private readonly string _dir;
    private readonly FakeDbIp _dbIp = new();

    public GeoIpDownloadServiceTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "jfsec-geoip-dl-" + Guid.NewGuid().ToString("N"));
        _dir = Path.Combine(_root, "TwoFactorAuth", "geoip");
    }

    public void Dispose()
    {
        _dbIp.Dispose();
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task Nothing_is_requested_or_written_while_automatic_updates_are_off()
    {
        using var service = Service();

        var run = await service.UpdateAsync(new PluginConfiguration(), null, CancellationToken.None);

        Assert.Null(run);
        Assert.Empty(_dbIp.Requests);
        Assert.False(Directory.Exists(_dir));
    }

    [Fact]
    public async Task The_first_run_installs_the_current_release_of_each_database_from_db_ip()
    {
        PublishAll("2026-11");
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.NotNull(run);
        Assert.False(run.Failed);
        Assert.Equal(new[] { GeoIpEdition.Asn, GeoIpEdition.Country, GeoIpEdition.City }, run.Editions.Select(e => e.Edition));
        Assert.All(run.Editions, e =>
        {
            Assert.Equal(GeoIpDownloadOutcome.Installed, e.Outcome);
            Assert.Equal("2026-11", e.Release);
            Assert.Null(e.Failure);
        });
        Assert.Equal(
            new[] { Url("asn", "2026-11"), Url("country", "2026-11"), Url("city", "2026-11") },
            _dbIp.Requests);
        Assert.Equal(
            new[] { "dbip-asn-lite-2026-11.mmdb", "dbip-city-lite-2026-11.mmdb", "dbip-country-lite-2026-11.mmdb" },
            Files());

        // The installed files are the databases DB-IP served, unpacked.
        using (var asn = new Reader(Path.Combine(_dir, "dbip-asn-lite-2026-11.mmdb")))
        {
            var record = asn.Find<Dictionary<string, object>>(IPAddress.Parse("203.0.113.7"));
            Assert.Equal(64500L, Convert.ToInt64(record!["autonomous_system_number"], System.Globalization.CultureInfo.InvariantCulture));
        }

        using (var city = new Reader(Path.Combine(_dir, "dbip-city-lite-2026-11.mmdb")))
        {
            var record = city.Find<Dictionary<string, object>>(IPAddress.Parse("203.0.113.7"));
            var location = Assert.IsType<Dictionary<string, object>>(record!["location"]);
            Assert.Equal(37.422, (double)location["latitude"], 3);
        }
    }

    [Fact]
    public async Task Only_the_databases_of_the_detectors_that_are_on_are_downloaded()
    {
        PublishAll("2026-11");

        using (var service = Service())
        {
            var run = await service.UpdateAsync(On(suspicious: false), null, CancellationToken.None);
            Assert.Equal(new[] { GeoIpEdition.City }, run!.Editions.Select(e => e.Edition));
            Assert.Equal(new[] { Url("city", "2026-11") }, _dbIp.Requests);
        }

        _dbIp.Requests.Clear();
        Directory.Delete(_dir, recursive: true);

        using (var service = Service())
        {
            var run = await service.UpdateAsync(On(travel: false), null, CancellationToken.None);
            Assert.Equal(new[] { GeoIpEdition.Asn, GeoIpEdition.Country }, run!.Editions.Select(e => e.Edition));
            Assert.Equal(new[] { Url("asn", "2026-11"), Url("country", "2026-11") }, _dbIp.Requests);
        }

        _dbIp.Requests.Clear();

        using (var service = Service())
        {
            var run = await service.UpdateAsync(On(suspicious: false, travel: false), null, CancellationToken.None);
            Assert.Empty(run!.Editions);
            Assert.False(run.Failed);
            Assert.Empty(_dbIp.Requests);
        }
    }

    [Fact]
    public async Task A_release_already_on_disk_needs_no_request()
    {
        InstallAll("2026-11");
        PublishAll("2026-11");
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.Empty(_dbIp.Requests);
        Assert.All(run!.Editions, e =>
        {
            Assert.Equal(GeoIpDownloadOutcome.UpToDate, e.Outcome);
            Assert.Equal("2026-11", e.Release);
        });
    }

    [Fact]
    public async Task Before_db_ip_publishes_the_new_month_the_previous_release_stays()
    {
        // DB-IP answers 404 for a month it has not published yet.
        InstallAll("2026-10");
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.False(run!.Failed);
        Assert.All(run.Editions, e =>
        {
            Assert.Equal(GeoIpDownloadOutcome.UpToDate, e.Outcome);
            Assert.Equal("2026-10", e.Release);
        });
        Assert.Equal(new[] { Url("asn", "2026-11"), Url("country", "2026-11"), Url("city", "2026-11") }, _dbIp.Requests);
        Assert.Equal(
            new[] { "dbip-asn-lite-2026-10.mmdb", "dbip-city-lite-2026-10.mmdb", "dbip-country-lite-2026-10.mmdb" },
            Files());
    }

    [Fact]
    public async Task With_nothing_installed_a_missing_current_month_falls_back_to_the_previous_one()
    {
        PublishAll("2026-10");
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.False(run!.Failed);
        Assert.All(run.Editions, e =>
        {
            Assert.Equal(GeoIpDownloadOutcome.Installed, e.Outcome);
            Assert.Equal("2026-10", e.Release);
        });
        Assert.Equal(
            new[] { "dbip-asn-lite-2026-10.mmdb", "dbip-city-lite-2026-10.mmdb", "dbip-country-lite-2026-10.mmdb" },
            Files());
    }

    [Fact]
    public async Task Neither_month_published_is_a_failure_that_names_both()
    {
        using var service = Service();

        var run = await service.UpdateAsync(On(travel: false), null, CancellationToken.None);

        Assert.True(run!.Failed);
        Assert.All(run.Editions, e =>
        {
            Assert.Equal(GeoIpDownloadOutcome.Failed, e.Outcome);
            Assert.Null(e.Release);
            Assert.Contains("2026-11", e.Failure);
            Assert.Contains("2026-10", e.Failure);
        });
        Assert.Empty(Files());
    }

    [Fact]
    public async Task A_new_release_replaces_the_previous_one_on_disk()
    {
        InstallAll("2026-09");
        InstallAll("2026-10");
        PublishAll("2026-11");
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.All(run!.Editions, e => Assert.Equal(GeoIpDownloadOutcome.Installed, e.Outcome));
        Assert.Equal(
            new[] { "dbip-asn-lite-2026-11.mmdb", "dbip-city-lite-2026-11.mmdb", "dbip-country-lite-2026-11.mmdb" },
            Files());
    }

    [Fact]
    public async Task An_older_release_left_behind_is_deleted_by_the_next_run()
    {
        // Windows cannot delete a release a reader still has open when the
        // next one arrives; a later run, with nothing to download, clears it.
        InstallAll("2026-10");
        InstallAll("2026-11");
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.All(run!.Editions, e => Assert.Equal(GeoIpDownloadOutcome.UpToDate, e.Outcome));
        Assert.Empty(_dbIp.Requests);
        Assert.Equal(
            new[] { "dbip-asn-lite-2026-11.mmdb", "dbip-city-lite-2026-11.mmdb", "dbip-country-lite-2026-11.mmdb" },
            Files());
    }

    [Fact]
    public async Task A_server_error_fails_that_database_and_keeps_its_installed_release()
    {
        InstallAll("2026-10");
        Publish("asn", "2026-11");
        Publish("country", "2026-11");
        _dbIp.Routes[Url("city", "2026-11")] = () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        using var service = Service();

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.True(run!.Failed);
        var city = run.Editions.Single(e => e.Edition == GeoIpEdition.City);
        Assert.Equal(GeoIpDownloadOutcome.Failed, city.Outcome);
        Assert.Equal("2026-10", city.Release);
        Assert.Contains("503", city.Failure);
        Assert.Contains("dbip-city-lite-2026-11.mmdb.gz", city.Failure);
        Assert.All(run.Editions.Where(e => e.Edition != GeoIpEdition.City), e => Assert.Equal(GeoIpDownloadOutcome.Installed, e.Outcome));
        Assert.Equal(
            new[] { "dbip-asn-lite-2026-11.mmdb", "dbip-city-lite-2026-10.mmdb", "dbip-country-lite-2026-11.mmdb" },
            Files());
    }

    [Fact]
    public async Task A_file_that_is_not_the_expected_database_is_not_installed()
    {
        // An ASN database served where the City database belongs.
        Publish("city", "2026-11", TestMmdb.Build("DBIP-ASN-Lite (compat=GeoLite2-ASN)", TestMmdb.AsnRecord()));
        using var service = Service();

        var run = await service.UpdateAsync(On(suspicious: false), null, CancellationToken.None);

        var city = Assert.Single(run!.Editions);
        Assert.Equal(GeoIpDownloadOutcome.Failed, city.Outcome);
        Assert.Contains("expected a City database", city.Failure);
        Assert.Contains("DBIP-ASN-Lite", city.Failure);
        Assert.Empty(Files());
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task A_database_without_the_fields_the_detectors_read_is_not_installed()
    {
        // The right type name, but no location for the impossible-travel
        // detector to compute a distance from.
        Publish("city", "2026-11", TestMmdb.Build("DBIP-City-Lite", TestMmdb.CountryRecord()));
        using var service = Service();

        var run = await service.UpdateAsync(On(suspicious: false), null, CancellationToken.None);

        var city = Assert.Single(run!.Editions);
        Assert.Equal(GeoIpDownloadOutcome.Failed, city.Outcome);
        Assert.Contains("latitude", city.Failure);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task A_body_that_is_not_gzip_is_not_installed()
    {
        _dbIp.Routes[Url("asn", "2026-11")] = () => Ok(TestMmdb.Build("DBIP-ASN-Lite (compat=GeoLite2-ASN)", TestMmdb.AsnRecord()));
        Publish("country", "2026-11");
        using var service = Service();

        var run = await service.UpdateAsync(On(travel: false), null, CancellationToken.None);

        Assert.Equal(GeoIpDownloadOutcome.Failed, run!.Editions.Single(e => e.Edition == GeoIpEdition.Asn).Outcome);
        Assert.Equal(new[] { "dbip-country-lite-2026-11.mmdb" }, Files());
        Assert.Single(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task A_database_larger_than_the_limit_is_cut_off_and_not_installed()
    {
        var asnDatabase = TestMmdb.Build("DBIP-ASN-Lite (compat=GeoLite2-ASN)", TestMmdb.AsnRecord());
        var countryDatabase = TestMmdb.Build("DBIP-Country-Lite", TestMmdb.CountryRecord());
        Publish("asn", "2026-11", asnDatabase);
        Publish("country", "2026-11", countryDatabase);
        using var service = Service(maxDatabaseBytes: Math.Min(asnDatabase.Length, countryDatabase.Length) - 1);

        var run = await service.UpdateAsync(On(travel: false), null, CancellationToken.None);

        Assert.All(run!.Editions, e =>
        {
            Assert.Equal(GeoIpDownloadOutcome.Failed, e.Outcome);
            Assert.Contains("larger than", e.Failure);
        });
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task A_download_that_takes_too_long_fails_with_the_time_limit()
    {
        _dbIp.Routes[Url("asn", "2026-11")] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StallingStream()) };
        Publish("country", "2026-11");
        using var service = Service(downloadTimeout: TimeSpan.FromMilliseconds(200));

        var run = await service.UpdateAsync(On(travel: false), null, CancellationToken.None);

        var asn = run!.Editions.Single(e => e.Edition == GeoIpEdition.Asn);
        Assert.Equal(GeoIpDownloadOutcome.Failed, asn.Outcome);
        Assert.Contains("did not finish", asn.Failure);
        Assert.Equal(GeoIpDownloadOutcome.Installed, run.Editions.Single(e => e.Edition == GeoIpEdition.Country).Outcome);
        Assert.Equal(new[] { "dbip-country-lite-2026-11.mmdb" }, Files());
    }

    [Fact]
    public async Task Cancelling_the_run_is_not_reported_as_a_failed_database()
    {
        _dbIp.Routes[Url("asn", "2026-11")] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StallingStream()) };
        using var service = Service();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.UpdateAsync(On(travel: false), null, cts.Token));

        Assert.Null(service.LastRun);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task Leftover_partial_downloads_are_removed()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllBytes(Path.Combine(_dir, "dbip-city-lite-2026-11.mmdb.download"), new byte[] { 1, 2, 3 });
        InstallAll("2026-11");
        using var service = Service();

        await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.False(File.Exists(Path.Combine(_dir, "dbip-city-lite-2026-11.mmdb.download")));
    }

    [Fact]
    public async Task Two_runs_at_once_do_not_download_twice()
    {
        var release = new TaskCompletionSource();
        _dbIp.BeforeAnswer = () => release.Task;
        PublishAll("2026-11");
        using var service = Service();

        var first = service.UpdateAsync(On(), null, CancellationToken.None);
        var second = service.UpdateAsync(On(), null, CancellationToken.None);
        release.SetResult();
        var runs = await Task.WhenAll(first, second);

        Assert.Equal(3, _dbIp.Requests.Count);
        Assert.Single(runs, r => r!.Editions.All(e => e.Outcome == GeoIpDownloadOutcome.Installed));
        Assert.Single(runs, r => r!.Editions.All(e => e.Outcome == GeoIpDownloadOutcome.UpToDate));
    }

    [Fact]
    public async Task The_last_run_is_kept_for_the_diagnostics_tab()
    {
        PublishAll("2026-11");
        using var service = Service();
        Assert.Null(service.LastRun);

        var run = await service.UpdateAsync(On(), null, CancellationToken.None);

        Assert.Same(run, service.LastRun);
        Assert.Equal(Now, service.LastRun!.FinishedAt);
    }

    [Fact]
    public async Task Progress_reaches_100_after_the_last_database()
    {
        InstallAll("2026-11");
        using var service = Service();
        var reported = new List<double>();

        await service.UpdateAsync(On(), new SyncProgress(reported.Add), CancellationToken.None);

        Assert.Equal(100, reported[^1], 3);
        Assert.Equal(reported.OrderBy(p => p), reported);
    }

    [Fact]
    public void While_automatic_updates_are_off_the_admin_paths_are_used()
    {
        InstallAll("2026-11");
        var cfg = new PluginConfiguration
        {
            GeoIpAsnDbPath = "/config/geoip/GeoLite2-ASN.mmdb",
            GeoIpCountryDbPath = "/config/geoip/GeoLite2-Country.mmdb",
            GeoIpCityDbPath = "/config/geoip/GeoLite2-City.mmdb",
        };

        Assert.Equal("/config/geoip/GeoLite2-ASN.mmdb", GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.Asn, _dir));
        Assert.Equal("/config/geoip/GeoLite2-Country.mmdb", GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.Country, _dir));
        Assert.Equal("/config/geoip/GeoLite2-City.mmdb", GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.City, _dir));
    }

    [Fact]
    public void With_automatic_updates_on_the_newest_downloaded_release_is_used_instead_of_the_admin_paths()
    {
        InstallAll("2026-09");
        InstallAll("2026-10");
        var cfg = new PluginConfiguration { GeoIpAutoUpdate = true, GeoIpCityDbPath = "/config/geoip/GeoLite2-City.mmdb" };

        Assert.Equal(Path.Combine(_dir, "dbip-asn-lite-2026-10.mmdb"), GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.Asn, _dir));
        Assert.Equal(Path.Combine(_dir, "dbip-country-lite-2026-10.mmdb"), GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.Country, _dir));
        Assert.Equal(Path.Combine(_dir, "dbip-city-lite-2026-10.mmdb"), GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.City, _dir));
    }

    [Fact]
    public void With_automatic_updates_on_and_nothing_downloaded_yet_no_path_is_used()
    {
        var cfg = new PluginConfiguration { GeoIpAutoUpdate = true, GeoIpAsnDbPath = "/config/geoip/GeoLite2-ASN.mmdb" };

        Assert.Equal(string.Empty, GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.Asn, _dir));
        Assert.Equal(string.Empty, GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.Asn, null));
    }

    [Fact]
    public void Files_that_do_not_follow_the_release_name_are_never_picked()
    {
        Directory.CreateDirectory(_dir);
        foreach (var name in new[] { "dbip-city-lite-2026-12.mmdb.download", "dbip-city-lite-latest.mmdb", "dbip-city-lite-2026-1.mmdb", "GeoLite2-City.mmdb", "dbip-city-lite-2026-13x.mmdb" })
        {
            File.WriteAllBytes(Path.Combine(_dir, name), new byte[] { 1 });
        }

        var cfg = new PluginConfiguration { GeoIpAutoUpdate = true };

        Assert.Equal(string.Empty, GeoIpDownloadService.ResolvePath(cfg, GeoIpEdition.City, _dir));
    }

    [Fact]
    public void A_saved_configuration_from_before_the_setting_keeps_automatic_updates_off()
    {
        const string xml = "<PluginConfiguration><GeoIpCityDbPath>/config/geoip/GeoLite2-City.mmdb</GeoIpCityDbPath></PluginConfiguration>";
        using var reader = new StringReader(xml);
        var cfg = (PluginConfiguration)new System.Xml.Serialization.XmlSerializer(typeof(PluginConfiguration)).Deserialize(reader)!;

        Assert.False(cfg.GeoIpAutoUpdate);
        Assert.False(new PluginConfiguration().GeoIpAutoUpdate);
    }

    [Fact]
    public void The_task_runs_at_startup_and_every_24_hours()
    {
        using var service = Service();
        var task = new GeoIpUpdateTask(service, () => On());

        var triggers = task.GetDefaultTriggers().ToList();

        Assert.Equal(2, triggers.Count);
        Assert.Contains(triggers, t => t.Type == TaskTriggerInfoType.StartupTrigger);
        Assert.Contains(triggers, t => t.Type == TaskTriggerInfoType.IntervalTrigger && t.IntervalTicks == TimeSpan.FromHours(24).Ticks);
        Assert.Equal("Update GeoIP databases", task.Name);
        Assert.Equal("Jellyfin Security", task.Category);
        Assert.False(string.IsNullOrWhiteSpace(task.Key));
    }

    [Fact]
    public async Task A_run_with_a_failed_database_fails_the_task_with_the_reason()
    {
        PublishAll("2026-11");
        _dbIp.Routes[Url("city", "2026-11")] = () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        using var service = Service();
        var task = new GeoIpUpdateTask(service, () => On());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => task.ExecuteAsync(new SyncProgress(_ => { }), CancellationToken.None));

        Assert.Contains("City", ex.Message);
        Assert.Contains("503", ex.Message);
    }

    [Fact]
    public async Task The_task_does_nothing_while_automatic_updates_are_off()
    {
        using var service = Service();
        var task = new GeoIpUpdateTask(service, () => new PluginConfiguration());

        await task.ExecuteAsync(new SyncProgress(_ => { }), CancellationToken.None);

        Assert.Empty(_dbIp.Requests);
        Assert.Null(service.LastRun);
    }

    [Fact]
    public void The_lookup_service_reads_the_downloaded_release_and_moves_to_the_next_one()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllBytes(Path.Combine(_dir, "dbip-asn-lite-2026-10.mmdb"), TestMmdb.Build("DBIP-ASN-Lite (compat=GeoLite2-ASN)", TestMmdb.AsnRecord(64500)));
        var cfg = new PluginConfiguration { GeoIpAutoUpdate = true, GeoIpAsnDbPath = "/config/geoip/GeoLite2-ASN.mmdb" };
        using var geo = new GeoIpService(NullLogger<GeoIpService>.Instance, () => cfg, () => _dir);

        Assert.Equal(64500u, geo.Resolve("203.0.113.7").Asn);
        Assert.Equal(Path.Combine(_dir, "dbip-asn-lite-2026-10.mmdb"), geo.Statuses[0].ConfiguredPath);

        // The next release lands under its own name, and the next lookup
        // switches to it.
        File.WriteAllBytes(Path.Combine(_dir, "dbip-asn-lite-2026-11.mmdb"), TestMmdb.Build("DBIP-ASN-Lite (compat=GeoLite2-ASN)", TestMmdb.AsnRecord(64501)));
        Assert.Equal(64501u, geo.Resolve("203.0.113.7").Asn);

        // Turning automatic updates off goes back to the admin's path.
        cfg.GeoIpAutoUpdate = false;
        Assert.Equal("/config/geoip/GeoLite2-ASN.mmdb", geo.Statuses[0].ConfiguredPath);
    }

    [Fact]
    public void The_impossible_travel_detector_reads_the_downloaded_city_database()
    {
        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "dbip-city-lite-2026-11.mmdb");
        File.WriteAllBytes(file, ValidDatabase("city"));
        var cfg = new PluginConfiguration { GeoIpAutoUpdate = true, GeoIpCityDbPath = "/config/geoip/GeoLite2-City.mmdb" };
        var store = new UserTwoFactorStore(TestApplicationPaths.Create(out var sandbox), Substitute.For<IServiceProvider>());
        try
        {
            using var travel = new ImpossibleTravelDetector(
                store,
                new NotificationService(NullLogger<NotificationService>.Instance),
                NullLogger<ImpossibleTravelDetector>.Instance,
                () => cfg,
                () => _dir);

            Assert.True(travel.CityAvailable);
            Assert.Equal(file, travel.CityStatus.ConfiguredPath);
        }
        finally
        {
            Directory.Delete(sandbox, recursive: true);
        }
    }

    [Theory]
    // auto before/after, suspicious-login before/after, impossible travel before/after
    [InlineData(false, true, true, true, true, true, true)]   // switched on
    [InlineData(true, true, true, true, true, true, false)]   // already on, nothing new needed
    [InlineData(true, false, true, true, true, true, false)]  // switched off
    [InlineData(false, false, true, true, true, true, false)] // stays off
    [InlineData(true, true, false, true, true, true, true)]   // suspicious-login turned on: ASN and Country now needed
    [InlineData(true, true, true, true, false, true, true)]   // impossible travel turned on: City now needed
    [InlineData(true, true, true, false, true, false, false)] // detectors turned off need nothing new
    public void A_save_starts_an_update_when_it_needs_a_database_not_downloaded_yet(
        bool autoBefore, bool autoAfter, bool suspiciousBefore, bool suspiciousAfter, bool travelBefore, bool travelAfter, bool expected)
    {
        var before = new PluginConfiguration { GeoIpAutoUpdate = autoBefore, SuspiciousLoginEnabled = suspiciousBefore, ImpossibleTravelEnabled = travelBefore };
        var after = new PluginConfiguration { GeoIpAutoUpdate = autoAfter, SuspiciousLoginEnabled = suspiciousAfter, ImpossibleTravelEnabled = travelAfter };

        Assert.Equal(expected, GeoIpDownloadService.ShouldRunAfterSave(before, after));
    }

    [Fact]
    public void A_first_save_with_automatic_updates_on_starts_an_update()
    {
        Assert.True(GeoIpDownloadService.ShouldRunAfterSave(null, On()));
        Assert.False(GeoIpDownloadService.ShouldRunAfterSave(null, new PluginConfiguration()));
    }

    [Fact]
    public void The_diagnostics_row_is_ok_with_every_needed_release_on_disk()
    {
        var run = new GeoIpDownloadRun(Now, new[]
        {
            new GeoIpEditionResult(GeoIpEdition.Asn, GeoIpDownloadOutcome.UpToDate, "2026-11", null),
            new GeoIpEditionResult(GeoIpEdition.Country, GeoIpDownloadOutcome.UpToDate, "2026-11", null),
            new GeoIpEditionResult(GeoIpEdition.City, GeoIpDownloadOutcome.Installed, "2026-11", null),
        });

        var row = DiagnosticsService.GeoIpUpdateCheck(On(), run, _ => "2026-11");

        Assert.Equal("geoip_update", row.Id);
        Assert.Equal(DiagnosticsService.CheckStatus.Ok, row.Status);
        Assert.Equal("DB-IP Lite on disk: ASN 2026-11, Country 2026-11, City 2026-11; last run 2026-11-10 12:00:00Z", row.Detail);
    }

    [Fact]
    public void The_diagnostics_row_warns_before_the_first_download()
    {
        var row = DiagnosticsService.GeoIpUpdateCheck(On(), null, _ => null);

        Assert.Equal(DiagnosticsService.CheckStatus.Warn, row.Status);
        Assert.StartsWith("DB-IP Lite on disk: ASN none, Country none, City none; no update run since the server started", row.Detail);
        Assert.Contains("Update GeoIP databases", row.Detail);
    }

    [Fact]
    public void The_diagnostics_row_fails_when_a_needed_database_is_missing_after_a_failed_run()
    {
        var run = new GeoIpDownloadRun(Now, new[]
        {
            new GeoIpEditionResult(GeoIpEdition.City, GeoIpDownloadOutcome.Failed, null, "DB-IP answered 503 (Service Unavailable) for dbip-city-lite-2026-11.mmdb.gz"),
        });

        var row = DiagnosticsService.GeoIpUpdateCheck(On(suspicious: false), run, _ => null);

        Assert.Equal(DiagnosticsService.CheckStatus.Fail, row.Status);
        Assert.Equal(
            "DB-IP Lite on disk: City none; last run 2026-11-10 12:00:00Z; City failed: DB-IP answered 503 (Service Unavailable) for dbip-city-lite-2026-11.mmdb.gz",
            row.Detail);
    }

    [Fact]
    public void The_diagnostics_row_warns_when_the_last_run_failed_but_an_older_release_is_in_use()
    {
        var run = new GeoIpDownloadRun(Now, new[]
        {
            new GeoIpEditionResult(GeoIpEdition.City, GeoIpDownloadOutcome.Failed, "2026-10", "DB-IP answered 503 (Service Unavailable) for dbip-city-lite-2026-11.mmdb.gz"),
        });

        var row = DiagnosticsService.GeoIpUpdateCheck(On(suspicious: false), run, _ => "2026-10");

        Assert.Equal(DiagnosticsService.CheckStatus.Warn, row.Status);
        Assert.Contains("City 2026-10", row.Detail);
        Assert.Contains("City failed: DB-IP answered 503", row.Detail);
    }

    [Fact]
    public void The_diagnostics_row_says_when_no_detector_needs_a_database()
    {
        var row = DiagnosticsService.GeoIpUpdateCheck(On(suspicious: false, travel: false), null, _ => null);

        Assert.Equal(DiagnosticsService.CheckStatus.Ok, row.Status);
        Assert.StartsWith("no detector that reads a GeoIP database is on", row.Detail);
    }

    private GeoIpDownloadService Service(long maxDatabaseBytes = GeoIpDownloadService.MaxDatabaseBytes, TimeSpan? downloadTimeout = null)
        => new(() => new HttpClient(_dbIp, disposeHandler: false), _dir, NullLogger.Instance, () => Now, maxDatabaseBytes, downloadTimeout);

    private static PluginConfiguration On(bool suspicious = true, bool travel = true) => new()
    {
        GeoIpAutoUpdate = true,
        SuspiciousLoginEnabled = suspicious,
        ImpossibleTravelEnabled = travel,
    };

    private static string Url(string edition, string release) => $"https://download.db-ip.com/free/dbip-{edition}-lite-{release}.mmdb.gz";

    private static byte[] ValidDatabase(string edition) => edition switch
    {
        "asn" => TestMmdb.Build("DBIP-ASN-Lite (compat=GeoLite2-ASN)", TestMmdb.AsnRecord()),
        "country" => TestMmdb.Build("DBIP-Country-Lite", TestMmdb.CountryRecord()),
        "city" => TestMmdb.Build("DBIP-City-Lite", TestMmdb.CityRecord()),
        _ => throw new ArgumentOutOfRangeException(nameof(edition)),
    };

    private void Publish(string edition, string release, byte[]? database = null)
    {
        var body = TestMmdb.Gzip(database ?? ValidDatabase(edition));
        _dbIp.Routes[Url(edition, release)] = () => Ok(body);
    }

    private void PublishAll(string release)
    {
        foreach (var edition in new[] { "asn", "country", "city" }) Publish(edition, release);
    }

    private void InstallAll(string release)
    {
        Directory.CreateDirectory(_dir);
        foreach (var edition in new[] { "asn", "country", "city" })
        {
            File.WriteAllBytes(Path.Combine(_dir, $"dbip-{edition}-lite-{release}.mmdb"), ValidDatabase(edition));
        }
    }

    private string[] Files() => Directory.Exists(_dir)
        ? Directory.GetFiles(_dir, "*.mmdb").Select(f => Path.GetFileName(f)).OrderBy(n => n, StringComparer.Ordinal).ToArray()
        : Array.Empty<string>();

    private static HttpResponseMessage Ok(byte[] body) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    // Records every request and answers from Routes; anything else is a 404,
    // which is how DB-IP answers for a month it has not published.
    private sealed class FakeDbIp : HttpMessageHandler
    {
        public Dictionary<string, Func<HttpResponseMessage>> Routes { get; } = new(StringComparer.Ordinal);

        public List<string> Requests { get; } = new();

        public Func<Task>? BeforeAnswer { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            lock (Requests) Requests.Add(url);
            if (BeforeAnswer is not null) await BeforeAnswer();
            return Routes.TryGetValue(url, out var answer) ? answer() : new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    // A response body that never delivers a byte until the read is cancelled.
    private sealed class StallingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    // Progress<T> posts to the thread pool; this one reports in order.
    private sealed class SyncProgress : IProgress<double>
    {
        private readonly Action<double> _report;

        public SyncProgress(Action<double> report) => _report = report;

        public void Report(double value) => _report(value);
    }
}

/// <summary>
/// [#351] Builds MaxMind DB files for tests: a one-node IPv4 tree in which every
/// address resolves to the same record, with the database type in the
/// metadata. Just enough of the format for MaxMind.Db to open the file.
/// </summary>
internal static class TestMmdb
{
    public static Dictionary<string, object> AsnRecord(uint asn = 64500, string organization = "Example AS") => new()
    {
        ["autonomous_system_number"] = asn,
        ["autonomous_system_organization"] = organization,
    };

    public static Dictionary<string, object> CountryRecord(string isoCode = "US") => new()
    {
        ["country"] = new Dictionary<string, object> { ["iso_code"] = isoCode },
    };

    public static Dictionary<string, object> CityRecord(double latitude = 37.422, double longitude = -122.085, string isoCode = "US") => new()
    {
        ["country"] = new Dictionary<string, object> { ["iso_code"] = isoCode },
        ["location"] = new Dictionary<string, object> { ["latitude"] = latitude, ["longitude"] = longitude },
    };

    public static byte[] Build(string databaseType, Dictionary<string, object> record)
    {
        var db = new List<byte>();

        // Search tree: node 0 with two 24-bit records, both pointing at data
        // offset 0 (a record above node_count means node_count + 16 + offset),
        // then the 16 zero bytes that separate it from the data section.
        db.AddRange(new byte[] { 0, 0, 17, 0, 0, 17 });
        db.AddRange(new byte[16]);
        Encode(db, record);

        // Metadata, after the marker the reader looks for from the end.
        db.AddRange(new byte[] { 0xAB, 0xCD, 0xEF });
        db.AddRange(Encoding.ASCII.GetBytes("MaxMind.com"));
        Encode(db, new Dictionary<string, object>
        {
            ["node_count"] = 1u,
            ["record_size"] = (ushort)24,
            ["ip_version"] = (ushort)4,
            ["database_type"] = databaseType,
            ["languages"] = new object[] { "en" },
            ["binary_format_major_version"] = (ushort)2,
            ["binary_format_minor_version"] = (ushort)0,
            ["build_epoch"] = 1_793_000_000UL,
            ["description"] = new Dictionary<string, object> { ["en"] = "test" },
        });
        return db.ToArray();
    }

    public static byte[] Gzip(byte[] bytes)
    {
        using var packed = new MemoryStream();
        using (var gzip = new GZipStream(packed, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(bytes);
        }

        return packed.ToArray();
    }

    private static void Encode(List<byte> db, object value)
    {
        switch (value)
        {
            case string text:
                var utf8 = Encoding.UTF8.GetBytes(text);
                Control(db, 2, utf8.Length);
                db.AddRange(utf8);
                break;
            case double number:
                Control(db, 3, 8);
                var raw = BitConverter.GetBytes(number);
                if (BitConverter.IsLittleEndian) Array.Reverse(raw);
                db.AddRange(raw);
                break;
            case ushort u16:
                Unsigned(db, 5, u16);
                break;
            case uint u32:
                Unsigned(db, 6, u32);
                break;
            case ulong u64:
                Unsigned(db, 9, u64);
                break;
            case Dictionary<string, object> map:
                Control(db, 7, map.Count);
                foreach (var (key, item) in map)
                {
                    Encode(db, key);
                    Encode(db, item);
                }

                break;
            case object[] array:
                Control(db, 11, array.Length);
                foreach (var item in array) Encode(db, item);
                break;
            default:
                throw new ArgumentException($"TestMmdb cannot encode {value.GetType().Name}", nameof(value));
        }
    }

    // Big-endian without leading zero bytes; type 5 is uint16, 6 is uint32
    // and 9 is uint64.
    private static void Unsigned(List<byte> db, int type, ulong value)
    {
        var bytes = new List<byte>();
        for (var v = value; v != 0; v >>= 8) bytes.Insert(0, (byte)v);
        Control(db, type, bytes.Count);
        db.AddRange(bytes);
    }

    // Control byte: the type in the top three bits (an extended type, 8 and
    // up, goes in the next byte as type - 7) and the size in the low five,
    // where 29 means 29 plus the byte after the type. Sizes here stay below 285.
    private static void Control(List<byte> db, int type, int size)
    {
        if (size >= 285) throw new ArgumentOutOfRangeException(nameof(size), "TestMmdb keeps every value below 285 bytes");
        db.Add((byte)((type <= 7 ? type << 5 : 0) | Math.Min(size, 29)));
        if (type > 7) db.Add((byte)(type - 7));
        if (size >= 29) db.Add((byte)(size - 29));
    }
}

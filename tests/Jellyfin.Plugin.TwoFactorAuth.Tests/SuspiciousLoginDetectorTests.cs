using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#258] SuspiciousLoginEnabled stops the detector without clearing the ASN
// and Country database paths. The detector gets a real (tiny) ASN database
// here, so an enabled one does record the sign-in's context, and it is the
// setting that stops it rather than a missing database.
public sealed class SuspiciousLoginDetectorTests : IDisposable
{
    private const string Address = "203.0.113.7";

    private readonly string _sandbox;
    private readonly UserTwoFactorStore _store;
    private GeoIpService? _geo;

    public SuspiciousLoginDetectorTests()
    {
        _store = new UserTwoFactorStore(TestApplicationPaths.Create(out _sandbox), Substitute.For<IServiceProvider>());
    }

    public void Dispose()
    {
        _geo?.Dispose();
        Directory.Delete(_sandbox, recursive: true);
    }

    // onGeoRead runs each time GeoIpService reads the configuration, which it
    // does on every availability check and lookup before touching a database.
    private SuspiciousLoginDetector Build(PluginConfiguration cfg, Action? onGeoRead = null)
    {
        _geo = new GeoIpService(NullLogger<GeoIpService>.Instance, () =>
        {
            onGeoRead?.Invoke();
            return cfg;
        });
        return new SuspiciousLoginDetector(
            _store,
            _geo,
            new NotificationService(NullLogger<NotificationService>.Instance),
            NullLogger<SuspiciousLoginDetector>.Instance,
            () => cfg);
    }

    [Fact]
    public async Task An_enabled_detector_records_the_context_and_flags_only_the_first_sign_in()
    {
        var detector = Build(new PluginConfiguration { GeoIpAsnDbPath = WriteAsnDatabase(64500, "Example AS") });
        var user = Guid.NewGuid();

        Assert.True(await detector.ObserveAsync(user, "alice", Address));
        Assert.False(await detector.ObserveAsync(user, "alice", Address));

        var seen = Assert.Single((await _store.GetUserDataAsync(user)).SeenContexts);
        Assert.Equal(64500u, seen.Asn);
        Assert.Equal(2L, seen.RequestCount);
    }

    [Fact]
    public async Task A_disabled_detector_records_nothing_with_the_database_still_configured()
    {
        var detector = Build(new PluginConfiguration
        {
            GeoIpAsnDbPath = WriteAsnDatabase(64500, "Example AS"),
            SuspiciousLoginEnabled = false,
        });
        var user = Guid.NewGuid();

        Assert.False(await detector.ObserveAsync(user, "alice", Address));
        Assert.Empty((await _store.GetUserDataAsync(user)).SeenContexts);
    }

    [Fact]
    public async Task A_disabled_detector_does_not_touch_the_databases()
    {
        // The switch is checked before the databases, so a server that turned
        // the detector off does not load them on its behalf.
        var cfg = new PluginConfiguration
        {
            GeoIpAsnDbPath = WriteAsnDatabase(64500, "Example AS"),
            SuspiciousLoginEnabled = false,
        };
        var geoReads = 0;
        var detector = Build(cfg, () => geoReads++);

        Assert.False(await detector.ObserveAsync(Guid.NewGuid(), "alice", Address));
        Assert.Equal(0, geoReads);

        // Control: the same detector, switched on, does reach the databases.
        cfg.SuspiciousLoginEnabled = true;
        Assert.True(await detector.ObserveAsync(Guid.NewGuid(), "alice", Address));
        Assert.True(geoReads > 0);
    }

    [Fact]
    public void A_configuration_saved_before_the_settings_existed_keeps_the_detector_on()
    {
        // An existing install's XML has neither element, and the serializer
        // leaves a missing element at the property's initial value.
        const string xml = "<PluginConfiguration><GeoIpAsnDbPath>/config/geoip/GeoLite2-ASN.mmdb</GeoIpAsnDbPath></PluginConfiguration>";
        var cfg = (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration)).Deserialize(new StringReader(xml))!;

        Assert.Equal("/config/geoip/GeoLite2-ASN.mmdb", cfg.GeoIpAsnDbPath);
        Assert.True(cfg.SuspiciousLoginEnabled);
        Assert.False(cfg.GeoProtectionHandledExternally);
    }

    // A one-node IPv4 MaxMind DB in which every address resolves to the same
    // ASN record: just enough of the format for GeoIpService to load it.
    private string WriteAsnDatabase(uint asn, string organization)
    {
        var db = new List<byte>();

        // Search tree: node 0 with two 24-bit records, both pointing at data
        // offset 0 (a record above node_count means node_count + 16 + offset),
        // then the 16 zero bytes that separate it from the data section.
        db.AddRange(new byte[] { 0, 0, 17, 0, 0, 17 });
        db.AddRange(new byte[16]);
        Map(db, 2);
        Text(db, "autonomous_system_number");
        Unsigned(db, 6, asn);
        Text(db, "autonomous_system_organization");
        Text(db, organization);

        // Metadata, after the marker the reader looks for.
        db.AddRange(new byte[] { 0xAB, 0xCD, 0xEF });
        db.AddRange(Encoding.ASCII.GetBytes("MaxMind.com"));
        Map(db, 9);
        Text(db, "node_count");
        Unsigned(db, 6, 1);
        Text(db, "record_size");
        Unsigned(db, 5, 24);
        Text(db, "ip_version");
        Unsigned(db, 5, 4);
        Text(db, "database_type");
        Text(db, "GeoLite2-ASN");
        Text(db, "languages");
        Control(db, 11, 1);
        Text(db, "en");
        Text(db, "binary_format_major_version");
        Unsigned(db, 5, 2);
        Text(db, "binary_format_minor_version");
        Unsigned(db, 5, 0);
        Text(db, "build_epoch");
        Unsigned(db, 9, 1_760_000_000);
        Text(db, "description");
        Map(db, 1);
        Text(db, "en");
        Text(db, "test");

        var path = Path.Combine(_sandbox, "GeoLite2-ASN.mmdb");
        File.WriteAllBytes(path, db.ToArray());
        return path;
    }

    // Control byte: the type in the top three bits (an extended type, 8 and
    // up, goes in the next byte as type - 7) and the size in the low five,
    // where 29 means 29 plus the byte after the type. Sizes here stay below 285.
    private static void Control(List<byte> db, int type, int size)
    {
        db.Add((byte)((type <= 7 ? type << 5 : 0) | Math.Min(size, 29)));
        if (type > 7) db.Add((byte)(type - 7));
        if (size >= 29) db.Add((byte)(size - 29));
    }

    private static void Map(List<byte> db, int pairs) => Control(db, 7, pairs);

    private static void Text(List<byte> db, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Control(db, 2, bytes.Length);
        db.AddRange(bytes);
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
}

using System;
using System.IO;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#216] A TV cannot render the challenge page, so a sign-in that someone
// approved on a second screen is the only way in, and forgetting the device
// afterwards means doing the whole dance again next time. These pin what is
// remembered, what is refused, and that a browser sign-in is not swept up
// with the TVs.
public class SecondScreenPairingDecisionTests
{
    private static PairedDevice Paired(string deviceId) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        DeviceId = deviceId,
        DeviceName = "Living room TV",
    };

    [Fact]
    public void Nothing_is_paired_while_the_setting_is_off()
    {
        Assert.False(SecondScreenPairing.ShouldPair(false, "lg-tv-1", Array.Empty<PairedDevice>()));
        Assert.True(SecondScreenPairing.ShouldPair(true, "lg-tv-1", Array.Empty<PairedDevice>()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_client_that_sends_no_device_id_cannot_be_paired(string? deviceId)
    {
        // There would be nothing to match on later, so the row would be a
        // permanent entry in the user's settings that never applies.
        Assert.False(SecondScreenPairing.ShouldPair(true, deviceId, Array.Empty<PairedDevice>()));
    }

    [Fact]
    public void An_absurdly_long_device_id_is_refused_rather_than_stored()
    {
        // Client-supplied and unbounded, and the file it lands in is read on
        // every auth request.
        Assert.False(SecondScreenPairing.ShouldPair(true, new string('a', 257), Array.Empty<PairedDevice>()));
        Assert.True(SecondScreenPairing.ShouldPair(true, new string('a', 256), Array.Empty<PairedDevice>()));
    }

    [Fact]
    public void A_device_that_is_already_paired_does_not_get_a_second_row()
    {
        var existing = new[] { Paired("lg-tv-1") };
        Assert.False(SecondScreenPairing.ShouldPair(true, "lg-tv-1", existing));
    }

    [Fact]
    public void A_web_client_device_id_matches_across_app_restarts()
    {
        // Jellyfin Web on Tizen/webOS appends "|<session timestamp>", so a
        // literal comparison would add a row every time the app restarts.
        var existing = new[] { Paired("QmFzZTY0VUFIYXNoT2ZUaGVUVg|1757980000000") };
        Assert.False(SecondScreenPairing.ShouldPair(true, "QmFzZTY0VUFIYXNoT2ZUaGVUVg|1758066400000", existing));
    }

    [Fact]
    public void The_record_carries_the_approval_it_came_from_and_trims_client_text()
    {
        var now = new DateTime(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);
        var record = SecondScreenPairing.BuildRecord(
            "lg-tv-1",
            new string('n', 200),
            "  Jellyfin Web  ",
            "192.0.2.10",
            SecondScreenPairing.SourceOidc,
            now);

        Assert.Equal("lg-tv-1", record.DeviceId);
        Assert.Equal(80, record.DeviceName.Length);
        Assert.Equal("Jellyfin Web", record.AppName);
        Assert.Equal("oidc", record.Source);
        Assert.Equal("192.0.2.10", record.LastIp);
        Assert.Equal(now, record.CreatedAt);
        Assert.Equal(now, record.LastUsedAt);
        // Indefinite trust stays a deliberate choice, made later and only
        // where the admin allowed it.
        Assert.False(record.IndefiniteTrust);
    }

    [Fact]
    public void A_device_with_no_name_still_gets_a_readable_row()
    {
        var record = SecondScreenPairing.BuildRecord(
            "lg-tv-1", null, null, null, SecondScreenPairing.SourceQuickConnect, DateTime.UtcNow);

        Assert.Equal("Unknown device", record.DeviceName);
        Assert.Equal(string.Empty, record.AppName);
        Assert.Equal(string.Empty, record.LastIp);
    }
}

public class SecondScreenPairingStoreTests
{
    private static UserTwoFactorStore NewStore()
        => new(TestApplicationPaths.Create(), Substitute.For<IServiceProvider>());

    private static ILogger Logger() => Substitute.For<ILogger<UserTwoFactorStore>>();

    [Fact]
    public async Task An_approved_device_is_remembered_and_audited()
    {
        using var store = NewStore();
        var cfg = new PluginConfiguration { PairDeviceOnSecondScreenApproval = true };
        var userId = Guid.NewGuid();

        var added = await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.10", SecondScreenPairing.SourceOidc, Logger());

        Assert.True(added);

        var data = await store.GetUserDataAsync(userId);
        var paired = Assert.Single(data.PairedDevices);
        Assert.Equal("lg-tv-1", paired.DeviceId);
        Assert.Equal("Living room TV", paired.DeviceName);
        Assert.Equal("oidc", paired.Source);

        var audit = await store.GetAuditLogAsync();
        Assert.Contains(audit, e => e.Method == "device_paired_oidc"
            && e.UserId == userId
            && e.Result == AuditResult.ConfigChanged);
    }

    [Fact]
    public async Task Signing_in_again_does_not_add_a_second_row()
    {
        using var store = NewStore();
        var cfg = new PluginConfiguration { PairDeviceOnSecondScreenApproval = true };
        var userId = Guid.NewGuid();

        Assert.True(await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.10", SecondScreenPairing.SourceOidc, Logger()));
        Assert.False(await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.11", SecondScreenPairing.SourceOidc, Logger()));

        var data = await store.GetUserDataAsync(userId);
        Assert.Single(data.PairedDevices);

        var audit = await store.GetAuditLogAsync();
        Assert.Single(audit, e => e.Method == "device_paired_oidc");
    }

    [Fact]
    public async Task Signing_in_again_moves_the_row_forward_instead_of_leaving_it_stale()
    {
        using var store = NewStore();
        var cfg = new PluginConfiguration { PairDeviceOnSecondScreenApproval = true };
        var userId = Guid.NewGuid();
        var first = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var second = new DateTime(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);

        await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.10", SecondScreenPairing.SourceOidc, Logger(), first);
        await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.11", SecondScreenPairing.SourceOidc, Logger(), second);

        // The user decides what to revoke from this list, so a device that
        // signed in today must not read as last used in January.
        var paired = Assert.Single((await store.GetUserDataAsync(userId)).PairedDevices);
        Assert.Equal(first, paired.CreatedAt);
        Assert.Equal(second, paired.LastUsedAt);
        Assert.Equal("192.0.2.11", paired.LastIp);
    }

    [Fact]
    public async Task With_the_setting_off_the_sign_in_leaves_no_trace()
    {
        using var store = NewStore();
        var cfg = new PluginConfiguration();
        var userId = Guid.NewGuid();

        Assert.False(cfg.PairDeviceOnSecondScreenApproval);
        Assert.False(await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.10", SecondScreenPairing.SourceOidc, Logger()));
        Assert.False(await SecondScreenPairing.RecordAsync(
            store, null, userId, "alice", "lg-tv-1", "Living room TV", "Jellyfin Web",
            "192.0.2.10", SecondScreenPairing.SourceOidc, Logger()));

        var data = await store.GetUserDataAsync(userId);
        Assert.Empty(data.PairedDevices);
        Assert.Empty(await store.GetAuditLogAsync());
    }

    [Fact]
    public async Task A_quickconnect_approval_is_recorded_under_its_own_source()
    {
        using var store = NewStore();
        var cfg = new PluginConfiguration { PairDeviceOnSecondScreenApproval = true };
        var userId = Guid.NewGuid();

        Assert.True(await SecondScreenPairing.RecordAsync(
            store, cfg, userId, "alice", "tizen-tv-2", "Bedroom TV", "Jellyfin Web",
            "192.0.2.20", SecondScreenPairing.SourceQuickConnect, Logger()));

        var data = await store.GetUserDataAsync(userId);
        Assert.Equal("quickconnect", Assert.Single(data.PairedDevices).Source);
        Assert.Contains(await store.GetAuditLogAsync(), e => e.Method == "device_paired_quickconnect");
    }
}

public class OidcBridgeTokenProvenanceTests
{
    // Only the poll side of the device flow describes a device someone
    // approved on another screen. A browser that completes its own callback
    // is an ordinary desktop sign-in and must not be paired.
    [Fact]
    public void A_token_picked_up_by_a_polling_client_is_marked_as_device_flow()
    {
        using var store = new OidcLoginTokenStore();
        var userId = Guid.NewGuid();
        var pollToken = store.BeginDeviceFlow("state-1");
        var bridgeToken = store.Mint(userId, "alice", "authentik");

        Assert.True(store.CompleteDeviceFlow("state-1", "alice", bridgeToken));
        var picked = store.PollDeviceFlow(pollToken);
        Assert.NotNull(picked);
        Assert.Equal(bridgeToken, picked!.Value.BridgeToken);

        var consumed = store.Consume(bridgeToken, "alice");
        Assert.NotNull(consumed);
        Assert.True(consumed!.Value.ViaDeviceFlow);
    }

    [Fact]
    public void A_browser_callback_token_is_not_marked()
    {
        using var store = new OidcLoginTokenStore();
        var bridgeToken = store.Mint(Guid.NewGuid(), "alice", "authentik");

        var consumed = store.Consume(bridgeToken, "alice");
        Assert.NotNull(consumed);
        Assert.False(consumed!.Value.ViaDeviceFlow);
    }

    [Fact]
    public void Marking_cannot_resurrect_a_token_that_was_already_redeemed()
    {
        // The poll is one-shot and so is Consume, but they are driven by two
        // different clients and can race. Whoever redeems first wins.
        using var store = new OidcLoginTokenStore();
        var pollToken = store.BeginDeviceFlow("state-1");
        var bridgeToken = store.Mint(Guid.NewGuid(), "alice", "authentik");
        store.CompleteDeviceFlow("state-1", "alice", bridgeToken);

        Assert.NotNull(store.Consume(bridgeToken, "alice"));
        store.PollDeviceFlow(pollToken);

        Assert.False(store.IsKnownBridgeToken(bridgeToken));
        Assert.Null(store.Consume(bridgeToken, "alice"));
    }
}

public class SecondScreenPairingWiringTests
{
    // The detectors in #215 sat in the tree for four releases with no caller.
    // A pairing that is never written fails the same silent way, so the call
    // site itself is pinned here.
    private static string ReadSource(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = dir.Parent;
        }

        throw new FileNotFoundException("Could not locate " + relativePath + " above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void The_oidc_bridge_pairs_the_device_it_signed_in()
    {
        var source = ReadSource(Path.Combine(
            "src", "Jellyfin.Plugin.TwoFactorAuth", "Services", "TwoFactorAuthProvider.cs"));

        var guard = source.IndexOf("if (consumed.Value.ViaDeviceFlow)", StringComparison.Ordinal);
        Assert.True(guard > 0, "the bridge path must decide on the device-flow flag");

        var call = source.IndexOf("SecondScreenPairing.RecordAsync", StringComparison.Ordinal);
        Assert.True(call > guard, "the pairing call must sit inside the device-flow guard");
        Assert.Contains("SecondScreenPairing.SourceOidc", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Quickconnect_pairs_the_device_the_session_belongs_to()
    {
        var source = ReadSource(Path.Combine(
            "src", "Jellyfin.Plugin.TwoFactorAuth", "Services", "AuthenticationEventHandler.cs"));

        // The pairing has to happen where the TV's own DeviceId is known: the
        // session that consumed the one-shot. At /QuickConnect/Authorize the
        // caller is the phone doing the approving, so pairing there would
        // remember the wrong device.
        var consume = source.IndexOf("ConsumeQuickConnectPending(info.UserId)", StringComparison.Ordinal);
        Assert.True(consume > 0, "the QuickConnect one-shot must still be consumed here");

        var call = source.IndexOf("SecondScreenPairing.RecordAsync", StringComparison.Ordinal);
        Assert.True(call > consume, "the pairing call must follow the QuickConnect consume");
        Assert.Contains("SecondScreenPairing.SourceQuickConnect", source, StringComparison.Ordinal);
        Assert.Contains("info.DeviceId", source.Substring(call, 600), StringComparison.Ordinal);
    }
}

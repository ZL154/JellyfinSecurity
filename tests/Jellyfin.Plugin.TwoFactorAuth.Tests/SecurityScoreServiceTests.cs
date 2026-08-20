using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class SecurityScoreDtosTests
{
    [Fact]
    public void ScoreFactor_DefaultsAreSane()
    {
        var f = new ScoreFactor { Id = "x", Label = "x", Earned = 0, Possible = 0, Status = "fail", NextAction = null };
        Assert.Equal("x", f.Id);
        Assert.Null(f.NextAction);
    }

    [Fact]
    public void SecurityScore_GradeIsAssignable()
    {
        var s = new SecurityScore
        {
            Total = 92,
            Possible = 100,
            Grade = "A",
            Factors = new List<ScoreFactor>(),
            ComputedAt = DateTime.UtcNow
        };
        Assert.Equal("A", s.Grade);
        Assert.Equal(92, s.Total);
    }
}

public class DiagnosticsServiceChainHelperTests
{
    [Fact]
    public void VerifyAuditChainPublic_ReturnsZeroForEmpty()
    {
        var n = Jellyfin.Plugin.TwoFactorAuth.Services.DiagnosticsService.VerifyAuditChainPublic(System.Array.Empty<Jellyfin.Plugin.TwoFactorAuth.Models.AuditEntry>());
        Assert.Equal(0, n);
    }

    [Fact]
    public void VerifyAuditChainPublic_AcceptsValidRetentionAnchor()
    {
        var first = Entry(previousHash: new string('A', 64), username: "first");
        var second = Entry(previousHash: first.EntryHash, username: "second");

        var broken = DiagnosticsService.VerifyAuditChainPublic(new[] { first, second });

        Assert.Equal(0, broken);
    }

    [Fact]
    public void VerifyAuditChainPublic_RejectsMalformedRetentionAnchor()
    {
        var entry = Entry(previousHash: "not-a-sha256", username: "first");

        var broken = DiagnosticsService.VerifyAuditChainPublic(new[] { entry });

        Assert.Equal(1, broken);
    }

    [Fact]
    public void VerifyAuditChainPublic_DetectsAlteredRetainedEntry()
    {
        var first = Entry(previousHash: new string('B', 64), username: "first");
        var second = Entry(previousHash: first.EntryHash, username: "second");
        first.Username = "tampered";

        var broken = DiagnosticsService.VerifyAuditChainPublic(new[] { first, second });

        Assert.Equal(1, broken);
    }

    private static AuditEntry Entry(string previousHash, string username)
    {
        var entry = new AuditEntry
        {
            PreviousHash = previousHash,
            Timestamp = new DateTime(2026, 7, 24, 0, 0, 0, DateTimeKind.Utc),
            UserId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Username = username,
            RemoteIp = "192.0.2.1",
            DeviceId = "device",
            DeviceName = "test",
            Result = AuditResult.Success,
            Method = "totp",
            Details = "fixture",
        };
        entry.EntryHash = UserTwoFactorStore.ComputeAuditEntryHash(entry);
        return entry;
    }
}

public class SecurityScoreComputeTests
{
    private static SecurityScoreService Build(out UserTwoFactorStore store, out PluginConfiguration cfg)
    {
        var paths = TestApplicationPaths.Create();
        store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        cfg = new PluginConfiguration();
        var stats = Substitute.For<StatsService>(store, Substitute.For<IUserManager>());
        var logger = Substitute.For<ILogger<SecurityScoreService>>();
        var localCfg = cfg;
        return new SecurityScoreService(store, stats, paths, logger, () => localCfg);
    }

    [Fact]
    public async Task Compute_AllOff_LowScore()
    {
        var svc = Build(out _, out var cfg);
        cfg.EnforcementScope = EnforcementScope.Optional;
        cfg.IpBanEnabled = false;
        cfg.ImpossibleTravelEnabled = false;
        cfg.HibpEnabled = false;
        var score = await svc.ComputeAsync();
        // v2.5.0: 12 factors, normalized to 100 ceiling. Vacuous-truth
        // baseline: admins(20, no admins exist) + audit-chain(10, empty log)
        // + clean-7d(5, empty log) = 35 raw of 130 possible -> ~27 after
        // scaling. All toggle factors off; the four new hardening factors
        // also score zero.
        Assert.InRange(score.Total, 20, 35);
        Assert.Equal("F", score.Grade);
        Assert.Equal(12, score.Factors.Count);
    }

    [Fact]
    public async Task Compute_AllFlagsOn_HighScoreCeiling()
    {
        var svc = Build(out _, out var cfg);
        cfg.EnforcementScope = EnforcementScope.All;
        cfg.IpBanEnabled = true;
        cfg.ImpossibleTravelEnabled = true;
        // v2.5.0: travel now requires the city-DB path; supply a sentinel
        // so the factor scores full credit alongside the other toggles.
        cfg.GeoIpCityDbPath = "/tmp/GeoLite2-City.mmdb";
        cfg.HibpEnabled = true;
        cfg.RequireTwoFactorToDisable = true;
        cfg.StepUpLevel = StepUpLevel.Everything;
        cfg.WebhookUrl = "https://example.invalid/hook";
        var score = await svc.ComputeAsync();
        // No users enrolled — coverage(0) and recovery-codes(0, since no
        // TOTP users to scale against). Everything else at full credit:
        // admins(20) + enforcement(15) + audit-chain(10) + ipban(8)
        // + travel(7) + hibp(5) + clean-7d(5) + require-to-disable(8)
        // + stepup(7) + webhook(5) = 90 raw of 130 -> ~69 after scaling.
        Assert.InRange(score.Total, 60, 75);
    }

    // -----------------------------------------------------------------
    // [v2.5.22] (#160, hax4dazy) password-sign-in-disabled credit.
    // -----------------------------------------------------------------

    [Fact]
    public async Task PasswordLoginFactor_IsAbsentWhenTheSwitchIsOff()
    {
        // The factor must not exist at all rather than score zero. A server
        // running password + 2FA is not insecure, and adding an 8-point factor
        // it can never earn would silently drop every such server's grade on
        // upgrade.
        var svc = Build(out _, out var cfg);
        cfg.DisablePasswordLogin = false;
        var score = await svc.ComputeAsync();

        Assert.DoesNotContain(score.Factors, f => f.Id == "password-login-disabled");
        Assert.Equal(12, score.Factors.Count);
    }

    [Fact]
    public async Task PasswordLoginFactor_GivesFullCreditWithNoEscapeHatches()
    {
        var svc = Build(out _, out var cfg);
        cfg.DisablePasswordLogin = true;
        cfg.AllowAdminPasswordLogin = false;
        cfg.AllowPasswordLoginOnLan = false;
        var score = await svc.ComputeAsync();

        var f = Assert.Single(score.Factors, x => x.Id == "password-login-disabled");
        Assert.Equal(8, f.Earned);
        Assert.Equal(8, f.Possible);
        Assert.Equal("ok", f.Status);
        Assert.Null(f.NextAction);
    }

    [Fact]
    public async Task PasswordLoginFactor_IsDockedForEachOpenEscapeHatch()
    {
        // An admin or LAN exemption means password compromise is still in the
        // threat model for those clients, so full credit would overstate it.
        var svc = Build(out _, out var cfg);
        cfg.DisablePasswordLogin = true;
        cfg.AllowAdminPasswordLogin = true;
        cfg.AllowPasswordLoginOnLan = true;
        var score = await svc.ComputeAsync();

        var f = Assert.Single(score.Factors, x => x.Id == "password-login-disabled");
        Assert.Equal(4, f.Earned);
        Assert.Equal("partial", f.Status);
        Assert.NotNull(f.NextAction);
        Assert.Contains("administrators", f.NextAction!, StringComparison.Ordinal);
        Assert.Contains("LAN clients", f.NextAction!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PasswordLoginFactor_RaisesTheScoreRatherThanLoweringIt()
    {
        // The whole point of #160: turning the switch on must move the grade UP.
        var off = Build(out _, out var cfgOff);
        cfgOff.DisablePasswordLogin = false;
        var scoreOff = (await off.ComputeAsync()).Total;

        var on = Build(out _, out var cfgOn);
        cfgOn.DisablePasswordLogin = true;
        cfgOn.AllowAdminPasswordLogin = false;
        cfgOn.AllowPasswordLoginOnLan = false;
        var scoreOn = (await on.ComputeAsync()).Total;

        Assert.True(scoreOn > scoreOff, $"expected {scoreOn} > {scoreOff}");
    }

    [Theory]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(85, "B+")]
    [InlineData(75, "B")]
    [InlineData(65, "C")]
    [InlineData(55, "D")]
    [InlineData(49, "F")]
    [InlineData(0, "F")]
    public void GradeFromTotal_MatchesThresholds(int total, string expected)
    {
        Assert.Equal(expected, SecurityScoreService.GradeFromTotal(total));
    }
}

public class SecurityScoreSnapshotTests : IDisposable
{
    private readonly string _tempPath;
    private readonly IApplicationPaths _paths;

    public SecurityScoreSnapshotTests()
    {
        _paths = TestApplicationPaths.Create();
        _tempPath = _paths.PluginConfigurationsPath;
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempPath, true); } catch { /* best-effort cleanup */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task TakeSnapshot_AppendsTodayEntry()
    {
        var svc = SecurityScoreServiceTests_TestHarness.Build(_paths, out var cfg);
        cfg.EnforcementScope = EnforcementScope.All;
        await svc.TakeSnapshotAsync();
        var hist = await svc.GetHistoryAsync(30);
        Assert.Single(hist);
        Assert.Equal(DateTime.UtcNow.ToString("yyyy-MM-dd"), hist[0].Date);
    }

    [Fact]
    public async Task TakeSnapshot_IsIdempotentForSameDay()
    {
        var svc = SecurityScoreServiceTests_TestHarness.Build(_paths, out _);
        await svc.TakeSnapshotAsync();
        await svc.TakeSnapshotAsync();
        await svc.TakeSnapshotAsync();
        var hist = await svc.GetHistoryAsync(30);
        Assert.Single(hist); // dedupe by UTC date
    }

    [Fact]
    public async Task History_CapsAt365Entries()
    {
        var svc = SecurityScoreServiceTests_TestHarness.Build(_paths, out _);
        for (int i = 0; i < 400; i++)
        {
            await svc.AppendForTestAsync(DateTime.UtcNow.AddDays(-i).ToString("yyyy-MM-dd"), 50);
        }
        var hist = await svc.GetHistoryAsync(1000);
        Assert.Equal(365, hist.Count);
    }
}

internal static class SecurityScoreServiceTests_TestHarness
{
    public static SecurityScoreService Build(IApplicationPaths paths, out PluginConfiguration cfg)
    {
        var store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        cfg = new PluginConfiguration();
        var stats = Substitute.For<StatsService>(store, Substitute.For<IUserManager>());
        var logger = Substitute.For<ILogger<SecurityScoreService>>();
        var localCfg = cfg;
        return new SecurityScoreService(store, stats, paths, logger, () => localCfg);
    }
}

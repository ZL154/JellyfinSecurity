using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
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
}

public class SecurityScoreComputeTests
{
    private static SecurityScoreService Build(out UserTwoFactorStore store, out PluginConfiguration cfg)
    {
        var paths = TestApplicationPaths.Create();
        store = new UserTwoFactorStore(paths);
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
        // Empty store + NSubstitute stub on EnumerateUsersPublic yields the
        // vacuous-truth baseline: admins(20, no admins exist) + audit-chain(10,
        // empty log) + clean-7d(5, empty log) = 35. All toggle factors off.
        Assert.InRange(score.Total, 30, 40);
        Assert.Equal("F", score.Grade);
        Assert.Equal(8, score.Factors.Count);
    }

    [Fact]
    public async Task Compute_AllFlagsOn_HighScoreCeiling()
    {
        var svc = Build(out _, out var cfg);
        cfg.EnforcementScope = EnforcementScope.All;
        cfg.IpBanEnabled = true;
        cfg.ImpossibleTravelEnabled = true;
        cfg.HibpEnabled = true;
        var score = await svc.ComputeAsync();
        // No users enrolled, all toggle factors at full + vacuous admins/audit/clean:
        // admins(20) + enforcement(15) + audit-chain(10) + ipban(8) + travel(7)
        // + hibp(5) + clean-7d(5) = 70 (coverage=0 since no users).
        Assert.InRange(score.Total, 65, 75);
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

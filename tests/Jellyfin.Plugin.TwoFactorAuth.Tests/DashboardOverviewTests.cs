using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class DashboardOverviewPayloadTests
{
    [Fact]
    public void DashboardOverview_Shape_ContainsExpectedSections()
    {
        // Pure shape smoke test — verifies the DTO surface compiles.
        var resp = new
        {
            Score = new SecurityScore { Total = 80, Possible = 100, Grade = "B+", Factors = new() },
            Kpis = new { EnrolledUsers = 1, TotalUsers = 5, ActiveSessions = 3, BannedIps = 0, AuditEntries = 100, AuditChainBroken = 0 },
            History = new List<ScoreSnapshot>(),
            EnrollmentByRole = new { AdminsEnrolled = 1, AdminsTotal = 1, UsersEnrolled = 0, UsersTotal = 4 },
            Bans = new List<IpBanEntry>()
        };
        Assert.NotNull(resp.Score);
        Assert.NotNull(resp.Kpis);
    }
}

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
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

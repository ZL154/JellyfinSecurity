using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// [#270/#216] One-time device codes are app passwords with an expiry. FindMatch
/// must never return an entry whose ExpiresAt has passed, however correct the
/// password — the single-use removal happens at the call site, but an expired
/// code must be dead on arrival regardless.
/// </summary>
public class AppPasswordExpiryTests
{
    private static AppPassword Entry(AppPasswordService svc, out string plaintext, DateTime? expiresAt, bool oneTime)
    {
        var (pt, hash) = svc.Generate();
        plaintext = pt;
        return new AppPassword
        {
            Id = Guid.NewGuid().ToString("N"),
            Label = "test",
            PasswordHash = hash,
            CreatedAt = DateTime.UtcNow,
            OneTime = oneTime,
            ExpiresAt = expiresAt,
        };
    }

    [Fact]
    public void A_non_expiring_password_still_matches()
    {
        var svc = new AppPasswordService();
        var e = Entry(svc, out var pt, expiresAt: null, oneTime: false);
        Assert.Same(e, svc.FindMatch(pt, new[] { e }));
    }

    [Fact]
    public void A_live_one_time_code_matches()
    {
        var svc = new AppPasswordService();
        var e = Entry(svc, out var pt, expiresAt: DateTime.UtcNow.AddMinutes(10), oneTime: true);
        Assert.Same(e, svc.FindMatch(pt, new[] { e }));
    }

    [Fact]
    public void An_expired_code_never_matches_even_with_the_right_password()
    {
        var svc = new AppPasswordService();
        var e = Entry(svc, out var pt, expiresAt: DateTime.UtcNow.AddSeconds(-1), oneTime: true);
        Assert.Null(svc.FindMatch(pt, new[] { e }));
    }

    [Fact]
    public void A_live_entry_is_matched_even_when_an_expired_one_is_present()
    {
        var svc = new AppPasswordService();
        var expired = Entry(svc, out var expiredPt, expiresAt: DateTime.UtcNow.AddSeconds(-1), oneTime: true);
        var live = Entry(svc, out var livePt, expiresAt: null, oneTime: false);
        var all = new List<AppPassword> { expired, live };
        Assert.Null(svc.FindMatch(expiredPt, all));
        Assert.Same(live, svc.FindMatch(livePt, all));
    }
}

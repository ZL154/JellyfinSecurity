using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// [v2.5.22] (#160, hax4dazy) The security score should credit a server that has
/// turned password sign-in off entirely.
///
/// Two properties matter and are easy to get wrong:
///
/// 1. It must be ADDITIVE. A server running password + 2FA is not insecure, and
///    docking every such server 8 points would make the grade less accurate, not
///    more. So the factor is absent (not zero-scored) when the switch is off.
/// 2. It must be GRADED. An escape hatch left open means password compromise is
///    still in the threat model for those clients, so full credit would overstate
///    the posture.
///
/// The trust-cookie path test lives here too because it is the same class of bug
/// as the v2.5.22 bypass: a control keyed to only one of Jellyfin's two password
/// endpoints.
/// </summary>
public class PasswordLoginScoreFactorTests
{
    private const string SampleUserId = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

    // -----------------------------------------------------------------
    // TrustCookieMiddleware: same blind spot, verified closed.
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/Users/AuthenticateWithQuickConnect")]
    [InlineData("/TwoFactorAuth/Authenticate")]
    [InlineData("/QuickConnect/Authorize")]
    [InlineData("/Users/" + SampleUserId + "/Authenticate")]
    [InlineData("/jellyfin/Users/" + SampleUserId + "/Authenticate")]
    public void TrustCookie_TreatsEveryAuthEndpointAsAnAuthPath(string path)
    {
        // The last two are the ones that were missing. This failed closed (no
        // trust cookie issued) rather than open, so it was never a vulnerability
        // — but it is the same omission as the DisablePasswordLogin bypass and
        // is fixed alongside it so the answer to "does anything else key off the
        // wrong path set?" is a clean no.
        Assert.True(TrustCookieMiddleware.IsTrustAuthPath(path));
    }

    [Theory]
    [InlineData("/Items/Latest")]
    [InlineData("/Users/Public")]
    [InlineData("/Admin/Proxy/AuthenticateByName")]
    public void TrustCookie_LeavesUnrelatedPathsAlone(string path)
    {
        // /Admin/Proxy/... is the anchoring case the original regex was written
        // for; widening it must not have reintroduced a substring match.
        Assert.False(TrustCookieMiddleware.IsTrustAuthPath(path));
    }

    // -----------------------------------------------------------------
    // Grade thresholds are unchanged by adding a factor.
    // -----------------------------------------------------------------

    [Theory]
    [InlineData(100, "A")]
    [InlineData(90, "A")]
    [InlineData(89, "B+")]
    [InlineData(70, "B")]
    [InlineData(49, "F")]
    public void GradeBoundaries_AreUnaffectedByTheNewFactor(int total, string expected)
    {
        Assert.Equal(expected, SecurityScoreService.GradeFromTotal(total));
    }
}

using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Issue #35: FsxShader2012 reported a 2FA-enabled user stuck on the login
/// spinner. v2.4.9's diagnostic build revealed the response body was 1969
/// bytes but contained NONE of "AccessToken" / "User" / "SessionInfo"
/// PascalCase markers — strongly suggesting a camelCase auth response from
/// either Jellyfin or a response-wrapping middleware in his pipeline.
///
/// These tests pin LooksLikeAuthResponse's case-insensitive matching so the
/// substring sniff matches whatever casing the IdP-or-middleware emits,
/// consistent with the downstream JsonSerializer.Deserialize which already
/// uses PropertyNameCaseInsensitive=true.
/// </summary>
public class LooksLikeAuthResponseTests
{
    [Fact]
    public void PascalCase_StockJellyfinResponse_Matches()
    {
        // The default System.Text.Json serialization for AuthenticationResult.
        var body = """{"User":{"Id":"abc"},"SessionInfo":{"Id":"def"},"AccessToken":"xyz"}""";
        Assert.True(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(body));
    }

    [Fact]
    public void CamelCase_RewrittenResponse_Matches()
    {
        // The shape v2.4.9 logs from issue #35 implied. Some response-wrapping
        // middleware (or a Jellyfin config with custom JSON options) rewrites
        // the auth result into camelCase. Without case-insensitive matching,
        // the user gets stuck on login because we silently fail to detect the
        // auth response and never inject the 2FA challenge.
        var body = """{"user":{"id":"abc"},"sessionInfo":{"id":"def"},"accessToken":"xyz"}""";
        Assert.True(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(body));
    }

    [Fact]
    public void MixedCase_Matches()
    {
        // Defensive: weird capitalization (e.g., "ACCESSTOKEN") shouldn't
        // block the auth flow either. Real-world JSON rarely looks like this
        // but our match shouldn't depend on the specific cap-style.
        var body = """{"USER":{"id":"abc"},"SESSIONINFO":{"id":"def"},"ACCESSTOKEN":"xyz"}""";
        Assert.True(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(body));
    }

    [Fact]
    public void MissingOneKey_DoesNotMatch()
    {
        // SEC v2.4 L6 contract: all three keys must be present, or we don't
        // touch the response. Without this, third-party plugin admin endpoints
        // returning JSON that mentions just AccessToken+User could get pulled
        // into the 2FA flow and silently mangled.
        var noSession = """{"User":{"Id":"abc"},"AccessToken":"xyz"}""";
        var noUser = """{"SessionInfo":{"Id":"def"},"AccessToken":"xyz"}""";
        var noToken = """{"User":{"Id":"abc"},"SessionInfo":{"Id":"def"}}""";

        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(noSession));
        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(noUser));
        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(noToken));
    }

    [Fact]
    public void EmptyOrOversizedBody_DoesNotMatch()
    {
        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(string.Empty));
        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(null!));
        // Oversized guard — 1MB+ bodies don't get sniffed at all (would
        // be unusual for an auth response and could be a memory-amplification
        // surface if we substring-scanned every JSON body).
        var huge = new string('A', 1_000_001);
        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(huge));
    }

    [Fact]
    public void HtmlOrNonJson_DoesNotMatch()
    {
        // An HTML error page or non-JSON content shouldn't accidentally trip
        // the auth-shaped detector. Realistically the upstream content-type
        // check filters HTML out first, but defence-in-depth.
        var html = "<html><body>500 internal server error</body></html>";
        Assert.False(TwoFactorEnforcementMiddleware.LooksLikeAuthResponse(html));
    }
}

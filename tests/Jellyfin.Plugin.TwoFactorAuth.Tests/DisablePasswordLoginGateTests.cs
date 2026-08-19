using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// [v2.5.22] Regression cover for two ways password sign-in survived
/// <c>DisablePasswordLogin</c>. The switch shipped in v2.5.11 (#69) with no
/// tests at all, which is how both of these lived through eleven releases.
///
/// 1. <see cref="LockoutMessageMiddleware"/> matched only
///    <c>/Users/AuthenticateByName</c>. Jellyfin also routes the obsolete
///    <c>POST /Users/{userId}/Authenticate?pw=…</c>, which carries no
///    [Authorize] and reaches the same authentication code as an in-process
///    method call, so nothing keyed off the HTTP path ever ran for it.
/// 2. The bridge-token waiver was a string-prefix test, so any password
///    beginning <c>oidcbr_</c> skipped the gate entirely.
///
/// Both are enforcement-shaped, so the tests are written to fail loudly if the
/// predicate is ever narrowed back.
/// </summary>
public class DisablePasswordLoginGateTests
{
    private const string SampleUserId = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

    // ---------------------------------------------------------------------
    // Bypass 1: which paths the gate is willing to police.
    // ---------------------------------------------------------------------

    [Fact]
    public void AuthenticateByName_IsMatched_WithNoRouteUser()
    {
        Assert.True(LockoutMessageMiddleware.TryMatchPasswordAuthPath(
            "/Users/AuthenticateByName", out var id));

        // The username lives in the JSON body on this endpoint, so there is no
        // route GUID to hand back — that is what tells the caller to peek the
        // body rather than the query string.
        Assert.Equal(Guid.Empty, id);
    }

    [Fact]
    public void ObsoleteByIdEndpoint_IsMatched_AndYieldsTheRouteUser()
    {
        // The bypass. Before v2.5.22 this returned false and every control in
        // the middleware was skipped for the request.
        Assert.True(LockoutMessageMiddleware.TryMatchPasswordAuthPath(
            "/Users/" + SampleUserId + "/Authenticate", out var id));
        Assert.Equal(Guid.Parse(SampleUserId), id);
    }

    [Fact]
    public void ObsoleteByIdEndpoint_IsMatched_BehindAConfiguredBaseUrl()
    {
        // Jellyfin 10.11.x leaves a configured BaseUrl in Request.Path rather
        // than PathBase, so an admin running the server under /jellyfin must
        // not silently lose the gate.
        Assert.True(LockoutMessageMiddleware.TryMatchPasswordAuthPath(
            "/jellyfin/Users/" + SampleUserId + "/Authenticate", out var id));
        Assert.Equal(Guid.Parse(SampleUserId), id);
    }

    [Fact]
    public void ObsoleteByIdEndpoint_IsMatched_InUndashedGuidForm()
    {
        // ASP.NET's :guid route constraint is Guid.TryParse, which takes the
        // 32-char "N" form too. Matching only the dashed form would leave the
        // bypass open to anyone who dropped the hyphens.
        var undashed = SampleUserId.Replace("-", string.Empty);
        Assert.True(LockoutMessageMiddleware.TryMatchPasswordAuthPath(
            "/Users/" + undashed + "/Authenticate", out var id));
        Assert.Equal(Guid.Parse(SampleUserId), id);
    }

    [Theory]
    [InlineData("/Users/AuthenticateByName/")]
    [InlineData("/USERS/AUTHENTICATEBYNAME")]
    public void AuthenticateByName_MatchIsTrailingSlashAndCaseTolerant(string path)
    {
        Assert.True(LockoutMessageMiddleware.TryMatchPasswordAuthPath(path, out _));
    }

    [Fact]
    public void QuickConnect_IsDeliberatelyNotMatched()
    {
        // Quick Connect is not password sign-in. DisablePasswordLogin is
        // documented as leaving "OIDC/SSO + Quick Connect" working, so pulling
        // this path into the gate would break the feature's stated contract.
        Assert.False(LockoutMessageMiddleware.TryMatchPasswordAuthPath(
            "/Users/AuthenticateWithQuickConnect", out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/Users/Public")]
    [InlineData("/Items/Latest")]
    [InlineData("/Users/" + SampleUserId)]
    [InlineData("/Users/" + SampleUserId + "/Authenticate/Extra")]
    [InlineData("/Users/not-a-guid/Authenticate")]
    public void UnrelatedPaths_AreLeftAlone(string? path)
    {
        // Anything that is not a password endpoint has to flow through
        // untouched — this middleware sits in front of the whole server.
        Assert.False(LockoutMessageMiddleware.TryMatchPasswordAuthPath(path, out var id));
        Assert.Equal(Guid.Empty, id);
    }

    // ---------------------------------------------------------------------
    // Bypass 2: the bridge-token waiver must be a lookup, not a prefix test.
    // ---------------------------------------------------------------------

    [Fact]
    public void ForgedPrefix_IsNotAcceptedAsABridgeToken()
    {
        // The bypass: a user sets their Jellyfin password to "oidcbr_hunter2"
        // and signs in normally despite the server-wide policy, with nothing in
        // the UI or the logs showing they had opted out.
        using var store = new OidcLoginTokenStore();

        Assert.True(OidcLoginTokenStore.LooksLikeBridgeToken("oidcbr_hunter2"));
        Assert.False(store.IsKnownBridgeToken("oidcbr_hunter2"));
    }

    [Fact]
    public void MintedToken_IsAcceptedSoSsoStillCompletes()
    {
        using var store = new OidcLoginTokenStore();
        var token = store.Mint(Guid.NewGuid(), "alice", "keycloak");

        Assert.True(store.IsKnownBridgeToken(token));
    }

    [Fact]
    public void TheCheckDoesNotConsume_SoTheProviderCanStillRedeemTheToken()
    {
        // The gate runs in the middleware, ahead of the auth provider that
        // legitimately consumes the token. If the check consumed, every single
        // SSO sign-in would break — which is exactly why Consume could not be
        // reused here and a separate non-consuming lookup was needed.
        using var store = new OidcLoginTokenStore();
        var userId = Guid.NewGuid();
        var token = store.Mint(userId, "alice", "keycloak");

        Assert.True(store.IsKnownBridgeToken(token));
        Assert.True(store.IsKnownBridgeToken(token));

        var consumed = store.Consume(token, "alice");
        Assert.NotNull(consumed);
        Assert.Equal(userId, consumed!.Value.UserId);
    }

    [Fact]
    public void AConsumedToken_IsNoLongerKnown()
    {
        // Single-use has to survive the new entry point: once redeemed, the
        // token must stop waiving the policy.
        using var store = new OidcLoginTokenStore();
        var token = store.Mint(Guid.NewGuid(), "alice", "keycloak");
        store.Consume(token, "alice");

        Assert.False(store.IsKnownBridgeToken(token));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("hunter2")]
    [InlineData("oidcbr")]
    [InlineData("OIDCBR_uppercase")]
    public void OrdinaryPasswords_NeverWaiveThePolicy(string? password)
    {
        using var store = new OidcLoginTokenStore();
        Assert.False(store.IsKnownBridgeToken(password));
    }
}

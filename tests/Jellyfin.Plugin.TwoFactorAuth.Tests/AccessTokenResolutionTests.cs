using Jellyfin.Plugin.TwoFactorAuth.Api;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// [v2.5.22] Server half of the Jellyfin 12 authorization-header change (#174).
///
/// That PR moved the plugin's own pages off the legacy <c>X-Emby-Token</c>
/// header onto <c>Authorization: MediaBrowser Token="..."</c>, which is
/// required once an operator disables legacy authorization on Jellyfin 12. Its
/// tests asserted only that the shipped HTML/JS had changed, so they stayed
/// green while three server endpoints still read the legacy header alone:
///
///   - SetPassword/Logout -> 400, killing the #134 onboarding logout button.
///   - Setup/QrPair/Begin -> lost its SEC-H4 ownership cross-check, which is
///     written to fail OPEN when no token is found.
///   - MySessions -> stopped marking the current session.
///
/// These pin the resolver both pages and endpoints now agree on, so the client
/// and server halves cannot drift apart again silently.
/// </summary>
public class AccessTokenResolutionTests
{
    private const string Token = "abc123def456";

    private static HttpRequest RequestWith(params (string Name, string Value)[] headers)
    {
        var ctx = new DefaultHttpContext();
        foreach (var (name, value) in headers)
        {
            ctx.Request.Headers[name] = value;
        }

        return ctx.Request;
    }

    [Fact]
    public void LegacyEmbyTokenHeader_StillWorks()
    {
        // Native clients and older jellyfin-web builds still send this, so the
        // widening must not become a swap.
        Assert.Equal(Token, TwoFactorAuthController.ResolveAccessToken(
            RequestWith(("X-Emby-Token", Token))));
    }

    [Fact]
    public void AuthorizationHeader_IsAccepted()
    {
        // The Jellyfin 12 shape, and what #174 made the plugin's pages send.
        // Before this change every endpoint below returned null here.
        Assert.Equal(Token, TwoFactorAuthController.ResolveAccessToken(
            RequestWith(("Authorization", $"MediaBrowser Token=\"{Token}\""))));
    }

    [Fact]
    public void XEmbyAuthorizationHeader_IsAccepted()
    {
        Assert.Equal(Token, TwoFactorAuthController.ResolveAccessToken(
            RequestWith(("X-Emby-Authorization", $"MediaBrowser Token=\"{Token}\""))));
    }

    [Fact]
    public void FullClientAuthorizationHeader_YieldsOnlyTheToken()
    {
        // The real header jellyfin-web sends carries four other fields; the
        // resolver must pick Token= and not, say, DeviceId=.
        var header = "MediaBrowser Client=\"Jellyfin Web\", Device=\"Firefox\", "
            + $"DeviceId=\"dev-999\", Version=\"10.11.11\", Token=\"{Token}\"";

        Assert.Equal(Token, TwoFactorAuthController.ResolveAccessToken(
            RequestWith(("Authorization", header))));
    }

    [Fact]
    public void LegacyHeaderWins_WhenBothArePresent()
    {
        // Not a preference so much as a guarantee of no behaviour change for
        // any client that still sends the legacy header.
        Assert.Equal(Token, TwoFactorAuthController.ResolveAccessToken(
            RequestWith(
                ("X-Emby-Token", Token),
                ("Authorization", "MediaBrowser Token=\"a-different-token\""))));
    }

    [Fact]
    public void UnauthenticatedClientMetadata_YieldsNoToken()
    {
        // X-Emby-Authorization is present on anonymous calls too, carrying
        // Client/Device/DeviceId/Version but no Token. Returning DeviceId here
        // would hand QrPairBegin a bogus value to compare against.
        Assert.Null(TwoFactorAuthController.ResolveAccessToken(
            RequestWith(("X-Emby-Authorization",
                "MediaBrowser Client=\"Jellyfin Web\", Device=\"Firefox\", DeviceId=\"dev-999\", Version=\"10.11.11\""))));
    }

    [Fact]
    public void NoHeadersAtAll_YieldsNull()
    {
        Assert.Null(TwoFactorAuthController.ResolveAccessToken(RequestWith()));
    }
}

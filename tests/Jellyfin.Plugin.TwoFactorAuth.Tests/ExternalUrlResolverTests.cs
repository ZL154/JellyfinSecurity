using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#216] A smart TV reaches Jellyfin directly on the LAN, so no forwarded
// header exists and the request-derived link points at a private address the
// IdP rejects. These pin the two halves of the answer: which declared value
// counts as "the outside world", and what shape a usable base URL has.
public class ExternalUrlResolverTests
{
    [Fact]
    public void Nothing_declared_means_no_public_base_and_the_caller_keeps_the_request()
    {
        Assert.Null(ExternalUrlResolver.PickPublished(null));
        Assert.Null(ExternalUrlResolver.PickPublished(Array.Empty<string>()));
        Assert.Null(ExternalUrlResolver.PickPublished(new[] { string.Empty, "   " }));
    }

    [Fact]
    public void Only_the_entries_that_mean_everyone_else_are_used()
    {
        // A subnet-specific URI is by definition not the address an IdP or a
        // phone on mobile data would use, so it must not be picked up.
        Assert.Null(ExternalUrlResolver.PickPublished(new[]
        {
            "192.168.1.0/24=http://192.168.1.10:8096",
            "internal=http://10.0.0.5:8096",
        }));

        Assert.Equal("https://jellyfin.example.com",
            ExternalUrlResolver.PickPublished(new[] { "all=https://jellyfin.example.com" }));
        Assert.Equal("https://jellyfin.example.com",
            ExternalUrlResolver.PickPublished(new[] { "external=https://jellyfin.example.com" }));
    }

    [Fact]
    public void External_wins_over_all_because_it_is_the_more_specific_statement()
    {
        var picked = ExternalUrlResolver.PickPublished(new[]
        {
            "internal=http://10.0.0.5:8096",
            "all=https://all.example.com",
            "external=https://outside.example.com",
        });

        Assert.Equal("https://outside.example.com", picked);
    }

    [Theory]
    [InlineData("https://jellyfin.example.com", "https://jellyfin.example.com")]
    [InlineData("https://jellyfin.example.com/", "https://jellyfin.example.com")]
    [InlineData("  https://jellyfin.example.com  ", "https://jellyfin.example.com")]
    [InlineData("http://jellyfin.example.com:8096", "http://jellyfin.example.com:8096")]
    [InlineData("https://example.com/jellyfin", "https://example.com/jellyfin")]
    [InlineData("https://example.com/jellyfin/", "https://example.com/jellyfin")]
    public void A_usable_base_keeps_scheme_host_port_and_path_without_a_trailing_slash(
        string configured, string expected)
    {
        Assert.Equal(expected, ExternalUrlResolver.Normalize(configured));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("jellyfin.example.com")]              // sem esquema
    [InlineData("ftp://jellyfin.example.com")]        // esquema errado
    [InlineData("file:///etc/passwd")]
    [InlineData("https://jellyfin.example.com?x=1")]  // query
    [InlineData("https://jellyfin.example.com#frag")] // fragmento
    [InlineData("https://user:pw@jellyfin.example.com")]
    public void Anything_that_would_produce_a_broken_link_is_refused_rather_than_trimmed(string? configured)
    {
        // Refusing sends the caller back to the request-derived behaviour,
        // which at least works on a directly reachable server. Silently
        // trimming would hand the IdP a URI the admin never wrote.
        Assert.Null(ExternalUrlResolver.Normalize(configured));
    }

    [Fact]
    public void The_declared_base_replaces_the_request_derivation_in_the_oidc_redirect()
    {
        // With a public base, neither the private Host nor the absence of
        // forwarded headers matters any more.
        var uri = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "192.168.1.10:8096",
            forwardedProto: null,
            forwardedHost: null,
            peer: "192.168.1.50",
            trustedCidrs: Array.Empty<string>(),
            providerId: "authentik",
            forceHttps: false,
            basePath: null,
            publicBaseUrl: "https://jellyfin.example.com");

        Assert.Equal("https://jellyfin.example.com/TwoFactorAuth/Oidc/Callback/authentik", uri);
    }

    [Fact]
    public void Without_a_declared_base_the_previous_behaviour_is_untouched()
    {
        var uri = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "192.168.1.10:8096",
            forwardedProto: null,
            forwardedHost: null,
            peer: "192.168.1.50",
            trustedCidrs: Array.Empty<string>(),
            providerId: "authentik");

        Assert.Equal("http://192.168.1.10:8096/TwoFactorAuth/Oidc/Callback/authentik", uri);
    }

    [Fact]
    public void A_declared_base_with_a_path_keeps_it_in_the_callback()
    {
        var uri = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "192.168.1.10:8096",
            forwardedProto: null,
            forwardedHost: null,
            peer: "192.168.1.50",
            trustedCidrs: Array.Empty<string>(),
            providerId: "authentik",
            forceHttps: false,
            basePath: "/ignored",
            publicBaseUrl: "https://example.com/jellyfin");

        Assert.Equal("https://example.com/jellyfin/TwoFactorAuth/Oidc/Callback/authentik", uri);
    }
}

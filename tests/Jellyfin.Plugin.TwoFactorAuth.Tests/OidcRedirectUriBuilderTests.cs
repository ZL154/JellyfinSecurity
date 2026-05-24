using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class OidcRedirectUriBuilderTests
{
    // 10.0.0.0/8 simulates a private network where the reverse proxy lives.
    private static readonly IReadOnlyList<string> Trusted = new[] { "10.0.0.0/8" };

    [Fact]
    public void Build_NoForwardedHeaders_UsesDirectSchemeAndHost()
    {
        // Baseline: no proxy in front of Jellyfin. Direct request values are
        // the source of truth.
        var result = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "jellyfin.local:8096",
            forwardedProto: null,
            forwardedHost: null,
            peer: "10.0.0.5",
            trustedCidrs: Trusted,
            providerId: "kanidm");

        Assert.Equal("http://jellyfin.local:8096/TwoFactorAuth/Oidc/Callback/kanidm", result);
    }

    [Fact]
    public void Build_ProtoOnlyFromTrustedProxy_PromotesToHttps()
    {
        // Issue #28: cloudflared / many nginx configs send X-Forwarded-Proto
        // but preserve the Host header directly. Old logic required BOTH
        // headers and fell back to http://; the fix honours scheme independently
        // so https propagates while host falls back to Request.Host verbatim.
        var result = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "jellyfin.example.com",
            forwardedProto: "https",
            forwardedHost: null,
            peer: "10.0.0.5",
            trustedCidrs: Trusted,
            providerId: "kanidm");

        Assert.Equal("https://jellyfin.example.com/TwoFactorAuth/Oidc/Callback/kanidm", result);
    }

    [Fact]
    public void Build_ProtoFromUntrustedPeer_HeaderIgnored()
    {
        // SECURITY: an attacker connecting from outside TrustedProxyCidrs must
        // NOT be able to spoof X-Forwarded-Proto. If we honoured it here, an
        // attacker could trick callers (and IdPs that don't strictly bind the
        // redirect_uri to a registered HTTPS one) into believing the origin
        // was secure. Direct scheme stays "http".
        var result = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "jellyfin.example.com",
            forwardedProto: "https",
            forwardedHost: null,
            peer: "203.0.113.42", // not in 10.0.0.0/8
            trustedCidrs: Trusted,
            providerId: "kanidm");

        Assert.Equal("http://jellyfin.example.com/TwoFactorAuth/Oidc/Callback/kanidm", result);
    }

    [Fact]
    public void Build_HostFromUntrustedPeer_HeaderIgnored()
    {
        // SECURITY: this is the redirect_uri-poisoning regression test. If the
        // gate weakened, an attacker sending X-Forwarded-Host: attacker.com
        // could push the IdP into emitting auth codes to their server. Direct
        // Host stays as configured.
        var result = OidcRedirectUriBuilder.Build(
            directScheme: "https",
            directHost: "jellyfin.example.com",
            forwardedProto: null,
            forwardedHost: "attacker.com",
            peer: "203.0.113.42",
            trustedCidrs: Trusted,
            providerId: "kanidm");

        Assert.Equal("https://jellyfin.example.com/TwoFactorAuth/Oidc/Callback/kanidm", result);
    }

    [Fact]
    public void Build_BothHeadersFromTrustedProxy_BothHonoured()
    {
        // Traefik-style: proxy rewrites Host to an internal hostname but sets
        // X-Forwarded-Host to the public-facing one. We use the forwarded one
        // for the redirect_uri so the IdP sees a hostname that matches what
        // was registered.
        var result = OidcRedirectUriBuilder.Build(
            directScheme: "http",
            directHost: "internal-jellyfin:8096",
            forwardedProto: "https",
            forwardedHost: "jellyfin.example.com",
            peer: "10.0.0.5",
            trustedCidrs: Trusted,
            providerId: "kanidm");

        Assert.Equal("https://jellyfin.example.com/TwoFactorAuth/Oidc/Callback/kanidm", result);
    }
}

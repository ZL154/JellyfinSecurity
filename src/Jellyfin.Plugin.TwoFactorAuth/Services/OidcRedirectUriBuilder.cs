using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Builds the OIDC <c>redirect_uri</c> for the authorisation request and the
/// token-exchange request. Both legs MUST send the same string — OAuth 2.0 /
/// OIDC require exact-match comparison against what's registered with the IdP.
///
/// Issue #28 fix: the previous implementation required both X-Forwarded-Proto
/// AND X-Forwarded-Host to be present before honouring either. Reverse-proxy
/// setups that only emit X-Forwarded-Proto (cloudflared, many nginx configs)
/// fell through to <c>Request.Scheme</c> which is "http" when TLS is
/// terminated upstream, and the IdP rejected the resulting http:// URI.
///
/// SECURITY: each forwarded header is only honoured when the direct peer is
/// in the configured TrustedProxyCidrs. An attacker connecting directly
/// cannot inject either header — the proxyTrusted gate keeps the original
/// SEC-H1 boundary intact.
/// </summary>
internal static class OidcRedirectUriBuilder
{
    public static string Build(
        string directScheme,
        string directHost,
        string? forwardedProto,
        string? forwardedHost,
        string peer,
        IReadOnlyList<string> trustedCidrs,
        string providerId)
    {
        var proxyTrusted = trustedCidrs.Any(c => BypassEvaluator.IsIpInCidr(peer, c));

        var scheme = proxyTrusted && !string.IsNullOrEmpty(forwardedProto)
            ? forwardedProto.Split(',')[0].Trim()
            : directScheme;

        var host = proxyTrusted && !string.IsNullOrEmpty(forwardedHost)
            ? forwardedHost.Split(',')[0].Trim()
            : directHost;

        return $"{scheme}://{host}/TwoFactorAuth/Oidc/Callback/{providerId}";
    }
}

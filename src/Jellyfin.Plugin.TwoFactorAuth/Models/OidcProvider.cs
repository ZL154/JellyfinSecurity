using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

/// <summary>An OIDC sign-in provider configured by the admin. Each provider
/// is a discrete identity source the user can link/sign in with — Google,
/// GitHub, Apple, Microsoft, Authelia, Authentik, Keycloak, PocketID,
/// Cloudflare Access, or anything else that speaks OIDC discovery.
///
/// Stored verbatim in the plugin XML config alongside other settings.</summary>
public class OidcProvider
{
    /// <summary>Stable identifier used in URLs (`/Oidc/Login/{Id}`) and in
    /// SsoLink records. Lowercase letters, digits, and hyphens only.
    /// Generated from the display name on creation.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>What appears on the "Sign in with X" button.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Provider preset key used to seed defaults — "google", "github",
    /// "apple", "microsoft", "discord", "pocketid", "authelia", "authentik",
    /// "keycloak", "cloudflare", or "generic" for hand-configured providers.
    /// Affects per-provider quirks (Apple's missing email_verified, Cloudflare's
    /// JWT-only flow, etc).</summary>
    public string Preset { get; set; } = "generic";

    /// <summary>OpenID discovery URL (`https://issuer/.well-known/openid-configuration`).
    /// All other endpoints (authorization, token, userinfo, jwks_uri) are
    /// fetched from here on first use and cached.</summary>
    public string DiscoveryUrl { get; set; } = string.Empty;

    /// <summary>OAuth 2.0 client credentials registered at the IdP.</summary>
    public string ClientId { get; set; } = string.Empty;

    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>Space-separated scope list. Default openid+profile+email is
    /// the common case. Add provider-specific scopes (e.g. `groups` for
    /// Authelia/Authentik) here.</summary>
    public string Scopes { get; set; } = "openid profile email";

    /// <summary>Optional `acr_values` to request — used to require the IdP to
    /// perform MFA (e.g. `mfa` for Cloudflare Access). Empty = whatever the
    /// IdP defaults to.</summary>
    public string AcrValues { get; set; } = string.Empty;

    /// <summary>Optional username claim name. Defaults to `preferred_username`
    /// then falls back to email-localpart. Override per provider when the
    /// IdP returns the username elsewhere (e.g. GitHub uses `login`).</summary>
    public string UsernameClaim { get; set; } = "preferred_username";

    /// <summary>If non-empty, sign-in only succeeds when the user's `groups`
    /// claim contains AT LEAST ONE of these strings. Comma-separated.</summary>
    public string AllowedGroups { get; set; } = string.Empty;

    /// <summary>If non-empty, the `groups` claim is checked against this list
    /// to grant Jellyfin admin. Comma-separated. Otherwise no admin elevation.</summary>
    public string AdminGroups { get; set; } = string.Empty;

    /// <summary>Auto-create a new Jellyfin user on first sign-in if the
    /// IdP-returned identity isn't linked yet. Default false (admin must
    /// pre-create users and let them link). Enabling this on a public-facing
    /// Jellyfin lets ANYONE with an account at the IdP create themselves a
    /// Jellyfin account — only enable for trusted IdPs.</summary>
    public bool AutoCreateUsers { get; set; }

    /// <summary>If true, refuse sign-in unless the IdP's `amr` claim indicates
    /// multi-factor (mfa, hwk, otp, etc). Useful for "force users to have
    /// IdP 2FA enabled before they can reach Jellyfin."</summary>
    public bool RequireIdpMfa { get; set; }

    /// <summary>When the user signs in via this provider, our 2FA challenge
    /// is skipped (the IdP already authenticated them). Default true — the
    /// whole point of SSO is to not double-2FA. Disable only if you want
    /// belt-and-braces (rare).</summary>
    public bool BypassPluginTwoFa { get; set; } = true;

    /// <summary>Show the "Sign in with this" button on the Jellyfin login
    /// page. Disable to hide a provider while keeping its config saved.</summary>
    public bool Enabled { get; set; } = true;

    public DateTime CreatedAt { get; set; }
}

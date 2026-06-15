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
    /// to grant Jellyfin admin. Comma-separated. Otherwise no admin elevation.
    ///
    /// SECURITY [v2.5.5] (N-A13): as of v2.5.5 this field is CONFIGURED but
    /// NOT CONSUMED by the sign-in pipeline. The OIDC flow does not elevate
    /// Jellyfin users to admin based on this list. Future implementer:
    /// before wiring this up, REQUIRE a fresh TOTP / passkey step-up
    /// challenge BEFORE applying admin elevation, and log every elevation
    /// at WARN with the source claim. Without that guard, a malicious or
    /// compromised IdP that controls the `groups` claim can elevate any
    /// claimed user to Jellyfin administrator silently.</summary>
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

    /// <summary>v2.5.1: force the redirect_uri scheme to https regardless of
    /// what the request / forwarded headers say. Needed when Jellyfin is
    /// behind a TLS-terminating proxy (Cloudflare Tunnel, some Caddy / nginx
    /// configs) that doesn't propagate <c>X-Forwarded-Proto</c> reliably —
    /// without this, redirect_uri is built as http:// and the IdP refuses
    /// the exchange.
    /// [v2.5.6] (issue #28): default flipped from false to true. The
    /// overwhelming-majority deployment is "Jellyfin behind a reverse proxy
    /// terminating TLS" — almost every IdP requires https redirect URIs,
    /// and the old default left users hitting a confusing IdP error before
    /// finding this toggle. New providers default to ForceHttps=true;
    /// existing providers keep their stored value on upgrade.</summary>
    public bool ForceHttps { get; set; } = true;

    /// <summary>[v2.5.7] (issue #54, cwildfoerster): bypass the v2.5.5 SSRF
    /// guard's HTTPS-only + public-unicast-IP check for THIS provider's
    /// outbound endpoint fetches (discovery / token / userinfo / jwks).
    /// Default false — keep the strict default for the public-Internet IdP
    /// case. Enable ONLY for IdPs that are intentionally reachable on
    /// private networks (LAN-only Authentik, Tailscale / Wireguard-fronted
    /// Authelia, etc.) where the boundary is the VPN/LAN and the SSRF
    /// vector — admin tricked into pointing the plugin at AWS IMDS or an
    /// internal HTTP service — is mitigated by the admin explicitly
    /// flipping this toggle. Per-provider so a public Google + a private
    /// Authentik can coexist without weakening Google's guard.</summary>
    public bool AllowPrivateNetworks { get; set; }

    /// <summary>[v2.5.10] (issue #66, ZEROX7): when true, on each successful
    /// sign-in the plugin copies the IdP-provided profile picture into the
    /// Jellyfin user's avatar. The URL is read from <see cref="PictureClaim"/>
    /// (default the standard OIDC `picture` claim) in the id_token / userinfo.
    /// The download goes through the same SSRF egress guard as the other
    /// outbound IdP calls. Best-effort: a failed picture sync never blocks
    /// sign-in. Default false so existing installs are unchanged.</summary>
    public bool SyncProfilePicture { get; set; }

    /// <summary>[v2.5.10] (issue #66): claim name holding the avatar URL.
    /// Standard OIDC is `picture`; some IdPs use a custom claim. Only used
    /// when <see cref="SyncProfilePicture"/> is enabled.</summary>
    public string PictureClaim { get; set; } = "picture";

    /// <summary>[v2.5.10] (issue #65, Bgabor997): when true, on each sign-in
    /// the user's Jellyfin library access is set from their IdP group/role
    /// claims via <see cref="RoleLibraryMappings"/>. The union of libraries
    /// granted by all of the user's matched roles becomes their EnabledFolders
    /// (EnableAllFolders is turned off). A user whose roles match no mapping
    /// gets NO libraries — so only enable this once mappings are configured,
    /// or unmapped users may lose visible libraries. Administrators are never
    /// restricted by this (admins implicitly see everything). Default false so
    /// existing installs are unchanged.</summary>
    /// <summary>[v2.5.10] When true, the sign-in request adds
    /// <c>prompt=select_account</c> so the IdP always shows its account chooser
    /// instead of silently reusing an existing IdP browser session. Useful on
    /// shared machines / multi-account households (e.g. switching between two
    /// Google accounts). Default false — single-account setups keep the
    /// one-click path.</summary>
    public bool PromptSelectAccount { get; set; }

    public bool ApplyRoleLibraryAccess { get; set; }

    /// <summary>[v2.5.10] (issue #65): role→library access map. Each entry maps
    /// one IdP group/role (matched against the `groups`/`roles` claim,
    /// case-insensitive) to a set of Jellyfin library IDs the role grants.</summary>
    public List<OidcRoleLibraryMapping> RoleLibraryMappings { get; set; } = new();

    /// <summary>[v2.5.11] (issue #70, ZEROX7): claim name holding the user's
    /// email address. Standard OIDC is `email`; some IdPs expose it under a
    /// custom claim (e.g. `internal_email`). Used both for the email-match
    /// resolve path and for <see cref="SyncEmailFromClaim"/>.</summary>
    public string EmailClaim { get; set; } = "email";

    /// <summary>[v2.5.11] (issue #70): when true, on each successful sign-in the
    /// plugin fills the Jellyfin user's plugin email (used for email OTP and
    /// shown in the admin Users tab) from <see cref="EmailClaim"/> if it is not
    /// already set. An existing, admin-entered email is never overwritten.
    /// Default true — this is the expected behaviour ZEROX7 reported missing.</summary>
    public bool SyncEmailFromClaim { get; set; } = true;

    /// <summary>[v2.5.11] (issue #69, ZEROX7): override the text on the
    /// "Sign in with X" login button. Empty = use "Sign in with {DisplayName}".</summary>
    public string ButtonText { get; set; } = string.Empty;

    /// <summary>[v2.5.11] (issue #69): optional icon/logo shown on the login
    /// button. An absolute https URL to an image, or a data: URI. Empty = no
    /// icon (a generic key glyph is used). Rendered client-side in inject.js;
    /// constrained to https / data: to avoid mixed-content + SSRF surprises.</summary>
    public string ButtonIconUrl { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
}

/// <summary>[v2.5.10] (issue #65): one role→libraries mapping for
/// <see cref="OidcProvider.RoleLibraryMappings"/>. Stored in the plugin XML
/// config, so plain string properties only (no Dictionary).</summary>
public class OidcRoleLibraryMapping
{
    /// <summary>IdP group/role name, matched case-insensitively against the
    /// user's `groups`/`roles` claim values.</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>Comma-separated Jellyfin library (virtual-folder) GUIDs this
    /// role grants access to. The admin UI resolves friendly library names to
    /// these IDs when saving.</summary>
    public string LibraryIds { get; set; } = string.Empty;
}

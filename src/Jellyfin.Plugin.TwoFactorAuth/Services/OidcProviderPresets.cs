using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Built-in seed data for popular OIDC providers. The admin picks
/// a preset and we pre-fill discovery URL + sensible scopes + per-provider
/// quirks. They still need to register their own OAuth client at the IdP and
/// paste in client_id + secret.
///
/// Adding a new preset = appending one entry. The plugin doesn't have to be
/// rebuilt to support a new IdP — admins can also pick "generic" and paste
/// any discovery URL.</summary>
public static class OidcProviderPresets
{
    public record Preset(
        string Key,
        string DisplayName,
        string DiscoveryUrl,
        string Scopes,
        string UsernameClaim,
        string SetupHint);

    /// <summary>Where to register the OAuth client at each IdP. Shown in the
    /// admin UI as a help link so admins don't have to hunt.</summary>
    public static readonly IReadOnlyList<Preset> All = new[]
    {
        new Preset(
            "google", "Google",
            "https://accounts.google.com/.well-known/openid-configuration",
            "openid profile email",
            "email",
            "console.cloud.google.com → APIs & Services → Credentials → Create OAuth client ID. Redirect URI: <jellyfin>/TwoFactorAuth/Oidc/Callback/google"),

        new Preset(
            "github", "GitHub",
            "", // GitHub isn't OIDC-discoverable; we use OAuth2 manual config (separate path)
            "openid profile email",
            "login",
            "github.com/settings/developers → New OAuth App. GitHub doesn't provide a discovery URL — use the GitHub preset which hard-codes the endpoints."),

        new Preset(
            "microsoft", "Microsoft / Entra ID",
            "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            "openid profile email",
            "preferred_username",
            "portal.azure.com → Entra ID → App registrations → New registration. Replace 'common' in the discovery URL with your tenant ID for single-tenant apps."),

        new Preset(
            "apple", "Apple",
            "https://appleid.apple.com/.well-known/openid-configuration",
            "openid name email",
            "email",
            "developer.apple.com → Certificates, IDs & Profiles → Sign in with Apple. Apple is unusual: returns email only on first sign-in, no email_verified claim."),

        new Preset(
            "discord", "Discord",
            "", // Discord uses OAuth2 not OIDC; separate manual flow
            "identify email",
            "username",
            "discord.com/developers/applications → New Application → OAuth2. Discord isn't OIDC-compliant — uses a custom OAuth2 flow."),

        new Preset(
            "pocketid", "PocketID",
            "", // user-supplied — depends on their PocketID instance URL
            "openid profile email groups",
            "preferred_username",
            "Your PocketID instance: Settings → OIDC Clients → Add. Discovery URL is https://your-pocketid/.well-known/openid-configuration."),

        new Preset(
            "authelia", "Authelia",
            "",
            "openid profile email groups",
            "preferred_username",
            "Authelia config.yml → identity_providers.oidc.clients. Discovery URL is https://your-authelia/.well-known/openid-configuration."),

        new Preset(
            "authentik", "Authentik",
            "",
            "openid profile email groups",
            "preferred_username",
            "Authentik admin → Applications → Providers → Create. Discovery URL is shown in the provider details."),

        new Preset(
            "keycloak", "Keycloak",
            "",
            "openid profile email roles",
            "preferred_username",
            "Keycloak admin → Clients → Create. Discovery URL is https://your-keycloak/realms/<realm>/.well-known/openid-configuration."),

        new Preset(
            "cloudflare", "Cloudflare Access",
            "",
            "openid profile email groups",
            "email",
            "Cloudflare Zero Trust dashboard → Access → Applications → SaaS app → OIDC. Discovery URL is https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<app-id>/.well-known/openid-configuration."),

        new Preset(
            "generic", "Generic OIDC",
            "",
            "openid profile email",
            "preferred_username",
            "Any OIDC-compliant provider. Paste the discovery URL exactly as the provider documents it."),
    };

    public static Preset? FindByKey(string key)
    {
        if (string.IsNullOrEmpty(key)) return null;
        foreach (var p in All)
        {
            if (string.Equals(p.Key, key, System.StringComparison.OrdinalIgnoreCase)) return p;
        }
        return null;
    }
}

using System.Xml.Serialization;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.TwoFactorAuth.Configuration;

public class UserEmailEntry
{
    [XmlAttribute("userId")]
    public string UserId { get; set; } = string.Empty;

    [XmlAttribute("email")]
    public string Email { get; set; } = string.Empty;
}

public class PluginConfiguration : BasePluginConfiguration
{
    public bool Enabled { get; set; } = true;

    public bool RequireForAllUsers { get; set; } = false;

    public bool LanBypassEnabled { get; set; } = true;

    public string[] LanBypassCidrs { get; set; } = new[]
    {
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12"
    };

    public bool TrustForwardedFor { get; set; } = false;

    public string[] TrustedProxyCidrs { get; set; } = Array.Empty<string>();

    public bool EmailOtpEnabled { get; set; } = true;

    public int EmailOtpTtlSeconds { get; set; } = 300;

    public int ChallengeTokenTtlSeconds { get; set; } = 300;

    public int PairingCodeTtlSeconds { get; set; } = 300;

    public int MaxFailedAttempts { get; set; } = 5;

    public int LockoutDurationMinutes { get; set; } = 15;

    public int AuditLogMaxEntries { get; set; } = 1000;

    public string NtfyUrl { get; set; } = string.Empty;

    public string NtfyTopic { get; set; } = string.Empty;

    public string GotifyUrl { get; set; } = string.Empty;

    public string GotifyAppToken { get; set; } = string.Empty;

    public string[] NotifyEmailAddresses { get; set; } = Array.Empty<string>();

    // SMTP settings for sending email OTP codes to users.
    public string SmtpHost { get; set; } = string.Empty;

    public int SmtpPort { get; set; } = 587;

    public bool SmtpUseSsl { get; set; } = true;

    public string SmtpUsername { get; set; } = string.Empty;

    public string SmtpPassword { get; set; } = string.Empty;

    public string SmtpFromAddress { get; set; } = string.Empty;

    public string SmtpFromName { get; set; } = "Jellyfin 2FA";

    // Per-user email addresses for OTP delivery. List form because Jellyfin
    // serializes plugin config as XML and XmlSerializer cannot handle Dictionary.
    public List<UserEmailEntry> UserEmails { get; set; } = new();

    public string? GetUserEmail(string userId)
    {
        var match = UserEmails.FirstOrDefault(e =>
            string.Equals(e.UserId, userId, StringComparison.OrdinalIgnoreCase));
        return match?.Email;
    }

    public void SetUserEmail(string userId, string? email)
    {
        UserEmails.RemoveAll(e => string.Equals(e.UserId, userId, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(email))
        {
            UserEmails.Add(new UserEmailEntry { UserId = userId, Email = email });
        }
    }

    // What appears in authenticator apps (issuer field of otpauth:// URI).
    // Defaults to "Jellyfin"; admins can override per server (e.g., "MyServer Jellyfin").
    public string TotpIssuerName { get; set; } = "Jellyfin";

    // ---- v1.4 additions ----

    /// <summary>How long a successful 2FA verification pre-authorizes follow-up
    /// session opens for the same (user, device). Default 120s — covers the
    /// usual flurry of WebSocket + HTTP sessions Jellyfin spawns immediately
    /// after sign-in. Range 30-900.</summary>
    public int PreVerifyWindowSeconds { get; set; } = 120;

    /// <summary>Lifetime of the per-device trust cookie (browser stays trusted
    /// without re-prompting). Range 1-90 days. Cookie rotates on every use,
    /// so a freshly-rotated cookie always gets a fresh window of this length.</summary>
    public int TrustCookieTtlDays { get; set; } = 30;

    /// <summary>Convenience for setups behind NAT hairpin: when enabled the
    /// plugin discovers its own public IP at startup (one outbound HTTPS GET)
    /// and treats requests arriving from that IP as if they came from LAN.
    /// Off by default — anyone sharing the same WAN egress, including IoT
    /// devices on the same router, would also bypass.</summary>
    public bool NatHairpinSelfIpBypass { get; set; }

    /// <summary>Server-wide default for max concurrent Jellyfin sessions per
    /// user. 0 = unlimited. Per-user override on UserTwoFactorData wins.
    /// Paired devices (TVs etc.) are excluded from the count.</summary>
    public int DefaultMaxConcurrentSessions { get; set; }

    /// <summary>Optional deadline by which RequireForAllUsers becomes effective
    /// in the admin UI's adoption dashboard. The plugin doesn't auto-flip the
    /// flag — it's a target date for the dashboard to flag stragglers.</summary>
    public DateTime? EnrollmentDeadline { get; set; }

    /// <summary>Webhook URL to POST every notable auth event to (lockouts,
    /// new-device sign-ins, recovery codes used, suspicious logins, passkey
    /// registers/uses, emergency lockouts, admin force-logouts).</summary>
    public string WebhookUrl { get; set; } = string.Empty;

    /// <summary>Optional shared secret. When set, every webhook POST carries
    /// `X-2FA-Signature: sha256=<hex>` HMAC over the body so receivers can
    /// authenticate the source.</summary>
    public string WebhookSecret { get; set; } = string.Empty;

    /// <summary>Path to a MaxMind GeoLite2-ASN.mmdb file. When set, the
    /// suspicious-login detector resolves remote IPs to ASN + country and
    /// notifies on first-seen contexts per user.</summary>
    public string GeoIpAsnDbPath { get; set; } = string.Empty;

    /// <summary>Path to a MaxMind GeoLite2-Country.mmdb file. Optional —
    /// without it, suspicious-login detection still works on ASN alone.</summary>
    public string GeoIpCountryDbPath { get; set; } = string.Empty;

    /// <summary>Optional explicit Relying Party ID for WebAuthn. If empty, the
    /// plugin derives it from the request Host. Required when behind a reverse
    /// proxy where the public hostname differs from the internal one.</summary>
    public string WebAuthnRpId { get; set; } = string.Empty;

    /// <summary>Allowed origins for WebAuthn (`https://yourdomain` form). If
    /// empty the request origin is used. Multiple allowed for multi-domain
    /// deployments.</summary>
    public string[] WebAuthnOrigins { get; set; } = Array.Empty<string>();

    /// <summary>v1.4.3: when a user is routed through a non-default
    /// IAuthenticationProvider (LDAP, SSO via jellyfin-plugin-sso, etc),
    /// their auth was already handled at the IdP — typically with that
    /// IdP's own MFA. Stacking our 2FA challenge on top is redundant and
    /// breaks federated logins (the IdP-issued token gets overwritten by
    /// our challenge response). When this is on (default), users on a
    /// non-default provider skip our 2FA entirely. Users on the stock
    /// password provider still get challenged normally.
    ///
    /// Default ON because the only sensible behaviour for SSO setups; admins
    /// who explicitly want belt-and-braces (2FA on top of SSO) can disable.
    /// </summary>
    public bool BypassForExternalAuthProviders { get; set; } = true;

    // ---- v2.0 additions ----

    /// <summary>OIDC sign-in providers. Each entry adds a "Sign in with X"
    /// button on the Jellyfin login page and an OAuth client to the plugin.
    /// Empty = SSO not in use (only the bypass shim above applies, for users
    /// routed through an external provider via a different plugin).</summary>
    public List<Models.OidcProvider> OidcProviders { get; set; } = new();

    /// <summary>Optional MaxMind GeoLite2-City.mmdb path. Required for
    /// impossible-travel detection (city resolution gives lat/lon). If only
    /// ASN/Country dbs are configured, suspicious-login alerts still work but
    /// impossible-travel is disabled (nothing to compute distance from).</summary>
    public string GeoIpCityDbPath { get; set; } = string.Empty;

    /// <summary>Brute-force IP banning — auto-ban a source IP after N failed
    /// auth attempts within a time window. 0 = disabled.</summary>
    public bool IpBanEnabled { get; set; } = true;

    /// <summary>Failed-attempt threshold (across ALL users from the same IP)
    /// that triggers an auto-ban.</summary>
    public int IpBanFailureThreshold { get; set; } = 10;

    /// <summary>Time window in minutes for the failure threshold count.</summary>
    public int IpBanFailureWindowMinutes { get; set; } = 10;

    /// <summary>How long an auto-ban persists in hours. Manual bans use this
    /// as the default but admin can override.</summary>
    public int IpBanDurationHours { get; set; } = 24;

    /// <summary>IPs / CIDRs that bypass the brute-force ban entirely. Useful
    /// for the admin's home/office IP so they can never be self-banned. LAN
    /// CIDRs are usually included implicitly via the LAN bypass list above.</summary>
    public string[] IpBanExemptCidrs { get; set; } = Array.Empty<string>();

    /// <summary>Impossible-travel detection: alert when a sign-in is too far
    /// from the user's last known location given the time elapsed. e.g.
    /// 500km in 30min ≈ Mach 1, almost certainly account compromise.</summary>
    public bool ImpossibleTravelEnabled { get; set; } = true;

    /// <summary>km/h threshold considered "impossible". 900 ≈ commercial jet
    /// cruise speed; anything above is suspicious. Lower = more sensitive
    /// (more false positives), higher = less.</summary>
    public int ImpossibleTravelMaxKmh { get; set; } = 900;

    /// <summary>Optional Ed25519 private key (PEM) for signing webhook bodies
    /// asymmetrically. Receivers verify with the matching public key. Empty =
    /// HMAC-only signing (current v1.4 behaviour). Asymmetric is preferred
    /// for SIEMs that want to verify without holding the shared secret.</summary>
    public string WebhookEd25519PrivateKey { get; set; } = string.Empty;
}

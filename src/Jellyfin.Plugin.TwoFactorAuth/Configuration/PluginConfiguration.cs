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
}

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
}

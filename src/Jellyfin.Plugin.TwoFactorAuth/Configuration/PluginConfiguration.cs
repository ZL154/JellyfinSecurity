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

/// <summary>v2.4: scope of 2FA enforcement. Replaces the all-or-nothing
/// RequireForAllUsers flag with a 3-state policy. RequireForAllUsers is
/// kept as a backwards-compat shim — setting it to true still works the
/// same as EnforcementScope=All.</summary>
/// <summary>[v2.5.6] (round-5 fix D): tri-state policy for whether
/// self-service 2FA mutations (enroll/replace TOTP, generate recovery
/// codes, create app password, add/delete passkey) require a fresh
/// current-factor code from the user. Designed to balance security
/// (default Forced) against UX flexibility for trusted households or
/// kiosk setups.</summary>
public enum SelfServiceStepUpMode
{
    /// <summary>No prompt. Any authenticated user can mutate their own 2FA
    /// state without a current code. Equivalent to v2.5.5 behaviour.</summary>
    Off = 0,

    /// <summary>Per-user opt-in. Admin exposes a toggle on each user's
    /// Setup page; opted-in users get the same prompt as Forced, opted-out
    /// users behave like Off. New per-user data starts opted-out.</summary>
    UserChoice = 1,

    /// <summary>Server-side mandatory. Every user with existing 2FA must
    /// submit a current TOTP/recovery code before mutating factors. No
    /// per-user opt-out. This is the secure default for v2.5.6.</summary>
    Forced = 2,
}

public enum EnforcementScope
{
    /// <summary>Default. Each user opts in to 2FA from the Setup page.
    /// Users without 2FA enabled sign in normally.</summary>
    Optional = 0,

    /// <summary>2FA is required for Jellyfin administrators. Regular users
    /// remain Optional. Standard enterprise pattern: protect privileged
    /// accounts hard, leave casual viewers alone.</summary>
    Admins = 1,

    /// <summary>2FA is required for every user. Equivalent to
    /// RequireForAllUsers=true.</summary>
    All = 2,
}

public class PluginConfiguration : BasePluginConfiguration
{
    public bool Enabled { get; set; } = true;

    /// <summary>v2.5.5 security: when true, /Users/AuthenticateByName attempts
    /// carrying an empty / whitespace-only password are hard-rejected by
    /// <see cref="Services.TwoFactorAuthProvider.Authenticate"/> before
    /// reaching Jellyfin's default provider. Closes the
    /// any-password-matches-empty-stored-hash exploit (Snerillinn / reddit
    /// report, June 2026) at the auth boundary for ALL users regardless of
    /// how their hash got into that state.
    ///
    /// Defaults to FALSE so v2.5.4-era installs that rely on the Jellyfin
    /// kiosk-mode "tap a user tile to sign in with no password" flow keep
    /// working on upgrade. Admins running shared / public / cloud Jellyfins
    /// should set this TRUE in the plugin config — the startup audit log
    /// surfaces every affected user so the impact is visible before flipping.
    ///
    /// Independent of this flag, NEW OIDC-provisioned users still get a
    /// random 256-bit password set by <see cref="Services.OidcService"/>
    /// at creation time, and the auth-time audit entries for empty-password
    /// attempts are still written. Disabling this only restores Jellyfin's
    /// default "no stored hash matches everything" behaviour for existing
    /// users — the OIDC create-side hardening always runs.</summary>
    public bool BlockEmptyPasswordLogin { get; set; } = false;

    /// <summary>v2.5.5 (Finding 7): when true, /Verify rejects challenge
    /// tokens whose original challenge was issued from a different /24
    /// (IPv4) or /48 (IPv6) than the verifying client. Defends against an
    /// attacker who captures the challenge token from one network and
    /// replays it from another. Defaults to FALSE because reverse-proxy /
    /// Cloudflare-Tunnel deployments routinely see the apparent client IP
    /// shift between the initial Authenticate and the subsequent Verify
    /// even within one legitimate user session. Admins on direct / static
    /// deployments should turn this ON.</summary>
    public bool RequireChallengeIpMatch { get; set; } = false;

    /// <summary>v2.5.5 (F12): days after which a registered-device-ID entry
    /// expires and stops granting 2FA bypass. 0 = no expiry (legacy behaviour
    /// preserved on upgrade). Recommend 90 days for a balance between
    /// convenience (don't re-prompt long-trusted devices) and security
    /// (compromise of a long-dormant device-id rotates out automatically).
    /// Only affects entries in <see cref="Models.UserTwoFactorData.RegisteredDeviceEntries"/>;
    /// legacy entries (only in RegisteredDeviceIds, no timestamp) are not
    /// expired — admins must re-register or clear to migrate them.</summary>
    public int RegisteredDeviceMaxAgeDays { get; set; } = 0;

    // SECURITY [v2.5.6] (ext review bare-DeviceId): bare client-supplied
    // DeviceId is a weak factor — a stolen password + a known/guessed/spoofed
    // DeviceId would skip 2FA via the "registered_device" or "paired_device"
    // bypass paths. We default this flag to FALSE so new and upgrading
    // installs close the gap. Admins who depend on the bare-DeviceId bypass
    // for TV / native-client convenience (Tizen, AppleTV, Findroid, etc.)
    // can re-enable explicitly. The signed trusted-device cookie path
    // (TokenHash + DeviceId) remains active regardless — that's still a
    // secure factor and isn't affected by this flag.
    public bool BareDeviceIdBypassEnabled { get; set; } = false;

    /// <summary>Legacy v2.3-style global flag. Kept for backwards compat: if
    /// true, behaves identically to EnforcementScope=All. Set the v2.4
    /// EnforcementScope to opt into the per-role policy.</summary>
    public bool RequireForAllUsers { get; set; } = false;

    /// <summary>v2.5.0: require a fresh TOTP/recovery code before a user can
    /// disable their own 2FA.
    /// [v2.5.6] (round-5 fix C): default changed to TRUE. Letting a stolen
    /// session disable 2FA without proof of the current factor was a free
    /// account-takeover path. Admins can override to false for kiosk / lab
    /// setups where the UX cost outweighs the risk.</summary>
    public bool RequireTwoFactorToDisable { get; set; } = true;

    /// <summary>SECURITY [v2.5.6] (round-5 fix D): tri-state hardened-security
    /// policy for self-service 2FA mutations (TOTP enroll/replace, recovery-
    /// code generate, app-password create, passkey add/delete). Replaces the
    /// older boolean <c>RequireStepUpForSelfServiceChanges</c>.
    ///   * <see cref="SelfServiceStepUpMode.Off"/> — never prompt the user
    ///     for a current-factor code. Legacy behaviour, accepted risk.
    ///   * <see cref="SelfServiceStepUpMode.UserChoice"/> — admin lets each
    ///     user opt in via their own Setup page toggle. Users who opt in
    ///     get the same code-on-change prompt as Forced; users who don't
    ///     can mutate without a code (same as Off for them).
    ///   * <see cref="SelfServiceStepUpMode.Forced"/> — every user must
    ///     submit a current TOTP / recovery code before any 2FA mutation.
    ///     No per-user opt-out. This is the secure default.
    /// First-time setup on a no-2FA account is exempt under every mode —
    /// there's no current factor to step up from yet.</summary>
    public SelfServiceStepUpMode SelfServiceStepUpMode { get; set; } = SelfServiceStepUpMode.Forced;

    /// <summary>v2.5.0: how aggressively to require step-up re-auth for
    /// sensitive admin actions. Off by default (opt-in).</summary>
    public StepUpLevel StepUpLevel { get; set; } = StepUpLevel.Off;

    /// <summary>v2.5.0: lifetime of a step-up "recently re-authenticated"
    /// token, seconds. Clamped 60-900.</summary>
    public int StepUpWindowSeconds { get; set; } = 300;

    /// <summary>v2.5.0: when true, users can opt individual trusted browsers
    /// and paired devices into indefinite trust (no 30-day re-auth). When
    /// false, the toggle is hidden from the user UI entirely. Disabled by
    /// default — admins must explicitly enable.</summary>
    public bool AllowIndefiniteTrust { get; set; } = false;

    /// <summary>[v2.5.7] (issue #48 feature request, Gaarindor): when true,
    /// inject.js skips injecting the "Sign in with Two-Factor Authentication"
    /// button on Jellyfin's main login page. Independent of the passkey
    /// toggle below so admins can pick the OIDC-only / passkey-only / 2FA-only
    /// shape they want. The plugin's own /TwoFactorAuth/Login still works
    /// directly for admins / fallback access regardless of this flag.</summary>
    public bool HideBuiltInTwoFactorButton { get; set; }

    /// <summary>[v2.5.7] (issue #48 feature request, Gaarindor): when true,
    /// inject.js skips injecting the "Sign in with passkey" button on the
    /// main login page. Set both this and HideBuiltInTwoFactorButton to true
    /// for OIDC-only mode where only IdP provider buttons remain.</summary>
    public bool HideBuiltInPasskeyButton { get; set; }

    /// <summary>v2.4: granular 2FA enforcement scope. Optional (per-user
    /// opt-in), Admins (only admins must have 2FA), or All (everyone).</summary>
    public EnforcementScope EnforcementScope { get; set; } = EnforcementScope.Optional;

    /// <summary>Returns true iff this user must have 2FA enabled given the
    /// current policy. Honors both the new EnforcementScope and the legacy
    /// RequireForAllUsers flag so existing v2.3 configs upgrade cleanly.</summary>
    public bool ShouldEnforceFor(bool isAdmin)
    {
        if (RequireForAllUsers) return true;
        return EnforcementScope switch
        {
            EnforcementScope.All => true,
            EnforcementScope.Admins => isAdmin,
            _ => false,
        };
    }

    // SECURITY [v2.5.6] (ext review #3): default changed from true → false.
    // Prior default + the default LanBypassCidrs (192.168/16, 10/8, 172.16/12)
    // + TrustForwardedFor=false combination created a real risk for any
    // Jellyfin running behind Docker / reverse-proxy / overlay-network where
    // the apparent client IP is the container/proxy gateway (often a
    // 172.16/12 or 10/8 address). External attackers would then look "LAN"
    // to the plugin and bypass 2FA entirely. Admins who actually want LAN
    // bypass must now (a) enable the flag, AND (b) configure
    // TrustedProxyCidrs + TrustForwardedFor=true so the proxy-walked
    // client IP is what's compared. Existing installs that opted in are
    // unaffected — only new installs get the safer default.
    public bool LanBypassEnabled { get; set; } = false;

    public string[] LanBypassCidrs { get; set; } = new[]
    {
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12"
    };

    public bool TrustForwardedFor { get; set; } = false;

    public string[] TrustedProxyCidrs { get; set; } = Array.Empty<string>();

    public bool EmailOtpEnabled { get; set; } = true;

    /// <summary>v2.4: opt-in Have I Been Pwned password check on successful
    /// sign-in. Uses the public api.pwnedpasswords.com k-anonymity range API
    /// — only the first 5 hex chars of SHA-1(password) leave the server.
    /// On a breach hit, logs a warning + writes an audit entry. Default off
    /// to keep existing installs unchanged; admins opt in.</summary>
    public bool HibpEnabled { get; set; } = false;

    public int EmailOtpTtlSeconds { get; set; } = 300;

    public int ChallengeTokenTtlSeconds { get; set; } = 300;

    public int PairingCodeTtlSeconds { get; set; } = 300;

    public int MaxFailedAttempts { get; set; } = 5;

    public int LockoutDurationMinutes { get; set; } = 15;

    /// <summary>[v2.5.10] (issue #55, Dasnap): when true, Jellyfin
    /// administrators are never locked out by the failed-attempt counter.
    /// Account lockout is a denial-of-service vector against the admin: anyone
    /// who knows the admin username can deliberately fail logins to lock the
    /// real admin out of their own server. Because admin accounts are already
    /// protected by 2FA enforcement AND the per-IP brute-force ban (which
    /// keeps firing against the attacker's IP regardless of this flag), the
    /// account-lockout adds little brute-force protection for admins while
    /// handing attackers an easy lockout DoS. Defaults to TRUE so the admin
    /// can't be self-locked out of the box; set FALSE to restore strict
    /// per-account lockout for administrators too. Regular users are always
    /// subject to lockout. Failed-attempt notifications/audit still fire for
    /// exempt admins, so a brute-force attempt is still visible.</summary>
    public bool ExemptAdministratorsFromLockout { get; set; } = true;

    /// <summary>[v2.5.11] (issue #69, ZEROX7): master switch to refuse
    /// username+password sign-in so only OIDC/SSO + Quick Connect remain. OIDC
    /// bridge tokens and Quick Connect are never blocked. Default false.
    /// Always paired with the escape hatches below so a dead IdP can't lock
    /// everyone out — and the plugin's own /TwoFactorAuth/Login page still
    /// works regardless of this flag.</summary>
    public bool DisablePasswordLogin { get; set; } = false;

    /// <summary>[v2.5.11] (#69) escape hatch (toggleable): administrators can
    /// always sign in with a password even when <see cref="DisablePasswordLogin"/>
    /// is on, so an admin can still get in if the IdP is unreachable. Default
    /// true.</summary>
    public bool AllowAdminPasswordLogin { get; set; } = true;

    /// <summary>[v2.5.11] (#69) escape hatch (toggleable): password sign-in is
    /// still allowed from LAN clients (matched against <see cref="LanBypassCidrs"/>)
    /// even when <see cref="DisablePasswordLogin"/> is on. With this on, the
    /// effect is "disable password login for REMOTE users only" — ZEROX7's
    /// requested scope. Turn off to disable password login for everyone
    /// (subject only to the admin + explicit-CIDR exemptions). Default true.</summary>
    public bool AllowPasswordLoginOnLan { get; set; } = true;

    /// <summary>[v2.5.11] (#69) escape hatch: explicit CIDRs that may always
    /// password-login even when <see cref="DisablePasswordLogin"/> is on (e.g.
    /// an admin's home IP). Empty by default.</summary>
    public string[] PasswordLoginExemptCidrs { get; set; } = Array.Empty<string>();

    /// <summary>[v2.5.11] (issue #71, ZEROX7): enable self-service password
    /// recovery by email. Requires SMTP configured. When on, the login page
    /// shows a "Forgot password?" link that emails a one-time, expiring reset
    /// link. Default false.</summary>
    public bool EnablePasswordRecovery { get; set; } = false;

    /// <summary>[v2.5.12] (issue #80, ZEROX7): when the plugin's own email
    /// password recovery is enabled, also hide Jellyfin's built-in "Forgot
    /// password?" link on the login page so users see only one recovery flow.
    /// Sub-option of <see cref="EnablePasswordRecovery"/> — only takes effect
    /// when that is on. Default true.</summary>
    public bool HideBuiltInForgotPassword { get; set; } = true;

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

    /// <summary>v2.5.0: default UI language used when a user has no per-user
    /// preference. Falls back to "en" if the requested language has no bundled
    /// translation file.</summary>
    public string DefaultLanguage { get; set; } = "en";

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

    // ===================================================================
    // [v2.5.14] (#100, Re4mstr) OIDC onboarding password policy. Applied
    // when an OIDC provider has ForcePasswordSetup on and the auto-created
    // user is asked to choose a local Jellyfin password. Global so a single
    // policy covers every provider.
    // ===================================================================

    /// <summary>Minimum length for an onboarding-set password. Default 16.
    /// Clamped to [1, 256] at validation time.</summary>
    public int OnboardingPasswordMinLength { get; set; } = 16;

    /// <summary>Require at least one uppercase letter. Default off.</summary>
    public bool OnboardingPasswordRequireUppercase { get; set; }

    /// <summary>Require at least one lowercase letter. Default off.</summary>
    public bool OnboardingPasswordRequireLowercase { get; set; }

    /// <summary>Require at least one digit. Default off.</summary>
    public bool OnboardingPasswordRequireDigit { get; set; }
}

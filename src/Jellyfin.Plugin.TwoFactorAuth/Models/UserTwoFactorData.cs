using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class UserTwoFactorData
{
    public Guid UserId { get; set; }

    public bool TotpEnabled { get; set; }

    public bool TotpVerified { get; set; }

    public string? EncryptedTotpSecret { get; set; }

    public bool EmailOtpPreferred { get; set; }

    public List<TrustedDevice> TrustedDevices { get; set; } = new();

    public List<string> RegisteredDeviceIds { get; set; } = new();

    public int FailedAttemptCount { get; set; }

    public DateTime? LockoutEnd { get; set; }

    public List<RecoveryCode> RecoveryCodes { get; set; } = new();

    public DateTime? RecoveryCodesGeneratedAt { get; set; }

    /// <summary>App-specific passwords for native clients (Swiftfin, Findroid, etc.)
    /// that can submit a password but cannot prompt for TOTP.</summary>
    public List<AppPassword> AppPasswords { get; set; } = new();

    /// <summary>Devices this user has paired (either via QR pairing or by approving
    /// a pending native-client login). Bypasses 2FA when matching DeviceId connects.</summary>
    public List<PairedDevice> PairedDevices { get; set; } = new();

    // ---- v1.4 additions (all additive, default-safe for old user JSON) ----

    /// <summary>WebAuthn / FIDO2 credentials registered by this user. Each entry is
    /// a public-key credential whose CredentialId is presented during sign-in.</summary>
    public List<PasskeyCredential> Passkeys { get; set; } = new();

    /// <summary>Set by emergency self-service lockout. While true, the user's next
    /// sign-in must consume a recovery code or email OTP — TOTP and passkey are
    /// stripped from the available methods list. Cleared on successful recovery.</summary>
    public bool ForceRecoveryOnNextLogin { get; set; }

    /// <summary>Per-user override for max concurrent sessions. Null = use the
    /// plugin-wide default. Zero = unlimited (matches default semantics).</summary>
    public int? MaxConcurrentSessions { get; set; }

    /// <summary>When true, only WebAuthn passkeys count as a 2nd factor; TOTP /
    /// email / recovery / app-password are rejected. Admin-only opt-in.</summary>
    public bool RequirePasskeyOnly { get; set; }

    /// <summary>ASN + country combinations we have already seen sign-ins from.
    /// Used by SuspiciousLoginDetector to fire a notification on first-seen
    /// contexts. Bounded — old entries pruned by LastSeen on cleanup.</summary>
    public List<SeenContext> SeenContexts { get; set; } = new();
}

public class RecoveryCode
{
    public string Hash { get; set; } = string.Empty;

    public bool Used { get; set; }

    public DateTime? UsedAt { get; set; }
}

public class TrustedDevice
{
    public string Id { get; set; } = string.Empty;

    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime LastUsedAt { get; set; }
}

/// <summary>App-specific password that lets a native client bypass 2FA.
/// The plaintext password is shown ONCE at creation; we persist only a PBKDF2 hash.</summary>
public class AppPassword
{
    public string Id { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    /// <summary>PBKDF2-SHA256 hash, base64. Format: "v1$iterations$saltB64$hashB64".</summary>
    public string PasswordHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime? LastUsedAt { get; set; }

    /// <summary>Last device that authenticated with this password (set when matched).</summary>
    public string LastDeviceName { get; set; } = string.Empty;

    public string LastDeviceId { get; set; } = string.Empty;
}

/// <summary>A FIDO2 / WebAuthn credential. The PublicKeyCose blob is the
/// COSE-encoded public key returned by the authenticator at registration —
/// stored verbatim because Fido2NetLib re-parses it on each verification.
/// SignatureCounter must monotonically increase across uses; a regression
/// indicates credential cloning and is rejected.</summary>
public class PasskeyCredential
{
    public string Id { get; set; } = string.Empty;

    /// <summary>Base64url-encoded credential ID (the byte string the browser
    /// sends in `allowCredentials` during auth).</summary>
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>Base64-encoded COSE public key.</summary>
    public string PublicKeyCose { get; set; } = string.Empty;

    /// <summary>Counter from the most recent successful assertion.</summary>
    public uint SignatureCounter { get; set; }

    /// <summary>Authenticator AAGUID — identifies the model (YubiKey, Windows
    /// Hello, iCloud Keychain, etc.). Surfaces in the admin UI for context.</summary>
    public string Aaguid { get; set; } = string.Empty;

    /// <summary>User-supplied label, e.g. "YubiKey 5 NFC" or "MacBook".</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Comma-separated transport hints from registration ("usb,nfc,ble").</summary>
    public string Transports { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime? LastUsedAt { get; set; }
}

/// <summary>An ASN+country pair previously seen for this user. Used to detect
/// novel sign-in contexts.</summary>
public class SeenContext
{
    /// <summary>Autonomous System Number (e.g. 13335 = Cloudflare).</summary>
    public uint Asn { get; set; }

    /// <summary>ISO 3166-1 alpha-2 country code (e.g. "GB", "US").</summary>
    public string Country { get; set; } = string.Empty;

    public DateTime FirstSeen { get; set; }

    public DateTime LastSeen { get; set; }

    /// <summary>Number of sign-ins observed from this context. Useful in the
    /// adoption dashboard to spot heavily-used vs one-off origins.</summary>
    public long RequestCount { get; set; }
}

/// <summary>A device the user has paired/approved. Matching DeviceId on auth → bypass 2FA.</summary>
public class PairedDevice
{
    public string Id { get; set; } = string.Empty;

    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public string AppName { get; set; } = string.Empty;

    public string Source { get; set; } = "auto"; // "auto" | "qr" | "manual"

    public DateTime CreatedAt { get; set; }

    public DateTime LastUsedAt { get; set; }

    public string LastIp { get; set; } = string.Empty;
}

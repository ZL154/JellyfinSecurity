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

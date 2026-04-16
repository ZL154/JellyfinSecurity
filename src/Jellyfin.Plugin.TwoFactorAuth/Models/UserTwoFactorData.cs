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

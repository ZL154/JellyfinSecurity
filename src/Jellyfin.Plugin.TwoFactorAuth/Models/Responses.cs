using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class TwoFactorRequiredResponse
{
    public bool TwoFactorRequired { get; set; } = true;

    public string ChallengeToken { get; set; } = string.Empty;

    public List<string> Methods { get; set; } = new();

    public string ChallengePageUrl { get; set; } = string.Empty;
}

public class VerifyResponse
{
    public string AccessToken { get; set; } = string.Empty;

    public string? DeviceToken { get; set; }
}

public class TotpSetupResponse
{
    public string SecretKey { get; set; } = string.Empty;

    public string QrCodeBase64 { get; set; } = string.Empty;

    public string ManualEntryKey { get; set; } = string.Empty;
}

public class TrustedDeviceResponse
{
    public string Id { get; set; } = string.Empty;

    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime LastUsedAt { get; set; }
}

public class UserTwoFactorStatus
{
    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public bool TotpEnabled { get; set; }

    public bool EmailOtpEnabled { get; set; }

    public int TrustedDeviceCount { get; set; }

    public int RecoveryCodesRemaining { get; set; }

    public bool IsLockedOut { get; set; }
}

public class TrustedDeviceWithUser
{
    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public string Id { get; set; } = string.Empty;

    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime LastUsedAt { get; set; }
}

public class PairingResponse
{
    public string Code { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public DateTime ExpiresAt { get; set; }
}

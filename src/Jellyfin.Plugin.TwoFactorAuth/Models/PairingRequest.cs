using System;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class PairingRequest
{
    public string Code { get; set; } = string.Empty;

    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public string ChallengeToken { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public PairingStatus Status { get; set; } = PairingStatus.Pending;
}

public enum PairingStatus
{
    Pending,
    Approved,
    Denied,
    Expired
}

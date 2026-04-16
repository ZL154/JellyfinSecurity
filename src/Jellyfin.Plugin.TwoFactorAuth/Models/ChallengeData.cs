using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class ChallengeData
{
    public string Token { get; set; } = string.Empty;

    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public List<string> AvailableMethods { get; set; } = new();

    public string? DeviceId { get; set; }

    public string? DeviceName { get; set; }

    public string? RemoteIp { get; set; }

    public bool IsConsumed { get; set; }

    public int AttemptCount { get; set; }

    public string? PendingAuthResponse { get; set; }
}

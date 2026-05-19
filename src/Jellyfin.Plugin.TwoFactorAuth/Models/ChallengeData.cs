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

    public bool EnrollmentRequired { get; set; }

    public string? DeviceId { get; set; }

    public string? DeviceName { get; set; }

    public string? RemoteIp { get; set; }

    // SEC v2.4 L2: backing field used for atomic single-consume via
    // Interlocked.CompareExchange. Previously IsConsumed was a plain bool
    // property, which made ConsumeChallenge a check-then-set race — two
    // concurrent requests could both pass the IsConsumed=false check and
    // both proceed, allowing one OTP code to mint two sessions. TryConsume
    // is the canonical claim path; the setter remains for migration paths
    // that need to externally mark a challenge consumed (e.g. cleanup).
    private int _consumed;

    public bool IsConsumed
    {
        get => System.Threading.Volatile.Read(ref _consumed) != 0;
        set => System.Threading.Volatile.Write(ref _consumed, value ? 1 : 0);
    }

    /// <summary>Atomically claim this challenge. Returns true exactly once
    /// across concurrent callers. Subsequent callers receive false.</summary>
    internal bool TryConsume()
        => System.Threading.Interlocked.CompareExchange(ref _consumed, 1, 0) == 0;

    public int AttemptCount { get; set; }

    public string? PendingAuthResponse { get; set; }
}

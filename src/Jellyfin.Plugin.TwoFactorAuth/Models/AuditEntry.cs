using System;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class AuditEntry
{
    public DateTime Timestamp { get; set; }

    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public string RemoteIp { get; set; } = string.Empty;

    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;

    public AuditResult Result { get; set; }

    public string Method { get; set; } = string.Empty;

    public string? Details { get; set; }
}

public enum AuditResult
{
    Success,
    Failed,
    Bypassed,
    Locked,
    ChallengeIssued
}

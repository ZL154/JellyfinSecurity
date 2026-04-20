using System;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

/// <summary>An IP address banned by the brute-force detector. Bans are
/// time-limited; expired entries are pruned by the periodic cleanup sweep.
/// Stored in a JSON file alongside the audit log so they survive restart.</summary>
public class IpBanEntry
{
    public string Ip { get; set; } = string.Empty;

    /// <summary>UTC timestamp of the ban.</summary>
    public DateTime BannedAt { get; set; }

    /// <summary>UTC timestamp when the ban auto-lifts.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>How many failed auth attempts triggered the ban.</summary>
    public int FailureCount { get; set; }

    /// <summary>"auto" for the brute-force detector, "manual" for an admin
    /// ban added via the UI. Manual bans don't auto-extend on subsequent
    /// failures.</summary>
    public string Source { get; set; } = "auto";

    /// <summary>Optional admin-supplied note shown in the IP-bans tab.</summary>
    public string Note { get; set; } = string.Empty;
}

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

    // ---- v1.4: hash chain ----
    // Each entry's hash is sha256 over a canonical serialization of all fields
    // EXCEPT EntryHash itself, prepended with the previous entry's hash. The
    // chain is verified on demand by the diagnostics service. Tampering with
    // any historical entry breaks every subsequent hash. Doesn't defeat an
    // attacker with file-write — it just makes silent tampering impossible.

    /// <summary>Sha256 of the prior audit entry's EntryHash, hex. All-zeros for
    /// the first entry in the file.</summary>
    public string PreviousHash { get; set; } = string.Empty;

    /// <summary>Sha256 over (PreviousHash || canonical-serialize(this without
    /// EntryHash)), hex. Filled in by the audit append code.</summary>
    public string EntryHash { get; set; } = string.Empty;
}

public enum AuditResult
{
    Success,
    Failed,
    Bypassed,
    Locked,
    ChallengeIssued,
    /// <summary>Config-change events (app password created/revoked, device paired/revoked,
    /// admin toggle). Not an auth bypass — keeps the audit log correctly filterable.</summary>
    ConfigChanged
}

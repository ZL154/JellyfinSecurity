namespace Jellyfin.Plugin.TwoFactorAuth.Configuration;

/// <summary>How aggressively step-up re-auth is required for sensitive admin
/// actions. Higher levels are supersets of lower ones.</summary>
public enum StepUpLevel
{
    /// <summary>No step-up ever (default). Pure pass-through.</summary>
    Off = 0,

    /// <summary>Re-auth before destructive actions: disable enforcement,
    /// reset/disable another user's 2FA, export-with-secrets, unban-all.</summary>
    Destructive = 1,

    /// <summary>Destructive + any settings change, OIDC edit, allowlist edit,
    /// single unban, config import.</summary>
    AllConfigChanges = 2,

    /// <summary>AllConfigChanges + viewing the audit log.</summary>
    Everything = 3,
}

using System;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class ApiKeyEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    // Legacy plaintext key — kept only for backward-compat with v1 keys
    // created before hashing was introduced. On first startup that touches
    // the store, any entry with a non-empty Key migrates to KeyHash + zeroed
    // Key so users aren't silently re-prompted. Serialized with default-
    // ignore so new entries don't emit it.
    public string Key { get; set; } = string.Empty;

    // Hashed storage: sha256 of the raw key, hex. Used for constant-time
    // comparison in BypassEvaluator. Adequate here because the raw key is
    // 256 bits of entropy (not a low-entropy password that needs PBKDF2).
    public string KeyHash { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    // Preview — first 6 chars of the raw key, shown in the admin UI so the
    // user can identify the key without seeing the full secret.
    public string KeyPreview { get; set; } = string.Empty;
}

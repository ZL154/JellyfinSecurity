using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

/// <summary>Versioned wrapper around an export payload. The frontend
/// deserializes this first to decide which decryption / parse path to take.</summary>
public class ExportEnvelope
{
    /// <summary>Format version. Bumped on incompatible schema changes.
    /// Imports of an unknown version are hard-rejected.</summary>
    public int FormatVersion { get; set; } = 1;

    public DateTime ExportedAt { get; set; }

    /// <summary>Plugin version that emitted the export. Mismatches are
    /// surfaced as a warning, not a hard reject.</summary>
    public string PluginVersion { get; set; } = string.Empty;

    public bool Encrypted { get; set; }

    /// <summary>When Encrypted=false, this is a ConfigExportPayload JSON object.
    /// When Encrypted=true, this is a base64 string of (salt || nonce || ciphertext || tag).</summary>
    public object Payload { get; set; } = null!;
}

public class ConfigExportPayload
{
    public PluginConfiguration Configuration { get; set; } = new();

    public List<ScoreSnapshot> ScoreHistory { get; set; } = new();

    public List<string> RedactedFields { get; set; } = new();
}

public class FullExportPayload
{
    public PluginConfiguration Configuration { get; set; } = new();

    public List<ScoreSnapshot> ScoreHistory { get; set; } = new();

    public List<UserTwoFactorData> Users { get; set; } = new();
}

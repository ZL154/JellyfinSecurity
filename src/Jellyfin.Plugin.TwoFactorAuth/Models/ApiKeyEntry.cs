using System;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class ApiKeyEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string Key { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
}

using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#345] Stored credentials are factors only while passkeys are enabled.</summary>
internal static class PasskeyPolicy
{
    internal const string DisabledMessage = "Passkeys are disabled on this server.";

    /// <summary>True only while the server allows passkeys and the user has at
    /// least one stored. With <see cref="PluginConfiguration.PasskeysEnabled"/>
    /// off, a stored passkey is kept but answers nothing and protects nothing.</summary>
    internal static bool HasUsable(UserTwoFactorData data, PluginConfiguration config)
        => config.PasskeysEnabled && data.Passkeys.Count > 0;
}

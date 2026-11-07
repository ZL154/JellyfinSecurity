using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#345] Stored credentials are factors only while passkeys are enabled.</summary>
internal static class PasskeyPolicy
{
    internal const string DisabledMessage = "Passkeys are disabled on this server.";

    internal static bool HasEnrolled(UserTwoFactorData data, PluginConfiguration config)
        => config.PasskeysEnabled && data.Passkeys.Count > 0;
}

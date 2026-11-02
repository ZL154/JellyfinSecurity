using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Decides whether local sign-in needs a challenge, independently of
/// which enrolled methods can answer that challenge.</summary>
internal static class SignInChallengePolicy
{
    internal static bool RequiresChallenge(UserTwoFactorData data, PluginConfiguration config, bool isAdmin)
        => GetReason(data, config, isAdmin) != "none";

    /// <summary>Returns the effective reason, with mandatory scope first,
    /// followed by the authenticator app and the passkey preference.</summary>
    internal static string GetReason(UserTwoFactorData data, PluginConfiguration config, bool isAdmin)
    {
        if (config.ShouldEnforceFor(isAdmin)) return "scope";
        if (data.TotpEnabled && data.TotpVerified) return "authenticator";
        if (data.Passkeys.Count > 0 && data.PasskeyRequiresSecondFactor) return "passkey";
        return "none";
    }
}

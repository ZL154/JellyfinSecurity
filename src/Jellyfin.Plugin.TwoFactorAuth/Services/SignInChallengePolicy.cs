using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Decides whether local sign-in needs a challenge, independently of
/// which enrolled methods can answer that challenge.</summary>
internal static class SignInChallengePolicy
{
    internal static bool RequiresChallenge(
        UserTwoFactorData data, PluginConfiguration config, bool isAdmin, bool accountPasswordSignInUnavailable)
        => GetReason(data, config, isAdmin, accountPasswordSignInUnavailable) != "none";

    /// <summary>Returns the effective reason, with mandatory scope first,
    /// followed by the authenticator app and the passkey preference.</summary>
    internal static string GetReason(
        UserTwoFactorData data, PluginConfiguration config, bool isAdmin, bool accountPasswordSignInUnavailable)
    {
        if (config.ShouldEnforceFor(isAdmin)) return "scope";
        if (data.TotpEnabled && data.TotpVerified) return "authenticator";
        if (PasskeyPolicy.HasUsable(data, config) && data.PasskeyRequiresSecondFactor)
        {
            if (accountPasswordSignInUnavailable) return data.ForceRecoveryOnNextLogin ? "recovery" : "none";
            return "passkey";
        }

        return "none";
    }
}

using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#345] Methods that can answer a local sign-in challenge. Enrollment
/// and the passkey turn-off guard use this same inventory. Linked providers and
/// device bypasses cannot answer a local challenge and do not belong here.</summary>
internal static class SignInFactors
{
    internal static List<string> ForChallenge(UserTwoFactorData data, PluginConfiguration config, out bool enrollmentRequired)
    {
        var methods = GetMethods(data, config);
        enrollmentRequired = methods.Count == 0 && !data.ForceRecoveryOnNextLogin;
        // Recovery mode must never fall back to unproven enrollment, even if
        // the user has no codes left and needs an administrator to reset 2FA.
        if (methods.Count == 0) methods.Add(enrollmentRequired ? "enroll" : "recovery");
        return methods;
    }

    internal static List<string> GetMethods(UserTwoFactorData data, PluginConfiguration config)
    {
        var methods = new List<string>();
        if (!data.ForceRecoveryOnNextLogin)
        {
            if (data.TotpEnabled && data.TotpVerified) methods.Add("totp");
            if (PasskeyPolicy.HasEnrolled(data, config)) methods.Add("passkey");
        }
        if (config.EmailOtpEnabled
            && (!string.IsNullOrEmpty(config.GetUserEmail(data.UserId.ToString("N")))
                || !string.IsNullOrEmpty(data.TelegramChatId)))
            methods.Add("email");
        if (data.RecoveryCodes.Any(c => !c.Used)) methods.Add("recovery");
        return methods;
    }
}

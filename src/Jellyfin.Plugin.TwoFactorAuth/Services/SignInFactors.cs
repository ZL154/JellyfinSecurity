using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#345] Methods that can answer a local sign-in challenge. With
/// passkeys off, the provider, the middleware and the portal all offer
/// <see cref="GetMethods"/>, the same inventory the passkey turn-off guard
/// checks, so an account the guard let through can always answer. With passkeys
/// on, each entry point keeps the offers it had before this setting existed
/// (<c>LegacyChallenge</c>). Linked providers and device bypasses cannot answer
/// a local challenge and do not belong here.</summary>
internal static class SignInFactors
{
    internal enum Entry { Provider, Middleware, Portal }

    internal static List<string> ForChallenge(
        UserTwoFactorData data, PluginConfiguration config, Entry entry, bool enforced, out bool enrollmentRequired)
    {
        if (config.PasskeysEnabled) return LegacyChallenge(data, config, entry, enforced, out enrollmentRequired);
        var methods = GetMethods(data, config);
        enrollmentRequired = methods.Count == 0 && !data.ForceRecoveryOnNextLogin;
        // Recovery mode must never fall back to unproven enrollment, even if
        // the user has no codes left and needs an administrator to reset 2FA.
        if (methods.Count == 0) methods.Add(enrollmentRequired ? "enroll" : "recovery");
        return methods;
    }

    // [#345] Preserve each entry point's existing offers while passkeys are on.
    // Normalizing unrelated legacy differences would change upgraded servers.
    private static List<string> LegacyChallenge(
        UserTwoFactorData data, PluginConfiguration config, Entry entry, bool enforced, out bool enrollmentRequired)
    {
        var hasPasskey = PasskeyPolicy.HasUsable(data, config);
        var hasDelivery = config.EmailOtpEnabled
            && !string.IsNullOrEmpty(config.GetUserEmail(data.UserId.ToString("N")));
        enrollmentRequired = entry == Entry.Portal
            ? !hasPasskey && !hasDelivery
            : enforced && !data.TotpVerified && !hasPasskey && !hasDelivery;
        var methods = new List<string>();
        if (enrollmentRequired)
        {
            methods.Add("enroll");
            return methods;
        }
        if (entry == Entry.Portal)
        {
            if (hasPasskey) methods.Add("passkey");
            if (config.EmailOtpEnabled) methods.Add("email");
            if (methods.Count == 0)
            {
                methods.Add("enroll");
                enrollmentRequired = true;
            }
            return methods;
        }
        if (entry == Entry.Middleware && data.ForceRecoveryOnNextLogin)
        {
            methods.Add("recovery");
            if (config.EmailOtpEnabled) methods.Add("email");
            return methods;
        }
        if (data.TotpVerified && (entry == Entry.Middleware || data.TotpEnabled)) methods.Add("totp");
        if (entry == Entry.Middleware && hasPasskey) methods.Add("passkey");
        if (entry == Entry.Provider && data.RecoveryCodes.Any(c => !c.Used)) methods.Add("recovery");
        if (config.EmailOtpEnabled) methods.Add("email");
        if (entry == Entry.Middleware && data.RecoveryCodes.Any(c => !c.Used)) methods.Add("recovery");
        if (methods.Count == 0) methods.Add("email");
        return methods;
    }

    internal static List<string> GetMethods(UserTwoFactorData data, PluginConfiguration config)
    {
        var methods = new List<string>();
        if (!data.ForceRecoveryOnNextLogin)
        {
            if (data.TotpEnabled && data.TotpVerified) methods.Add("totp");
            if (PasskeyPolicy.HasUsable(data, config)) methods.Add("passkey");
        }
        if (config.EmailOtpEnabled
            && (!string.IsNullOrEmpty(config.GetUserEmail(data.UserId.ToString("N")))
                || !string.IsNullOrEmpty(data.TelegramChatId)))
            methods.Add("email");
        if (data.RecoveryCodes.Any(c => !c.Used)) methods.Add("recovery");
        return methods;
    }
}

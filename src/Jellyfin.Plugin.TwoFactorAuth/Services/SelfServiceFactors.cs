using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#248] The factors a self-service step-up can verify: a confirmed
/// authenticator app, a passkey, a linked identity provider (re-authenticated
/// with prompt=login), or the email code when the server allows it and the
/// account has an address on file, which is what sign-in checks for the email
/// factor. The step-up gate, disabling 2FA and app password creation share this
/// list, so any factor that can confirm a change can also back an app password.
/// Creation used to accept only the authenticator app, which left accounts that
/// sign in through SSO, or with a passkey, no way to create one.
/// <see cref="UserTwoFactorData.EmailOtpPreferred"/> still counts for data that
/// has it set, but the plugin itself never sets it.</summary>
internal static class SelfServiceFactors
{
    internal static bool HasAny(UserTwoFactorData data, PluginConfiguration config)
        => (data.TotpEnabled && data.TotpVerified)
           || data.Passkeys.Count > 0
           || data.SsoLinks.Count > 0
           || (config.EmailOtpEnabled
               && (data.EmailOtpPreferred || !string.IsNullOrEmpty(config.GetUserEmail(data.UserId.ToString("N")))));
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#213] A passkey sign-in, an app password and the OIDC bridge move an account
/// onto <see cref="TwoFactorAuthProvider"/>, and nothing ever moved it back. Once
/// the plugin was gone, Jellyfin put every such account on its InvalidAuthProvider
/// and refused all of its sign-ins, administrators included. Uninstalling now
/// hands those accounts back to the provider this plugin was passing their
/// password checks to, so they sign in exactly as they did while it was
/// installed. A plugin that fails to load runs none of this; the README
/// recovery section covers that case.
/// </summary>
public static class SignInProviderRestore
{
    /// <summary>
    /// Only used when no other provider is registered, which Jellyfin never
    /// ships: the id Jellyfin stores for its own password provider.
    /// </summary>
    internal const string JellyfinDefaultProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    /// <summary>Jellyfin stores a provider's full type name as its id.</summary>
    internal static string PluginProviderId => typeof(TwoFactorAuthProvider).FullName!;

    /// <summary>Called from <see cref="Plugin.OnUninstalling"/>. Never throws.</summary>
    public static void RestoreOnUninstall(IApplicationHost appHost, ILogger logger)
    {
        try
        {
            var userManager = appHost.Resolve<IUserManager>();
            var target = PasswordProviderId(appHost.GetExports<IAuthenticationProvider>(false));
            // Materialised first: saving an account while enumerating
            // Jellyfin's user collection would modify it underneath us.
            var users = UserEnumeration.All(userManager).ToList();
            var restored = RestoreAsync(users, target, user => userManager.UpdateUserAsync(user), logger)
                .GetAwaiter().GetResult();
            logger.LogInformation("[2FA] Uninstall: {Count} account(s) handed back to {Provider}", restored, target);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "[2FA] Uninstall: could not hand accounts back from TwoFactorAuthProvider; they cannot sign in until they are moved back (README, Recovery)");
        }
    }

    /// <summary>
    /// The provider <see cref="TwoFactorAuthProvider"/> hands a password check
    /// to: the first enabled one that is not this plugin's. The same rule, so an
    /// account moved back keeps signing in against the same credentials.
    /// </summary>
    internal static string PasswordProviderId(IEnumerable<IAuthenticationProvider> providers)
        => providers.FirstOrDefault(p => p is not TwoFactorAuthProvider && p.IsEnabled)?.GetType().FullName
            ?? JellyfinDefaultProviderId;

    /// <summary>
    /// Moves every account on this plugin's provider to <paramref name="targetProviderId"/>
    /// and returns how many were saved. One failed save neither stops the others
    /// nor leaves that account half-changed in memory.
    /// </summary>
    internal static async Task<int> RestoreAsync(
        IEnumerable<User> users,
        string targetProviderId,
        Func<User, Task> save,
        ILogger logger)
    {
        var restored = 0;
        foreach (var user in users)
        {
            if (!string.Equals(user.AuthenticationProviderId, PluginProviderId, StringComparison.Ordinal))
            {
                continue;
            }

            user.AuthenticationProviderId = targetProviderId;
            try
            {
                await save(user).ConfigureAwait(false);
                restored++;
                logger.LogInformation("[2FA] Uninstall: {User} moved back to {Provider}", user.Username, targetProviderId);
            }
            catch (Exception ex)
            {
                user.AuthenticationProviderId = PluginProviderId;
                logger.LogError(ex, "[2FA] Uninstall: could not move {User} back to {Provider}", user.Username, targetProviderId);
            }
        }

        return restored;
    }
}

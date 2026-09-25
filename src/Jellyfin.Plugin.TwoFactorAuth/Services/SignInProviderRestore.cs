using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#213] A passkey sign-in, an app password and the OIDC bridge move an account
/// onto <see cref="TwoFactorAuthProvider"/>, and nothing ever moved it back. Once
/// the plugin was gone, Jellyfin put every such account on its InvalidAuthProvider
/// and refused all of its sign-ins, administrators included. Uninstalling the
/// plugin, or disabling it in Jellyfin's dashboard, now hands those accounts back
/// to the provider this plugin was passing their password checks to, so they sign
/// in exactly as they did while it was running, and lists them in the plugin's
/// data folder, which neither action touches. The next start with the plugin
/// loaded, after a reinstall or after enabling it again, moves the listed
/// accounts back onto <see cref="TwoFactorAuthProvider"/>; without that, their
/// app passwords would fail until each account created a new one. A plugin that
/// fails to load runs none of this; the README recovery section covers that case.
/// </summary>
public static class SignInProviderRestore
{
    /// <summary>
    /// Only used when no other provider is registered, which Jellyfin never
    /// ships: the id Jellyfin stores for its own password provider.
    /// </summary>
    internal const string JellyfinDefaultProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    /// <summary>The accounts handed back that the plugin has yet to take back.</summary>
    internal const string RecordFileName = "handed-back.json";

    private static readonly JsonSerializerOptions RecordJsonOptions = new() { WriteIndented = true };

    /// <summary>Jellyfin stores a provider's full type name as its id.</summary>
    internal static string PluginProviderId => typeof(TwoFactorAuthProvider).FullName!;

    /// <summary>Beside the rest of the plugin's data, which an uninstall does not delete.</summary>
    internal static string RecordPath(IApplicationPaths paths)
        => Path.Combine(paths.PluginConfigurationsPath, "TwoFactorAuth", RecordFileName);

    /// <summary>Called from <see cref="Plugin.OnUninstalling"/>, which is synchronous. Never throws.</summary>
    public static void RestoreOnUninstall(IApplicationHost appHost, IApplicationPaths paths, ILogger logger)
        => HandBackAsync(appHost, paths, "Uninstall", logger).GetAwaiter().GetResult();

    /// <summary>
    /// Hands every account on this plugin's provider back to the provider it
    /// passes password checks to, and lists them for <see cref="ReclaimAtStartAsync"/>.
    /// <paramref name="reason"/> only labels the log lines. Never throws.
    /// </summary>
    internal static async Task HandBackAsync(IApplicationHost appHost, IApplicationPaths paths, string reason, ILogger logger)
    {
        try
        {
            var userManager = appHost.Resolve<IUserManager>();
            var target = DelegateProviderId(appHost.GetExports<IAuthenticationProvider>(false));
            // Materialised first: saving an account while enumerating
            // Jellyfin's user collection would modify it underneath us.
            var users = UserEnumeration.All(userManager).ToList();
            var handedBack = await RestoreAsync(users, target, user => userManager.UpdateUserAsync(user), reason, logger)
                .ConfigureAwait(false);
            logger.LogInformation("[2FA] {Reason}: {Count} account(s) handed back to {Provider}", reason, handedBack.Count, target);
            ListHandedBack(RecordPath(paths), target, handedBack, reason, logger);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "[2FA] {Reason}: could not hand accounts back from TwoFactorAuthProvider; they cannot sign in without the plugin until they are moved back (README, Recovery)",
                reason);
        }
    }

    /// <summary>
    /// Called from <see cref="SignInProviderReclaimService"/> at every start; a
    /// no-op unless an uninstall or a disable left a list behind. Never throws.
    /// </summary>
    public static async Task ReclaimAtStartAsync(IUserManager userManager, IApplicationPaths paths, ILogger logger)
    {
        var path = RecordPath(paths);
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var pending = ReadPending(path, logger);
            var remaining = await ReclaimAsync(pending, userManager.GetUserById, user => userManager.UpdateUserAsync(user), logger)
                .ConfigureAwait(false);
            WritePending(path, remaining);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "[2FA] Start: could not move the accounts listed in {Path} back to TwoFactorAuthProvider; trying again at the next start",
                path);
        }
    }

    /// <summary>
    /// The provider <see cref="TwoFactorAuthProvider"/> hands a password check
    /// to: the first enabled one that is not this plugin's. The same rule, so an
    /// account moved back keeps signing in against the same credentials.
    /// </summary>
    internal static string DelegateProviderId(IEnumerable<IAuthenticationProvider> providers)
        => providers.FirstOrDefault(p => p is not TwoFactorAuthProvider && p.IsEnabled)?.GetType().FullName
            ?? JellyfinDefaultProviderId;

    /// <summary>
    /// Moves every account on this plugin's provider to <paramref name="targetProviderId"/>
    /// and returns the ones that were saved. One failed save neither stops the
    /// others nor leaves that account half-changed in memory. Provider ids are
    /// matched ignoring case, as Jellyfin matches them.
    /// </summary>
    internal static async Task<IReadOnlyList<User>> RestoreAsync(
        IEnumerable<User> users,
        string targetProviderId,
        Func<User, Task> save,
        string reason,
        ILogger logger)
    {
        var handedBack = new List<User>();
        foreach (var user in users)
        {
            if (!string.Equals(user.AuthenticationProviderId, PluginProviderId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var previous = user.AuthenticationProviderId;
            user.AuthenticationProviderId = targetProviderId;
            try
            {
                await save(user).ConfigureAwait(false);
                handedBack.Add(user);
                logger.LogInformation("[2FA] {Reason}: {User} moved back to {Provider}", reason, user.Username, targetProviderId);
            }
            catch (Exception ex)
            {
                user.AuthenticationProviderId = previous;
                logger.LogError(ex, "[2FA] {Reason}: could not move {User} back to {Provider}", reason, user.Username, targetProviderId);
            }
        }

        return handedBack;
    }

    /// <summary>
    /// Moves each listed account back onto this plugin's provider, but only
    /// while it is still on the provider it was handed back to: an account
    /// someone moved elsewhere since is left alone, and one deleted since is
    /// dropped. Returns the entries whose save failed, to try again at the next
    /// start.
    /// </summary>
    internal static async Task<List<HandedBackAccount>> ReclaimAsync(
        IEnumerable<HandedBackAccount> pending,
        Func<Guid, User?> findUser,
        Func<User, Task> save,
        ILogger logger)
    {
        var remaining = new List<HandedBackAccount>();
        var reclaimed = 0;
        foreach (var entry in pending)
        {
            var user = findUser(entry.UserId);
            if (user is null)
            {
                logger.LogInformation("[2FA] Start: account {UserId} no longer exists", entry.UserId);
                continue;
            }

            if (!string.Equals(user.AuthenticationProviderId, entry.Provider, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogInformation(
                    "[2FA] Start: {User} is on {Current} now, not {Provider}; left there",
                    user.Username,
                    user.AuthenticationProviderId,
                    entry.Provider);
                continue;
            }

            var previous = user.AuthenticationProviderId;
            user.AuthenticationProviderId = PluginProviderId;
            try
            {
                await save(user).ConfigureAwait(false);
                reclaimed++;
                logger.LogInformation("[2FA] Start: {User} moved back to TwoFactorAuthProvider", user.Username);
            }
            catch (Exception ex)
            {
                user.AuthenticationProviderId = previous;
                remaining.Add(entry);
                logger.LogError(
                    ex,
                    "[2FA] Start: could not move {User} back to TwoFactorAuthProvider; trying again at the next start",
                    user.Username);
            }
        }

        if (reclaimed > 0)
        {
            logger.LogInformation("[2FA] Start: {Count} handed-back account(s) taken back", reclaimed);
        }

        return remaining;
    }

    /// <summary>
    /// The listed accounts, or none. A list that is not valid JSON is logged
    /// and treated as empty, so the next write replaces it; any other error
    /// propagates and leaves the file alone.
    /// </summary>
    internal static List<HandedBackAccount> ReadPending(string path, ILogger logger)
    {
        if (!File.Exists(path))
        {
            return new List<HandedBackAccount>();
        }

        try
        {
            var entries = JsonSerializer.Deserialize<List<HandedBackAccount>>(File.ReadAllText(path));
            return (entries ?? new List<HandedBackAccount>())
                .Where(e => e is not null && e.UserId != Guid.Empty && !string.IsNullOrEmpty(e.Provider))
                .ToList();
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "[2FA] {Path} is not a valid list of accounts; ignoring it", path);
            return new List<HandedBackAccount>();
        }
    }

    /// <summary>Writes the list through a temporary file, or deletes it once it is empty.</summary>
    internal static void WritePending(string path, IReadOnlyCollection<HandedBackAccount> pending)
    {
        if (pending.Count == 0)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(pending, RecordJsonOptions));
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>
    /// Adds the accounts just handed back to the list, keeping any an earlier
    /// hand-back left there that the plugin has not taken back yet.
    /// </summary>
    private static void ListHandedBack(string path, string targetProviderId, IReadOnlyList<User> handedBack, string reason, ILogger logger)
    {
        if (handedBack.Count == 0)
        {
            return;
        }

        try
        {
            var pending = ReadPending(path, logger);
            foreach (var user in handedBack)
            {
                pending.RemoveAll(e => e.UserId == user.Id);
                pending.Add(new HandedBackAccount { UserId = user.Id, Provider = targetProviderId });
            }

            WritePending(path, pending);
            logger.LogInformation("[2FA] {Reason}: listed them in {Path}; the plugin's next start moves them back", reason, path);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "[2FA] {Reason}: could not list the accounts handed back in {Path}; once the plugin runs again, their app passwords only work after each account creates a new one",
                reason,
                path);
        }
    }
}

/// <summary>An account handed back, and the provider it was handed back to.</summary>
internal sealed class HandedBackAccount
{
    public Guid UserId { get; set; }

    public string Provider { get; set; } = string.Empty;
}

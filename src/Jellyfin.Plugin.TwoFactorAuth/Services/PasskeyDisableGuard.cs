using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#345] Refuse the enabled-to-disabled transition before any write
/// while a live user relies on a stored passkey for their second factor.</summary>
public sealed class PasskeyDisableGuard
{
    private readonly UserTwoFactorStore _store;
    private readonly Func<Guid, PasskeyAccount?> _accountFor;

    public PasskeyDisableGuard(UserTwoFactorStore store, IUserManager users)
        : this(store, id => users.GetUserById(id) is { } user
            ? new PasskeyAccount(user.Username, user.HasPermission(PermissionKind.IsAdministrator))
            : null)
    {
    }

    internal PasskeyDisableGuard(UserTwoFactorStore store, Func<Guid, PasskeyAccount?> accountFor)
    {
        _store = store;
        _accountFor = accountFor;
    }

    internal async Task EnsureCanApplyAsync(
        PluginConfiguration current,
        PluginConfiguration incoming,
        IReadOnlyList<UserTwoFactorData>? replacements = null)
    {
        if (!current.PasskeysEnabled || incoming.PasskeysEnabled) return;

        var rows = (await _store.GetAllUsersAsync().ConfigureAwait(false)).ToDictionary(d => d.UserId);
        // A full import replaces these records after applying its configuration.
        // Check that effective state before either part of the import is written.
        if (replacements is not null)
            foreach (var row in replacements) rows[row.UserId] = row;

        var dependents = new List<PasskeyDependent>();
        foreach (var row in rows.Values)
        {
            if (row.Passkeys.Count == 0) continue;
            // Deleted Jellyfin users have no account to migrate or reset.
            if (_accountFor(row.UserId) is not { } account) continue;
            if (ReliesOnPasskeys(row, incoming, account.IsAdmin)) dependents.Add(new PasskeyDependent(row.UserId, account.Name));
        }
        if (dependents.Count == 0) return;
        var sorted = dependents.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(d => d.Name, StringComparer.Ordinal).ThenBy(d => d.Id).ToArray();
        throw new PasskeyDisableException(sorted);
    }

    /// <summary>Whether a user with stored passkeys would lose part of their
    /// protection once <paramref name="incoming"/> (passkeys off) applies. Any
    /// one of these is enough: nothing left that answers the sign-in challenge;
    /// the passkey, through the user's choice, was the only reason password
    /// sign-in asked for a second factor (an email code or a recovery code can
    /// answer the challenge, but neither makes it required); or the passkey was
    /// the only factor that makes the self-service step-up ask for proof, so
    /// changes to the account would stop needing it. Opted-out passkeys count
    /// too: turning passkeys off must not silently leave such an account
    /// without any factor. Each test is the rule the plugin itself applies,
    /// never a copy.</summary>
    internal static bool ReliesOnPasskeys(UserTwoFactorData row, PluginConfiguration incoming, bool isAdmin)
        => SignInFactors.GetMethods(row, incoming).Count == 0
           || (row.PasskeyRequiresSecondFactor && !SignInChallengePolicy.RequiresChallenge(row, incoming, isAdmin))
           || !SelfServiceFactors.HasAny(row, incoming);
}

/// <summary>[#345] The Jellyfin account behind stored 2FA data: its name for
/// the refusal, and whether the enforcement scope treats it as an administrator.</summary>
internal readonly record struct PasskeyAccount(string Name, bool IsAdmin);

internal sealed record PasskeyDependent(Guid Id, string Name);

internal sealed class PasskeyDisableException : InvalidOperationException
{
    internal PasskeyDisableException(IReadOnlyList<PasskeyDependent> users)
        : base("Passkeys cannot be disabled because these users rely on a passkey for their second factor: "
            + string.Join(", ", users.Select(u => u.Name))
            + ". Have them add an authenticator app while passkeys are still enabled, or use \"Reset 2FA (full wipe)\" in the Users tab.")
    {
        Users = users;
    }

    private IReadOnlyList<PasskeyDependent> Users { get; }

    internal object ToResponse() => new
    {
        message = Message,
        users = Users.Select(u => new { id = u.Id, name = u.Name }),
    };
}

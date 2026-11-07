using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>[#345] Refuse the enabled-to-disabled transition before any write
/// if a live user would lose their only way to answer a sign-in challenge.</summary>
public sealed class PasskeyDisableGuard
{
    private readonly UserTwoFactorStore _store;
    private readonly Func<Guid, string?> _nameFor;

    public PasskeyDisableGuard(UserTwoFactorStore store, IUserManager users)
        : this(store, id => users.GetUserById(id)?.Username)
    {
    }

    internal PasskeyDisableGuard(UserTwoFactorStore store, Func<Guid, string?> nameFor)
    {
        _store = store;
        _nameFor = nameFor;
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
            // Stored credentials deliberately count here, including opted-out ones.
            if (row.Passkeys.Count == 0 || SignInFactors.GetMethods(row, incoming).Count > 0) continue;
            var name = _nameFor(row.UserId);
            // Deleted Jellyfin users have no account to migrate or reset.
            if (name is not null) dependents.Add(new PasskeyDependent(row.UserId, name));
        }
        if (dependents.Count == 0) return;
        var sorted = dependents.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(d => d.Name, StringComparer.Ordinal).ThenBy(d => d.Id).ToArray();
        throw new PasskeyDisableException(sorted);
    }
}

internal sealed record PasskeyDependent(Guid Id, string Name);

internal sealed class PasskeyDisableException : InvalidOperationException
{
    internal PasskeyDisableException(IReadOnlyList<PasskeyDependent> users)
        : base("Passkeys cannot be disabled because these users have no other sign-in verification method: "
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

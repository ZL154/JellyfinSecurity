using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Account links hold subjects from the identity provider a slug pointed at
/// when they were made, and a <c>sub</c> is only unique within that provider.
/// When a slug stops pointing there, its links are retired rather than
/// deleted: they stop matching tokens, but they still block the email and
/// username fallbacks from attaching a different identity to the account.
/// Retiring is idempotent and runs before the new settings are saved, so an
/// interrupted save can simply be repeated.
/// </summary>
internal static class OidcLinkRetirement
{
    /// <summary>Slugs whose identity provider may differ between two
    /// provider lists: added, removed, or with a different discovery URL.</summary>
    public static IReadOnlyList<string> ChangedProviderIds(
        IEnumerable<OidcProvider> before, IEnumerable<OidcProvider> after)
    {
        var old = before.GroupBy(p => p.Id, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().DiscoveryUrl, StringComparer.Ordinal);
        var @new = after.GroupBy(p => p.Id, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().DiscoveryUrl, StringComparer.Ordinal);
        return old.Keys.Union(@new.Keys, StringComparer.Ordinal)
            .Where(id => !old.TryGetValue(id, out var o)
                || !@new.TryGetValue(id, out var n)
                || !OidcService.SameDiscoveryUrl(o, n))
            .ToList();
    }

    /// <summary>Retire every active link under the given slugs. Returns, per
    /// user changed, how many links were retired.</summary>
    public static async Task<IReadOnlyDictionary<Guid, int>> RetireAsync(
        UserTwoFactorStore store, IReadOnlyCollection<string> providerIds, string reason)
    {
        var changed = new Dictionary<Guid, int>();
        if (providerIds.Count == 0) return changed;
        var ids = new HashSet<string>(providerIds, StringComparer.Ordinal);
        var users = await store.GetAllUsersAsync().ConfigureAwait(false);
        foreach (var u in users)
        {
            if (!u.SsoLinks.Any(l => l.RetiredAt is null && ids.Contains(l.ProviderId)))
            {
                continue;
            }

            var retired = 0;
            await store.MutateAsync(u.UserId, ud => retired = Retire(ud, ids, reason, DateTime.UtcNow)).ConfigureAwait(false);
            if (retired > 0) changed[u.UserId] = retired;
        }

        return changed;
    }

    internal static int Retire(UserTwoFactorData data, ISet<string> providerIds, string reason, DateTime now)
    {
        var count = 0;
        foreach (var link in data.SsoLinks)
        {
            if (link.RetiredAt is null && providerIds.Contains(link.ProviderId))
            {
                link.RetiredAt = now;
                link.RetiredReason = reason;
                count++;
            }
        }

        return count;
    }

    /// <summary>Give every row that predates <see cref="SsoLink.Id"/> an id.
    /// Returns whether anything changed.</summary>
    internal static bool EnsureLinkIds(UserTwoFactorData data)
    {
        var changed = false;
        foreach (var link in data.SsoLinks)
        {
            if (string.IsNullOrEmpty(link.Id))
            {
                link.Id = NewLinkId();
                changed = true;
            }
        }

        return changed;
    }

    internal static string NewLinkId() => Guid.NewGuid().ToString("N");
}

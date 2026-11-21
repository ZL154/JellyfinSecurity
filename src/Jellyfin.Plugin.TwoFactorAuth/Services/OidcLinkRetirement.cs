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
    /// <param name="spare">Rows to leave alone, e.g. rows a rename already
    /// moved here.</param>
    public static async Task<IReadOnlyDictionary<Guid, int>> RetireAsync(
        UserTwoFactorStore store, IReadOnlyCollection<string> providerIds, string reason, Func<SsoLink, bool>? spare = null)
    {
        var changed = new Dictionary<Guid, int>();
        if (providerIds.Count == 0) return changed;
        var ids = new HashSet<string>(providerIds, StringComparer.Ordinal);
        var users = await store.GetAllUsersAsync().ConfigureAwait(false);
        foreach (var u in users)
        {
            if (!u.SsoLinks.Any(l => !l.IsRetired && ids.Contains(l.ProviderId) && spare?.Invoke(l) != true))
            {
                continue;
            }

            var retired = 0;
            await store.MutateAsync(u.UserId, ud => retired = Retire(ud, ids, reason, DateTime.UtcNow, spare)).ConfigureAwait(false);
            if (retired > 0) changed[u.UserId] = retired;
        }

        return changed;
    }

    internal static int Retire(UserTwoFactorData data, ISet<string> providerIds, string reason, DateTime now, Func<SsoLink, bool>? spare = null)
    {
        var count = 0;
        foreach (var link in data.SsoLinks)
        {
            if (!link.IsRetired && providerIds.Contains(link.ProviderId) && spare?.Invoke(link) != true)
            {
                link.RetiredAt = now;
                link.RetiredReason = reason;
                // An active link never carries the prefix (tokens with such a
                // sub are refused), so this always marks the row.
                link.Subject = SsoLink.RetiredSubjectPrefix + link.Subject;
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

    /// <summary>Bring links to one form when a file is read.
    /// <list type="bullet">
    /// <item>A row with missing fields (an older model writes nulls) gets empty
    /// strings; a row without a subject or provider can never match a token,
    /// so it is retired and shown for removal.</item>
    /// <item>A row with a retirement time gets the current subject prefix,
    /// replacing the ASCII one pre-release builds used, so the marker survives
    /// a rewrite by a version that drops <see cref="SsoLink.RetiredAt"/>.</item>
    /// </list>
    /// The change reaches disk with the user's next write.</summary>
    internal static void NormalizeRetired(UserTwoFactorData data)
    {
        data.SsoLinks ??= new List<SsoLink>();
        data.SsoLinks.RemoveAll(l => l is null);
        foreach (var link in data.SsoLinks)
        {
            link.Id ??= string.Empty;
            link.ProviderId ??= string.Empty;
            link.Subject ??= string.Empty;
            link.Issuer ??= string.Empty;
            link.Email ??= string.Empty;
            link.RetiredReason ??= string.Empty;
            link.RenamedFrom ??= string.Empty;
            link.RenamedWithDiscoveryUrl ??= string.Empty;

            if (!link.IsRetired && (link.Subject.Length == 0 || link.ProviderId.Length == 0))
            {
                link.RetiredAt = DateTime.UtcNow;
                link.RetiredReason = "invalid stored link";
            }

            if (link.RetiredAt is not null
                && !link.Subject.StartsWith(SsoLink.RetiredSubjectPrefix, StringComparison.Ordinal))
            {
                var subject = link.Subject.StartsWith(SsoLink.LegacyRetiredSubjectPrefix, StringComparison.Ordinal)
                    ? link.Subject[SsoLink.LegacyRetiredSubjectPrefix.Length..]
                    : link.Subject;
                link.Subject = SsoLink.RetiredSubjectPrefix + subject;
            }
        }
    }

    /// <summary>The subject as the IdP issued it, without the retired prefix.</summary>
    internal static string DisplaySubject(SsoLink link)
        => link.Subject.StartsWith(SsoLink.RetiredSubjectPrefix, StringComparison.Ordinal)
            ? link.Subject[SsoLink.RetiredSubjectPrefix.Length..]
            : link.Subject;
}

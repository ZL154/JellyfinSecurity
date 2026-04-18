using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Maintains a per-user "seen contexts" set (ASN + country) and fires a
/// notification on the first sign-in from a context not previously observed.
///
/// Scope decision (v1.4): notify only — no in-flight Deny link in the email.
/// The user will already be prompted for their 2FA code; an attacker who
/// stole the password is still gated by the second factor. The Deny flow
/// races the challenge expiry and is a v1.5 problem.
/// </summary>
public class SuspiciousLoginDetector
{
    private readonly UserTwoFactorStore _store;
    private readonly GeoIpService _geo;
    private readonly NotificationService _notifications;
    private readonly ILogger<SuspiciousLoginDetector> _logger;

    public SuspiciousLoginDetector(
        UserTwoFactorStore store,
        GeoIpService geo,
        NotificationService notifications,
        ILogger<SuspiciousLoginDetector> logger)
    {
        _store = store;
        _geo = geo;
        _notifications = notifications;
        _logger = logger;
    }

    /// <summary>Record this sign-in's context. If first-seen, fire-and-forget
    /// a notification. Returns true when novel.</summary>
    public async Task<bool> ObserveAsync(Guid userId, string username, string? ip)
    {
        if (userId == Guid.Empty) return false;
        if (!_geo.AsnAvailable && !_geo.CountryAvailable) return false;

        var lookup = _geo.Resolve(ip);
        if (lookup.Asn == 0 && string.IsNullOrEmpty(lookup.Country)) return false;

        bool novel = false;
        await _store.MutateAsync(userId, ud =>
        {
            var existing = ud.SeenContexts.FirstOrDefault(c =>
                c.Asn == lookup.Asn
                && string.Equals(c.Country, lookup.Country, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                novel = true;
                ud.SeenContexts.Add(new SeenContext
                {
                    Asn = lookup.Asn,
                    Country = lookup.Country,
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    RequestCount = 1,
                });
                // Bound the per-user list — keep most recent 100. Beyond that
                // every login is "novel" and the alert becomes useless noise.
                if (ud.SeenContexts.Count > 100)
                {
                    var trimmed = ud.SeenContexts.OrderByDescending(c => c.LastSeen).Take(100).ToList();
                    ud.SeenContexts.Clear();
                    ud.SeenContexts.AddRange(trimmed);
                }
            }
            else
            {
                existing.LastSeen = DateTime.UtcNow;
                existing.RequestCount++;
            }
        }).ConfigureAwait(false);

        if (novel)
        {
            // Fire-and-forget — never block the auth path on notification I/O.
            _ = Task.Run(async () =>
            {
                try
                {
                    await _notifications.NotifySuspiciousLoginAsync(
                        username, ip ?? "unknown", lookup.Country, lookup.AsnOrg, lookup.Asn)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[2FA] Suspicious-login notification failed");
                }
            });
        }

        return novel;
    }
}

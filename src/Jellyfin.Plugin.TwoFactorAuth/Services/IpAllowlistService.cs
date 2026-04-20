using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Per-user IP allowlist enforcement. When a user has any CIDRs in
/// their `IpAllowlistCidrs` list, sign-in attempts from any IP NOT in that
/// list are refused — used to lock high-value accounts (admin) to a known
/// home/office IP. Empty list = no restriction (default).</summary>
public class IpAllowlistService
{
    private readonly UserTwoFactorStore _store;
    private readonly ILogger<IpAllowlistService> _logger;

    public IpAllowlistService(UserTwoFactorStore store, ILogger<IpAllowlistService> logger)
    {
        _store = store;
        _logger = logger;
    }

    /// <summary>Returns true if the IP is allowed for this user. Trusted-proxy
    /// IPs always allowed (the proxy itself isn't the real client). Users
    /// with an empty allowlist always allowed.</summary>
    public async Task<bool> IsAllowedAsync(Guid userId, string? ip)
    {
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (data.IpAllowlistCidrs.Count == 0) return true;
        if (string.IsNullOrEmpty(ip)) return false;

        foreach (var cidr in data.IpAllowlistCidrs)
        {
            if (BypassEvaluator.IsIpInCidr(ip, cidr)) return true;
        }
        _logger.LogWarning("[2FA] User {UserId} sign-in refused: IP {Ip} not in allowlist", userId, ip);
        return false;
    }
}

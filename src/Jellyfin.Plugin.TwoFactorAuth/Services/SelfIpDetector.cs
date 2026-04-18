using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Discovers the server's own public IP at startup so the bypass evaluator
/// can treat hairpinned requests (LAN client → router WAN → back in) as if
/// they came from LAN. Off by default — admins enable knowing the tradeoff
/// (anyone sharing the same WAN egress, including IoT/guest WiFi, also
/// bypasses).
///
/// One-shot at startup, no retries, no auto-refresh on dynamic-IP changes —
/// admins restart Jellyfin if the WAN IP changes. Public IP is exposed via
/// the static <see cref="SelfPublicIp"/> for BypassEvaluator to read at
/// per-request time without a DI dependency.
/// </summary>
public class SelfIpDetector : IHostedService
{
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly ILogger<SelfIpDetector> _logger;

    public static string? SelfPublicIp { get; private set; }

    public SelfIpDetector(ILogger<SelfIpDetector> logger)
    {
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.NatHairpinSelfIpBypass) return;

        try
        {
            using var resp = await _httpClient.GetAsync("https://api.ipify.org?format=text", cancellationToken).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var ip = (await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
            if (!System.Net.IPAddress.TryParse(ip, out var parsed))
            {
                _logger.LogWarning("[2FA] Self-IP discovery returned non-IP body, hairpin bypass inactive");
                return;
            }
            // SEC-M7: refuse to accept loopback / RFC1918 / link-local — if
            // ipify is compromised or replaced via DNS, that would otherwise
            // turn the hairpin bypass into a privilege escalation by trusting
            // every internal IP as "LAN".
            if (System.Net.IPAddress.IsLoopback(parsed) || IsPrivateOrLinkLocal(parsed))
            {
                _logger.LogWarning("[2FA] Self-IP discovery returned non-public address {Ip} — refusing (hairpin bypass inactive)", ip);
                return;
            }
            SelfPublicIp = ip;
            _logger.LogInformation("[2FA] Self-public-IP discovered as {Ip} — hairpin bypass active", ip);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Self-IP discovery failed; hairpin bypass inactive until restart");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static bool IsPrivateOrLinkLocal(System.Net.IPAddress a)
    {
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            if (b[0] == 10) return true;                                     // 10/8
            if (b[0] == 172 && (b[1] & 0xF0) == 16) return true;             // 172.16/12
            if (b[0] == 192 && b[1] == 168) return true;                     // 192.168/16
            if (b[0] == 169 && b[1] == 254) return true;                     // 169.254/16 link-local
            if (b[0] == 0) return true;                                      // 0/8
        }
        else if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = a.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return true;                          // fc00::/7 ULA
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;          // fe80::/10
        }
        return false;
    }
}

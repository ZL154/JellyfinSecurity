using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public record BypassResult(bool IsBypassed, string? Reason)
{
    public static BypassResult Bypassed(string reason) => new(true, reason);
    public static BypassResult NotBypassed => new(false, null);
}

public class BypassEvaluator
{
    private readonly ILogger<BypassEvaluator> _logger;

    public BypassEvaluator(ILogger<BypassEvaluator> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Evaluates whether the incoming request should bypass 2FA. First match wins.
    /// Order: API key -> LAN -> trusted device token -> registered device ID.
    /// </summary>
    public BypassResult Evaluate(
        string? remoteIp,
        string? forwardedFor,
        string? twoFactorToken,
        string? deviceId,
        string? embyToken,
        List<TrustedDevice> trustedDevices,
        List<string> registeredDeviceIds,
        IReadOnlyList<Models.ApiKeyEntry> apiKeys)
    {
        // 1. API key check — compare hashes. Raw key is 256 bits of entropy
        // so a plain SHA-256 suffices (no PBKDF2 cost). Hashing at rest means
        // a leaked user-data directory doesn't hand over live API keys.
        if (!string.IsNullOrWhiteSpace(embyToken))
        {
            var submittedHash = HashApiKey(embyToken);
            foreach (var apiKey in apiKeys)
            {
                var stored = !string.IsNullOrEmpty(apiKey.KeyHash)
                    ? apiKey.KeyHash
                    : (!string.IsNullOrEmpty(apiKey.Key) ? HashApiKey(apiKey.Key) : null);
                if (stored is null) continue;
                if (submittedHash.Length == stored.Length
                    && CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(submittedHash),
                        Encoding.UTF8.GetBytes(stored)))
                {
                    _logger.LogDebug("Bypass granted via API key");
                    return BypassResult.Bypassed("apikey");
                }
            }
        }

        // 2. LAN bypass
        var config = Plugin.Instance?.Configuration;
        if (config is { LanBypassEnabled: true })
        {
            string? ipToCheck = remoteIp;

            if (config.TrustForwardedFor && !string.IsNullOrWhiteSpace(forwardedFor))
            {
                // Verify the direct requester is a trusted proxy before trusting X-Forwarded-For
                var remoteIsTrustedProxy = false;
                if (!string.IsNullOrWhiteSpace(remoteIp))
                {
                    foreach (var proxyCidr in config.TrustedProxyCidrs)
                    {
                        if (IsIpInCidr(remoteIp, proxyCidr))
                        {
                            remoteIsTrustedProxy = true;
                            break;
                        }
                    }
                }

                if (remoteIsTrustedProxy)
                {
                    // Use the first (leftmost) IP from X-Forwarded-For as the real client IP
                    var parts = forwardedFor.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0)
                    {
                        ipToCheck = parts[0];
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(ipToCheck))
            {
                foreach (var cidr in config.LanBypassCidrs)
                {
                    if (IsIpInCidr(ipToCheck, cidr))
                    {
                        _logger.LogDebug("Bypass granted via LAN for IP {Ip}", ipToCheck);
                        return BypassResult.Bypassed("lan");
                    }
                }
                // v1.4 NAT hairpin: discovered self-public-IP also counts as LAN.
                // Loaded once at startup; admins must restart on WAN IP change.
                if (config.NatHairpinSelfIpBypass
                    && !string.IsNullOrEmpty(SelfIpDetector.SelfPublicIp)
                    && string.Equals(ipToCheck, SelfIpDetector.SelfPublicIp, StringComparison.Ordinal))
                {
                    _logger.LogDebug("Bypass granted via NAT hairpin for self-public IP {Ip}", ipToCheck);
                    return BypassResult.Bypassed("hairpin");
                }
            }
        }

        // 3. Trusted device token
        if (!string.IsNullOrWhiteSpace(twoFactorToken) && !string.IsNullOrWhiteSpace(deviceId))
        {
            var submittedHash = DeviceTokenService.HashToken(twoFactorToken);
            var submittedHashBytes = Encoding.UTF8.GetBytes(submittedHash);

            foreach (var device in trustedDevices)
            {
                if (!string.Equals(device.DeviceId, deviceId, StringComparison.Ordinal))
                {
                    continue;
                }

                var storedHashBytes = Encoding.UTF8.GetBytes(device.TokenHash);
                if (CryptographicOperations.FixedTimeEquals(submittedHashBytes, storedHashBytes))
                {
                    _logger.LogDebug("Bypass granted via trusted device token for device {DeviceId}", deviceId);
                    return BypassResult.Bypassed("trusted_device");
                }
            }
        }

        // 4. Registered device ID — use DeviceIdMatches so Jellyfin Web's
        // UA-hash IDs with per-session timestamp suffixes still match across
        // Tizen/SmartTV app restarts.
        if (!string.IsNullOrWhiteSpace(deviceId)
            && registeredDeviceIds.Any(r => DeviceIdMatches(r, deviceId)))
        {
            _logger.LogDebug("Bypass granted via registered device ID {DeviceId}", deviceId);
            return BypassResult.Bypassed("registered_device");
        }

        return BypassResult.NotBypassed;
    }

    internal static string HashApiKey(string rawKey)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawKey)));

    /// <summary>Normalise a Jellyfin Web-generated UA-hash deviceId so that
    /// per-session timestamp suffixes don't defeat paired-device matching.
    /// Jellyfin Web (incl. inside the Tizen webview) uses a deviceId formed
    /// from base64(UserAgent) + "|" + millis-since-boot or similar — every app
    /// restart changes the suffix while the prefix stays stable. We strip the
    /// trailing "|digits" segment so pairings survive Tizen app restarts.
    ///
    /// Non-UA-hash deviceIds (regular 16/32-char hex from native apps, GUIDs
    /// from Swiftfin, etc) pass through unchanged.</summary>
    public static string NormaliseDeviceId(string? id)
    {
        if (string.IsNullOrEmpty(id)) return string.Empty;
        // Jellyfin Web pattern: starts with a long base64 chunk and ends
        // with "|digits" (usually 10-20 digits of millisecond timestamp).
        // Only strip when the suffix looks like the session timestamp —
        // don't touch deviceIds that legitimately contain a pipe.
        var lastPipe = id.LastIndexOf('|');
        if (lastPipe > 16 && lastPipe < id.Length - 4)
        {
            var suffix = id.AsSpan(lastPipe + 1);
            bool allDigits = true;
            foreach (var c in suffix) { if (c < '0' || c > '9') { allDigits = false; break; } }
            if (allDigits) return id.Substring(0, lastPipe);
        }
        return id;
    }

    /// <summary>Paired/trusted-device comparator that normalises both sides
    /// so Tizen/SmartTV UA-hash deviceIds match across app restarts. Callers
    /// previously used raw Ordinal string.Equals which broke for Tizen.</summary>
    public static bool DeviceIdMatches(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        return string.Equals(NormaliseDeviceId(a), NormaliseDeviceId(b), StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks whether the given IP address falls within the specified CIDR range.
    /// Supports both IPv4 and IPv6.
    /// </summary>
    internal static bool IsIpInCidr(string ip, string cidr)
    {
        var slashIndex = cidr.IndexOf('/', StringComparison.Ordinal);
        if (slashIndex < 0)
        {
            // Treat as a host address with no mask
            return string.Equals(ip, cidr, StringComparison.OrdinalIgnoreCase);
        }

        var networkStr = cidr[..slashIndex];
        var prefixLenStr = cidr[(slashIndex + 1)..];

        if (!int.TryParse(prefixLenStr, out var prefixLength))
        {
            return false;
        }

        if (!IPAddress.TryParse(ip, out var ipAddr) ||
            !IPAddress.TryParse(networkStr, out var networkAddr))
        {
            return false;
        }

        // Normalize IPv4-mapped IPv6 addresses to plain IPv4
        if (ipAddr.IsIPv4MappedToIPv6)
        {
            ipAddr = ipAddr.MapToIPv4();
        }

        if (networkAddr.IsIPv4MappedToIPv6)
        {
            networkAddr = networkAddr.MapToIPv4();
        }

        var ipBytes = ipAddr.GetAddressBytes();
        var networkBytes = networkAddr.GetAddressBytes();

        if (ipBytes.Length != networkBytes.Length)
        {
            return false;
        }

        return MaskedEquals(ipBytes, networkBytes, prefixLength);
    }

    private static bool MaskedEquals(byte[] a, byte[] b, int prefixLength)
    {
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        // Check full bytes
        for (var i = 0; i < fullBytes && i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        // Check partial byte
        if (remainingBits > 0 && fullBytes < a.Length)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((a[fullBytes] & mask) != (b[fullBytes] & mask))
            {
                return false;
            }
        }

        return true;
    }
}

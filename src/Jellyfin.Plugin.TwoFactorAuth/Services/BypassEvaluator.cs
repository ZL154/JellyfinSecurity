using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.AspNetCore.Http;
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
                    // SEC-H2: walk XFF right-to-left and pick the first hop that
                    // is NOT a trusted proxy. The leftmost entry is attacker-
                    // controllable when proxies (Cloudflare, nginx without
                    // set_real_ip_from) APPEND to XFF instead of overwriting.
                    // Without this, a request with `X-Forwarded-For: 10.0.0.5`
                    // arrives as `10.0.0.5, real_client_ip` after the proxy,
                    // and trusting first[0] hands LAN bypass to anyone.
                    ipToCheck = PickRealClientIp(forwardedFor, config.TrustedProxyCidrs) ?? ipToCheck;
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

    // PERF-P5: parsed CIDR cache. The hot path used to call IPAddress.TryParse
    // on every check, every request — with ~10 configured CIDRs (LAN bypass +
    // trusted proxies + IP-ban exempt) that's 10 parses per auth request.
    // We cache the parse result per literal CIDR string. Cap is generous
    // (admins rarely have >100 CIDRs).
    private record ParsedCidr(byte[] NetworkBytes, int PrefixLength);

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, ParsedCidr?> _cidrCache = new();
    private const int CidrCacheMaxEntries = 1024;

    private static ParsedCidr? ParseCidrCached(string cidr)
    {
        if (_cidrCache.TryGetValue(cidr, out var cached)) return cached;

        ParsedCidr? parsed = null;
        var slashIndex = cidr.IndexOf('/', StringComparison.Ordinal);
        if (slashIndex < 0)
        {
            // Host address with no mask: treat as /32 (IPv4) or /128 (IPv6).
            if (IPAddress.TryParse(cidr, out var hostAddr))
            {
                if (hostAddr.IsIPv4MappedToIPv6) hostAddr = hostAddr.MapToIPv4();
                var bytes = hostAddr.GetAddressBytes();
                parsed = new ParsedCidr(bytes, bytes.Length * 8);
            }
        }
        else
        {
            var networkStr = cidr[..slashIndex];
            var prefixLenStr = cidr[(slashIndex + 1)..];
            if (int.TryParse(prefixLenStr, out var prefixLength)
                && IPAddress.TryParse(networkStr, out var networkAddr))
            {
                if (networkAddr.IsIPv4MappedToIPv6) networkAddr = networkAddr.MapToIPv4();
                parsed = new ParsedCidr(networkAddr.GetAddressBytes(), prefixLength);
            }
        }

        // Cheap cap: when oversized, drop a chunk of the oldest-inserted
        // entries. Admins re-configuring CIDRs through the UI are the only
        // realistic source of cache growth.
        if (_cidrCache.Count >= CidrCacheMaxEntries)
        {
            foreach (var k in _cidrCache.Keys.Take(CidrCacheMaxEntries / 4))
            {
                _cidrCache.TryRemove(k, out _);
            }
        }
        _cidrCache[cidr] = parsed;
        return parsed;
    }

    /// <summary>
    /// Checks whether the given IP address falls within the specified CIDR range.
    /// Supports both IPv4 and IPv6. PERF-P5: each distinct CIDR string is
    /// parsed once and cached.
    /// </summary>
    internal static bool IsIpInCidr(string ip, string cidr)
    {
        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(cidr)) return false;

        var parsed = ParseCidrCached(cidr);
        if (parsed is null)
        {
            // Unparseable mask form — fall back to literal host compare.
            return string.Equals(ip, cidr, StringComparison.OrdinalIgnoreCase);
        }

        if (!IPAddress.TryParse(ip, out var ipAddr)) return false;
        if (ipAddr.IsIPv4MappedToIPv6) ipAddr = ipAddr.MapToIPv4();
        var ipBytes = ipAddr.GetAddressBytes();

        if (ipBytes.Length != parsed.NetworkBytes.Length) return false;
        return MaskedEquals(ipBytes, parsed.NetworkBytes, parsed.PrefixLength);
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

    /// <summary>SEC-H2: walk a comma-separated X-Forwarded-For value right-to-left
    /// and return the first hop that is NOT in any of the trusted proxy CIDRs.
    /// That's the real client — anything to the left of it could have been
    /// supplied by an attacker before the chain of proxies appended their own
    /// observed peer addresses.
    ///
    /// Returns null if every hop is in the trusted-proxy set (rare — implies
    /// the call originated from inside the proxy chain, e.g. a load-balancer
    /// health check) or if the header is empty/malformed.</summary>
    internal static string? PickRealClientIp(string? forwardedFor, string[] trustedProxyCidrs)
    {
        if (string.IsNullOrWhiteSpace(forwardedFor)) return null;
        var parts = forwardedFor.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;
        // Walk right-to-left. Each step: is this hop a trusted proxy? If yes,
        // keep walking. The first untrusted hop is the real client.
        for (var i = parts.Length - 1; i >= 0; i--)
        {
            var hop = parts[i];
            // Strip optional bracketed IPv6 form ("[::1]") and ":port" suffix.
            if (hop.StartsWith('[')) {
                var close = hop.IndexOf(']');
                if (close > 0) hop = hop.Substring(1, close - 1);
            }
            else if (hop.Count(c => c == ':') == 1 && hop.IndexOf('.') >= 0) {
                // IPv4 with port; IPv6 has many colons so this only triggers on v4.
                hop = hop.Substring(0, hop.IndexOf(':'));
            }
            if (!IPAddress.TryParse(hop, out _)) continue;
            var isTrusted = false;
            foreach (var cidr in trustedProxyCidrs)
            {
                if (IsIpInCidr(hop, cidr)) { isTrusted = true; break; }
            }
            if (!isTrusted) return hop;
        }
        return null;
    }

    /// <summary>Returns the real client IP for the request, accounting for a
    /// trusted reverse-proxy chain. Falls back to the direct peer when no
    /// proxy is configured or trusted. Centralises the SEC-H2 fix so every
    /// caller (rate limiter, IP ban checks, audit logs) sees the same view.</summary>
    public static string? ResolveClientIp(HttpContext context)
    {
        var peer = context.Connection.RemoteIpAddress;
        var peerStr = peer?.ToString();
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.TrustForwardedFor || config.TrustedProxyCidrs.Length == 0)
            return peerStr;
        if (string.IsNullOrEmpty(peerStr)) return null;

        // Direct peer must be a trusted proxy before XFF is honoured at all.
        var peerTrusted = false;
        foreach (var cidr in config.TrustedProxyCidrs)
        {
            if (IsIpInCidr(peerStr, cidr)) { peerTrusted = true; break; }
        }
        if (!peerTrusted) return peerStr;

        var xff = context.Request.Headers["X-Forwarded-For"].ToString();
        var real = PickRealClientIp(xff, config.TrustedProxyCidrs);
        return real ?? peerStr;
    }

    /// <summary>Returns the real request scheme ("http" or "https") accounting
    /// for a TLS-terminating reverse proxy. SEC-H1: behind Cloudflare/Caddy/
    /// nginx that terminates TLS, context.Request.Scheme is "http" even though
    /// the browser used HTTPS. Without this, the trust-cookie Secure attribute
    /// is silently dropped in production deployments.</summary>
    public static string ResolveScheme(HttpContext context)
    {
        var direct = context.Request.Scheme;
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.TrustForwardedFor || config.TrustedProxyCidrs.Length == 0)
            return direct;
        var peerStr = context.Connection.RemoteIpAddress?.ToString();
        if (string.IsNullOrEmpty(peerStr)) return direct;
        var peerTrusted = false;
        foreach (var cidr in config.TrustedProxyCidrs)
        {
            if (IsIpInCidr(peerStr, cidr)) { peerTrusted = true; break; }
        }
        if (!peerTrusted) return direct;
        var fwdProto = context.Request.Headers["X-Forwarded-Proto"].ToString();
        if (string.IsNullOrWhiteSpace(fwdProto)) return direct;
        // X-Forwarded-Proto can be a comma-separated list (rare, when chained
        // through multiple proxies). Take the leftmost — that's the original
        // browser-facing scheme. Lowercased + length-checked.
        var first = fwdProto.Split(',', 2)[0].Trim().ToLowerInvariant();
        return first is "http" or "https" ? first : direct;
    }

    /// <summary>True iff the resolved request scheme is HTTPS — proxy-aware.</summary>
    public static bool IsSecureRequest(HttpContext context)
        => string.Equals(ResolveScheme(context), "https", StringComparison.Ordinal);
}

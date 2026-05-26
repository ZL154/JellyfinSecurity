using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class BypassEvaluatorTests
{
    // ---- CIDR matching -----------------------------------------------------

    [Theory]
    [InlineData("192.168.1.5", "192.168.1.0/24", true)]
    [InlineData("192.168.1.0", "192.168.1.0/24", true)]
    [InlineData("192.168.1.255", "192.168.1.0/24", true)]
    [InlineData("10.0.0.1", "10.0.0.0/8", true)]
    [InlineData("10.255.255.254", "10.0.0.0/8", true)]
    [InlineData("192.168.2.5", "192.168.1.0/24", false)]
    [InlineData("172.16.0.1", "10.0.0.0/8", false)]
    [InlineData("11.0.0.1", "10.0.0.0/8", false)]
    [InlineData("192.168.1.5", "192.168.1.5/32", true)]
    [InlineData("192.168.1.6", "192.168.1.5/32", false)]
    [InlineData("192.168.1.5", "192.168.1.5", true)]
    [InlineData("192.168.1.6", "192.168.1.5", false)]
    [InlineData("1.2.3.4", "0.0.0.0/0", true)]
    [InlineData("8.8.8.8", "0.0.0.0/0", true)]
    public void IsIpInCidr_ipv4_cases(string ip, string cidr, bool expected)
    {
        Assert.Equal(expected, BypassEvaluator.IsIpInCidr(ip, cidr));
    }

    [Theory]
    [InlineData("::1", "::1/128", true)]
    [InlineData("::1", "::/0", true)]
    [InlineData("2001:db8::1", "2001:db8::/32", true)]
    [InlineData("2001:db8:1::1", "2001:db8::/32", true)]
    [InlineData("2001:db9::1", "2001:db8::/32", false)]
    [InlineData("fe80::1", "fe80::/10", true)]
    public void IsIpInCidr_ipv6_cases(string ip, string cidr, bool expected)
    {
        Assert.Equal(expected, BypassEvaluator.IsIpInCidr(ip, cidr));
    }

    [Theory]
    [InlineData("", "192.168.1.0/24")]
    [InlineData("192.168.1.5", "")]
    [InlineData("not-an-ip", "192.168.1.0/24")]
    [InlineData("192.168.1.5", "definitely-not-a-cidr")]
    public void IsIpInCidr_invalid_inputs_return_false(string ip, string cidr)
    {
        Assert.False(BypassEvaluator.IsIpInCidr(ip, cidr));
    }

    [Fact]
    public void IsIpInCidr_does_not_match_v4_against_v6_cidr()
    {
        Assert.False(BypassEvaluator.IsIpInCidr("192.168.1.5", "2001:db8::/32"));
        Assert.False(BypassEvaluator.IsIpInCidr("::1", "192.168.0.0/16"));
    }

    // ---- X-Forwarded-For parsing (SEC-H2) ----------------------------------

    [Fact]
    public void PickRealClientIp_returns_first_untrusted_hop_walking_right_to_left()
    {
        // Real chain: client -> cloudflare -> origin.
        // XFF arrives at origin as "client, cloudflare". Origin's trusted-proxy
        // set includes cloudflare. PickRealClientIp must walk right-to-left,
        // skip cloudflare, return the first untrusted hop (the client).
        var result = BypassEvaluator.PickRealClientIp(
            "1.2.3.4, 172.65.0.1",
            new[] { "172.65.0.0/16" });

        Assert.Equal("1.2.3.4", result);
    }

    [Fact]
    public void PickRealClientIp_walks_through_multiple_trusted_proxies()
    {
        var result = BypassEvaluator.PickRealClientIp(
            "1.2.3.4, 10.0.0.5, 172.65.0.1",
            new[] { "172.65.0.0/16", "10.0.0.0/8" });

        Assert.Equal("1.2.3.4", result);
    }

    [Fact]
    public void PickRealClientIp_rejects_attacker_supplied_leftmost_hop()
    {
        // Attacker sets the leftmost XFF entry hoping to be treated as LAN.
        // Cloudflare appends the real client IP, then origin sees three hops.
        // After skipping cloudflare, the rightmost untrusted hop is the real
        // attacker IP — NOT the attacker-supplied leftmost value.
        var result = BypassEvaluator.PickRealClientIp(
            "127.0.0.1, 5.6.7.8, 172.65.0.1",
            new[] { "172.65.0.0/16" });

        Assert.Equal("5.6.7.8", result);
    }

    [Fact]
    public void PickRealClientIp_strips_ipv4_port()
    {
        var result = BypassEvaluator.PickRealClientIp("1.2.3.4:54321", System.Array.Empty<string>());
        Assert.Equal("1.2.3.4", result);
    }

    [Fact]
    public void PickRealClientIp_strips_bracketed_ipv6()
    {
        var result = BypassEvaluator.PickRealClientIp("[2001:db8::1]", System.Array.Empty<string>());
        Assert.Equal("2001:db8::1", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PickRealClientIp_returns_null_for_empty_input(string? xff)
    {
        Assert.Null(BypassEvaluator.PickRealClientIp(xff, System.Array.Empty<string>()));
    }

    [Fact]
    public void PickRealClientIp_returns_null_when_every_hop_is_trusted()
    {
        // Internal load-balancer health check — every hop is in the trust set.
        var result = BypassEvaluator.PickRealClientIp(
            "10.0.0.5, 10.0.0.6",
            new[] { "10.0.0.0/8" });

        Assert.Null(result);
    }

    [Fact]
    public void PickRealClientIp_skips_garbage_entries()
    {
        // Some proxies append non-IP tokens (UNKNOWN, hostnames). Must not crash.
        var result = BypassEvaluator.PickRealClientIp(
            "1.2.3.4, UNKNOWN, garbage, 172.65.0.1",
            new[] { "172.65.0.0/16" });

        Assert.Equal("1.2.3.4", result);
    }

    // ---- Refuse-LAN-bypass guard (v2.4.12 SEC-H3) --------------------------

    [Fact]
    public void ShouldRefuseLanBypass_when_xff_missing_and_peer_is_trusted_proxy()
    {
        // Regression for issue #35 follow-up reported by @FsxShader2012.
        // SessionStarted fires from a websocket reconnect with no live
        // HttpContext.Request, so AuthenticationEventHandler's synchronous
        // XFF capture is null. The peer is the nginx box (10.150.0.203) which
        // sits inside the admin's LAN-bypass CIDR. Without this guard the
        // bypass evaluator would treat the proxy itself as a LAN client and
        // silently ApproveToken without 2FA.
        Assert.True(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: null,
            remoteIp: "10.150.0.203",
            trustedProxyCidrs: new[] { "10.150.0.0/24" }));
    }

    [Fact]
    public void ShouldRefuseLanBypass_returns_false_when_xff_is_present()
    {
        // The standard SEC-H2 right-to-left walk handles this case via
        // PickRealClientIp — the guard must defer to it, not block.
        Assert.False(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: "203.0.113.5, 10.150.0.203",
            remoteIp: "10.150.0.203",
            trustedProxyCidrs: new[] { "10.150.0.0/24" }));
    }

    [Fact]
    public void ShouldRefuseLanBypass_returns_false_for_direct_lan_client()
    {
        // Direct LAN client (peer in 192.168.1.0/24, NOT in any trusted-proxy
        // CIDR) with no XFF — should fall through to the normal LAN-CIDR
        // check, not be refused. This is the everyday LAN-bypass case and
        // must keep working.
        Assert.False(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: null,
            remoteIp: "192.168.1.50",
            trustedProxyCidrs: new[] { "10.150.0.0/24" }));
    }

    [Fact]
    public void ShouldRefuseLanBypass_returns_false_when_no_trusted_proxies_configured()
    {
        // Admin hasn't configured a trusted-proxy list at all — we have no
        // way to know if the peer is supposed to be a proxy, so we don't
        // intervene. The standard LAN-CIDR check handles it downstream.
        Assert.False(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: null,
            remoteIp: "10.150.0.203",
            trustedProxyCidrs: System.Array.Empty<string>()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ShouldRefuseLanBypass_returns_false_when_remote_ip_missing(string? remoteIp)
    {
        // Can't classify a peer we don't have — defer to default behaviour.
        Assert.False(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: null,
            remoteIp: remoteIp,
            trustedProxyCidrs: new[] { "10.150.0.0/24" }));
    }

    [Fact]
    public void ShouldRefuseLanBypass_handles_multi_cidr_proxy_list()
    {
        // Admin lists multiple trusted-proxy ranges (e.g. nginx LAN IP +
        // Cloudflare edge). Peer matching ANY of them must trigger the guard.
        Assert.True(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: null,
            remoteIp: "172.65.0.42",
            trustedProxyCidrs: new[] { "10.150.0.0/24", "172.65.0.0/16" }));
    }

    [Fact]
    public void ShouldRefuseLanBypass_treats_whitespace_only_xff_as_missing()
    {
        // A header that's just spaces is semantically the same as absent.
        // Guard must still fire if peer is a trusted proxy.
        Assert.True(BypassEvaluator.ShouldRefuseLanBypassWhenXffMissing(
            forwardedFor: "   ",
            remoteIp: "10.150.0.203",
            trustedProxyCidrs: new[] { "10.150.0.0/24" }));
    }

    // ---- Device ID normalisation ------------------------------------------

    [Fact]
    public void NormaliseDeviceId_strips_session_timestamp_suffix()
    {
        // Jellyfin Web/Tizen pattern: base64-ish prefix + "|<millis>".
        // Restarts change the millis suffix but the prefix is stable.
        const string id = "VGhpc0lzQVZlcnlMb25nQmFzZTY0SXNoUHJlZml4|1700000000000";
        Assert.Equal("VGhpc0lzQVZlcnlMb25nQmFzZTY0SXNoUHJlZml4", BypassEvaluator.NormaliseDeviceId(id));
    }

    [Fact]
    public void NormaliseDeviceId_leaves_non_timestamp_pipe_alone()
    {
        // A pipe followed by non-digit content is part of a legitimate deviceId.
        const string id = "VGhpc0lzQVZlcnlMb25nUHJlZml4|not-digits-here";
        Assert.Equal(id, BypassEvaluator.NormaliseDeviceId(id));
    }

    [Fact]
    public void NormaliseDeviceId_leaves_short_pipes_alone()
    {
        // Pipes within the first 16 chars are not stripped.
        const string id = "short|123";
        Assert.Equal(id, BypassEvaluator.NormaliseDeviceId(id));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    public void NormaliseDeviceId_handles_empty(string? input, string expected)
    {
        Assert.Equal(expected, BypassEvaluator.NormaliseDeviceId(input));
    }

    [Fact]
    public void DeviceIdMatches_returns_true_after_session_restart_changes_suffix()
    {
        const string before = "VGhpc0lzQVZlcnlMb25nQmFzZTY0SXNoUHJlZml4|1700000000000";
        const string after = "VGhpc0lzQVZlcnlMb25nQmFzZTY0SXNoUHJlZml4|1700099999999";
        Assert.True(BypassEvaluator.DeviceIdMatches(before, after));
    }

    [Fact]
    public void DeviceIdMatches_returns_false_for_different_prefixes()
    {
        Assert.False(BypassEvaluator.DeviceIdMatches(
            "VGhpc0lzQVZlcnlMb25nUHJlZml4|123456",
            "RGlmZmVyZW50QmFzZTY0SXNoUHJlZml4|123456"));
    }

    [Theory]
    [InlineData(null, "x")]
    [InlineData("x", null)]
    [InlineData("", "x")]
    [InlineData("x", "")]
    [InlineData(null, null)]
    public void DeviceIdMatches_rejects_empty_inputs(string? a, string? b)
    {
        Assert.False(BypassEvaluator.DeviceIdMatches(a, b));
    }

    // ---- API key hashing ---------------------------------------------------

    [Fact]
    public void HashApiKey_is_deterministic_uppercase_hex()
    {
        var hash = BypassEvaluator.HashApiKey("api-key-12345");

        // SHA-256 -> 32 bytes -> 64 hex chars, uppercase.
        Assert.Equal(64, hash.Length);
        foreach (var c in hash)
        {
            Assert.True(
                (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'),
                $"non-uppercase-hex char in hash: {c}");
        }

        Assert.Equal(hash, BypassEvaluator.HashApiKey("api-key-12345"));
    }

    [Fact]
    public void HashApiKey_changes_with_input()
    {
        Assert.NotEqual(
            BypassEvaluator.HashApiKey("api-key-A"),
            BypassEvaluator.HashApiKey("api-key-B"));
    }
}

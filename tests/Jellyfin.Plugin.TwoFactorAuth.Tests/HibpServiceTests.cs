using System.Net.Http;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// v2.4 batch 3: tests for HibpService. Network calls are skipped in unit
/// tests (they'd flake on CI without network or against rate limits). The
/// deterministic SHA-1 helper is the most important thing to lock down:
/// if it ever drifts, every cached HIBP result becomes a false negative.
/// </summary>
public class HibpServiceTests
{
    // ---- SHA-1 helper (deterministic, no network) --------------------------

    [Fact]
    public void ComputeSha1Hex_known_vector_password()
    {
        // Cross-check against the canonical HIBP example:
        //   SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        var hash = HibpService.ComputeSha1Hex("password");
        Assert.Equal("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", hash);
    }

    [Fact]
    public void ComputeSha1Hex_known_vector_abc()
    {
        // RFC 3174 test vector: SHA-1("abc") = A9993E364706816ABA3E25717850C26C9CD0D89D
        var hash = HibpService.ComputeSha1Hex("abc");
        Assert.Equal("A9993E364706816ABA3E25717850C26C9CD0D89D", hash);
    }

    [Fact]
    public void ComputeSha1Hex_empty_string()
    {
        // SHA-1("") = DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
        var hash = HibpService.ComputeSha1Hex(string.Empty);
        Assert.Equal("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", hash);
    }

    [Fact]
    public void ComputeSha1Hex_is_deterministic()
    {
        Assert.Equal(
            HibpService.ComputeSha1Hex("hunter2"),
            HibpService.ComputeSha1Hex("hunter2"));
    }

    [Fact]
    public void ComputeSha1Hex_changes_with_input()
    {
        Assert.NotEqual(
            HibpService.ComputeSha1Hex("hunter2"),
            HibpService.ComputeSha1Hex("hunter3"));
    }

    [Fact]
    public void ComputeSha1Hex_is_case_sensitive()
    {
        Assert.NotEqual(
            HibpService.ComputeSha1Hex("Password"),
            HibpService.ComputeSha1Hex("password"));
    }

    [Fact]
    public void ComputeSha1Hex_returns_uppercase_40_chars_no_separators()
    {
        var hash = HibpService.ComputeSha1Hex("anything");
        Assert.Equal(40, hash.Length);
        foreach (var c in hash)
        {
            Assert.True(
                (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'),
                $"unexpected char '{c}' in SHA-1 hex output");
        }
    }

    // ---- CheckPasswordAsync input-edge behavior ---------------------------

    [Fact]
    public async System.Threading.Tasks.Task CheckPasswordAsync_returns_zero_for_null()
    {
        // Null / empty must short-circuit BEFORE the network call so a
        // cleared-text-field client doesn't accidentally trigger an HTTP
        // request with an empty prefix.
        var http = new HttpClient();
        var svc = new HibpService(http, Substitute.For<ILogger<HibpService>>());

        Assert.Equal(0, await svc.CheckPasswordAsync(null));
    }

    [Fact]
    public async System.Threading.Tasks.Task CheckPasswordAsync_returns_zero_for_empty()
    {
        var http = new HttpClient();
        var svc = new HibpService(http, Substitute.For<ILogger<HibpService>>());

        Assert.Equal(0, await svc.CheckPasswordAsync(string.Empty));
    }
}

using System.IO;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class CookieSignerTests
{
    private static CookieSigner NewSigner(out string sandbox)
    {
        var paths = TestApplicationPaths.Create(out sandbox);
        return new CookieSigner(paths, Substitute.For<ILogger<CookieSigner>>());
    }

    [Fact]
    public void Sign_returns_non_empty_url_safe_token()
    {
        var signer = NewSigner(out _);
        var sig = signer.Sign("user=abc;exp=12345");

        Assert.False(string.IsNullOrEmpty(sig));
        Assert.DoesNotContain('+', sig);
        Assert.DoesNotContain('/', sig);
        Assert.DoesNotContain('=', sig);
    }

    [Fact]
    public void Sign_then_Verify_returns_true()
    {
        var signer = NewSigner(out _);
        var payload = "user=abc;device=xyz;exp=9999";
        var sig = signer.Sign(payload);

        Assert.True(signer.Verify(payload, sig));
    }

    [Fact]
    public void Verify_rejects_tampered_signature()
    {
        var signer = NewSigner(out _);
        var payload = "user=abc";
        var sig = signer.Sign(payload);

        var tampered = sig.Length > 0 && sig[0] != 'A'
            ? "A" + sig.Substring(1)
            : "B" + sig.Substring(1);

        Assert.False(signer.Verify(payload, tampered));
    }

    [Fact]
    public void Verify_rejects_tampered_payload()
    {
        var signer = NewSigner(out _);
        var sig = signer.Sign("user=abc");
        Assert.False(signer.Verify("user=evil", sig));
    }

    [Fact]
    public void Verify_rejects_null_signature()
    {
        var signer = NewSigner(out _);
        Assert.False(signer.Verify("any", null!));
    }

    [Fact]
    public void Verify_rejects_empty_signature()
    {
        var signer = NewSigner(out _);
        Assert.False(signer.Verify("any", string.Empty));
    }

    [Fact]
    public void Verify_rejects_length_mismatch_without_throwing()
    {
        // SEC: CryptographicOperations.FixedTimeEquals throws on length mismatch.
        // CookieSigner.Verify must length-check first to remove the throw/no-throw
        // timing oracle. Calling Verify with a too-short signature must return
        // false cleanly, not throw.
        var signer = NewSigner(out _);
        var realSig = signer.Sign("user=abc");

        var ex = Record.Exception(() => signer.Verify("user=abc", "short"));
        Assert.Null(ex);
        Assert.False(signer.Verify("user=abc", "short"));
        Assert.False(signer.Verify("user=abc", realSig + "extra"));
    }

    [Fact]
    public void Sign_is_deterministic_for_same_payload_and_key()
    {
        var signer = NewSigner(out _);
        var a = signer.Sign("p");
        var b = signer.Sign("p");
        Assert.Equal(a, b);
    }

    [Fact]
    public void Key_persists_across_signer_instances_in_same_directory()
    {
        var paths = TestApplicationPaths.Create(out _);
        var sigA = new CookieSigner(paths, Substitute.For<ILogger<CookieSigner>>()).Sign("p");
        var sigB = new CookieSigner(paths, Substitute.For<ILogger<CookieSigner>>()).Sign("p");
        Assert.Equal(sigA, sigB);
    }

    [Fact]
    public void Different_directories_produce_different_signatures()
    {
        var signerA = NewSigner(out _);
        var signerB = NewSigner(out _);
        Assert.NotEqual(signerA.Sign("p"), signerB.Sign("p"));
    }

    [Fact]
    public void Key_file_is_32_bytes_on_disk()
    {
        _ = NewSigner(out var sandbox);
        var keyPath = Path.Combine(sandbox, "config", "plugins", "TwoFactorAuth", "cookie.key");
        Assert.True(File.Exists(keyPath));
        Assert.Equal(32, new FileInfo(keyPath).Length);
    }

    [Fact]
    public void Truncated_key_file_is_regenerated()
    {
        var paths = TestApplicationPaths.Create(out var sandbox);
        var keyPath = Path.Combine(sandbox, "config", "plugins", "TwoFactorAuth", "cookie.key");
        Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        File.WriteAllBytes(keyPath, Encoding.UTF8.GetBytes("too-short"));

        // Constructing the signer should detect the bad key, regenerate, and
        // produce a working signature pair.
        var signer = new CookieSigner(paths, Substitute.For<ILogger<CookieSigner>>());
        var sig = signer.Sign("payload");
        Assert.True(signer.Verify("payload", sig));
        Assert.Equal(32, new FileInfo(keyPath).Length);
    }
}

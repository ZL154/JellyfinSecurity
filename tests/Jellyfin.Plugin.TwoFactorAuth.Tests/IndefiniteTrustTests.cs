using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>v2.5.0: smoke tests for the indefinite-device-trust opt-in.
/// Full controller integration would require WebApplicationFactory which the
/// rest of this test project does not use; these cover the additive data-model
/// + config defaults so a future regression that flips the default to ON,
/// or drops the persisted field, fails the build instead of silently shipping.</summary>
public class IndefiniteTrustTests
{
    [Fact]
    public void PluginConfiguration_AllowIndefiniteTrust_DefaultsToFalse()
    {
        var cfg = new PluginConfiguration();
        Assert.False(cfg.AllowIndefiniteTrust);
    }

    [Fact]
    public void TrustedDevice_IndefiniteTrust_DefaultsToFalse()
    {
        var d = new TrustedDevice();
        Assert.False(d.IndefiniteTrust);
    }

    [Fact]
    public void PairedDevice_IndefiniteTrust_DefaultsToFalse()
    {
        var p = new PairedDevice();
        Assert.False(p.IndefiniteTrust);
    }

    [Fact]
    public void TrustedDevice_IndefiniteTrust_Roundtrip()
    {
        var d = new TrustedDevice { IndefiniteTrust = true };
        Assert.True(d.IndefiniteTrust);
        d.IndefiniteTrust = false;
        Assert.False(d.IndefiniteTrust);
    }

    [Fact]
    public void PairedDevice_IndefiniteTrust_Roundtrip()
    {
        var p = new PairedDevice { IndefiniteTrust = true };
        Assert.True(p.IndefiniteTrust);
    }
}

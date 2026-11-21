using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;
using static Jellyfin.Plugin.TwoFactorAuth.Services.OidcService;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>The plugin email receives email OTP codes and password reset
/// links, so the identity provider's claim only fills it once the provider
/// has verified the address.</summary>
public class OidcEmailAutoFillTests
{
    private static readonly OidcProvider Syncing = new() { SyncEmailFromClaim = true };

    [Fact]
    public void A_verified_claim_fills_an_empty_plugin_email()
        => Assert.Equal(EmailAutoFill.Fill, DecideEmailAutoFill(Syncing, "user@example.com", emailVerified: true, currentEmail: null));

    [Fact]
    public void An_unverified_claim_never_becomes_the_plugin_email()
        => Assert.Equal(EmailAutoFill.Unverified, DecideEmailAutoFill(Syncing, "user@example.com", emailVerified: false, currentEmail: null));

    [Fact]
    public void An_address_already_set_is_never_overwritten()
        => Assert.Equal(EmailAutoFill.AlreadySet, DecideEmailAutoFill(Syncing, "new@example.com", emailVerified: true, currentEmail: "old@example.com"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void No_claim_fills_nothing(string? claim)
        => Assert.Equal(EmailAutoFill.NoClaim, DecideEmailAutoFill(Syncing, claim, emailVerified: true, currentEmail: null));

    [Fact]
    public void Sync_turned_off_fills_nothing()
        => Assert.Equal(EmailAutoFill.Off, DecideEmailAutoFill(new OidcProvider { SyncEmailFromClaim = false }, "user@example.com", emailVerified: true, currentEmail: null));
}

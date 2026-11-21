using System;
using System.Security.Claims;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;
using static Jellyfin.Plugin.TwoFactorAuth.Services.OidcService;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>The plugin email receives email OTP codes and password reset
/// links, so the identity provider's claim only fills it once the provider
/// has attested that exact address.</summary>
public class OidcEmailAutoFillTests
{
    private static readonly OidcProvider Syncing = new() { SyncEmailFromClaim = true };

    private static EmailAutoFill FromUserInfo(string json, string? emailClaim = null, string? current = null)
    {
        var extract = ExtractClaimsFromUserInfo(JsonDocument.Parse(json).RootElement, emailClaim ?? "email");
        return DecideEmailAutoFill(Syncing, extract.Email, extract.EmailVerified, () => current);
    }

    private static EmailAutoFill FromIdToken(string? emailClaim, params (string Type, string Value)[] claims)
    {
        var (email, verified) = ExtractEmailFromIdTokenClaims(
            Array.ConvertAll(claims, c => new Claim(c.Type, c.Value)), emailClaim);
        return DecideEmailAutoFill(Syncing, email, verified, () => null);
    }

    // ---- claim documents: /userinfo ----

    [Fact]
    public void UserInfo_verified_standard_email_fills()
        => Assert.Equal(EmailAutoFill.Fill, FromUserInfo("""{ "email": "a@example.com", "email_verified": true }"""));

    [Fact]
    public void UserInfo_unverified_standard_email_does_not_fill()
        => Assert.Equal(EmailAutoFill.Unverified, FromUserInfo("""{ "email": "a@example.com", "email_verified": false }"""));

    [Fact]
    public void UserInfo_missing_email_verified_does_not_fill()
        => Assert.Equal(EmailAutoFill.Unverified, FromUserInfo("""{ "email": "a@example.com" }"""));

    [Fact]
    public void UserInfo_custom_claim_with_a_different_address_is_not_attested()
        => Assert.Equal(EmailAutoFill.Unverified, FromUserInfo(
            """{ "internal_email": "other@corp.example", "email": "a@corp.example", "email_verified": true }""", "internal_email"));

    [Fact]
    public void UserInfo_custom_claim_without_a_standard_email_is_not_attested()
        => Assert.Equal(EmailAutoFill.Unverified, FromUserInfo(
            """{ "internal_email": "a@corp.example", "email_verified": true }""", "internal_email"));

    [Fact]
    public void UserInfo_custom_claim_matching_the_verified_email_fills_with_the_attested_spelling()
    {
        var extract = ExtractClaimsFromUserInfo(JsonDocument.Parse(
            """{ "internal_email": "a@CORP.example", "email": "a@corp.example", "email_verified": "true" }""").RootElement, "internal_email");

        Assert.True(extract.EmailVerified);
        // The address delivered to is the one the issuer verified.
        Assert.Equal("a@corp.example", extract.Email);
    }

    [Fact]
    public void UserInfo_custom_claim_differing_in_the_local_part_case_is_not_attested()
        => Assert.Equal(EmailAutoFill.Unverified, FromUserInfo(
            """{ "internal_email": "A@corp.example", "email": "a@corp.example", "email_verified": "true" }""", "internal_email"));

    [Fact]
    public void UserInfo_custom_claim_absent_falls_back_to_the_verified_email()
        => Assert.Equal(EmailAutoFill.Fill, FromUserInfo(
            """{ "email": "a@example.com", "email_verified": true }""", "internal_email"));

    // ---- claim documents: ID token ----

    [Fact]
    public void IdToken_verified_standard_email_fills()
        => Assert.Equal(EmailAutoFill.Fill, FromIdToken(null, ("email", "a@example.com"), ("email_verified", "True")));

    [Fact]
    public void IdToken_unverified_standard_email_does_not_fill()
        => Assert.Equal(EmailAutoFill.Unverified, FromIdToken(null, ("email", "a@example.com"), ("email_verified", "false")));

    [Fact]
    public void IdToken_custom_claim_with_a_different_address_is_not_attested()
        => Assert.Equal(EmailAutoFill.Unverified, FromIdToken(
            "internal_email", ("internal_email", "other@corp.example"), ("email", "a@corp.example"), ("email_verified", "true")));

    [Fact]
    public void IdToken_custom_claim_matching_the_verified_email_fills()
        => Assert.Equal(EmailAutoFill.Fill, FromIdToken(
            "internal_email", ("internal_email", "a@corp.example"), ("email", "a@corp.example"), ("email_verified", "true")));

    [Fact]
    public void IdToken_custom_claim_differing_in_the_local_part_case_is_not_attested()
        => Assert.Equal(EmailAutoFill.Unverified, FromIdToken(
            "internal_email", ("internal_email", "A@corp.example"), ("email", "a@corp.example"), ("email_verified", "true")));

    [Fact]
    public void IdToken_fill_uses_the_attested_spelling()
    {
        var (email, verified) = ExtractEmailFromIdTokenClaims(new[]
        {
            new Claim("internal_email", "a@CORP.EXAMPLE"), new Claim("email", "a@corp.example"), new Claim("email_verified", "true"),
        }, "internal_email");

        Assert.True(verified);
        Assert.Equal("a@corp.example", email);
    }

    // ---- writing ----

    [Fact]
    public void The_fill_writes_the_address_into_the_checked_configuration()
    {
        var cfg = new PluginConfiguration();

        Assert.True(TryFillEmail(cfg, cfg, "user", "a@example.com"));
        Assert.Equal("a@example.com", cfg.GetUserEmail("user"));
    }

    [Fact]
    public void An_address_from_a_concurrent_admin_save_is_kept()
    {
        var checkedCfg = new PluginConfiguration();
        var saved = new PluginConfiguration();
        saved.SetUserEmail("user", "admin@example.com");

        // The admin save replaced the configuration after the check.
        Assert.False(TryFillEmail(checkedCfg, saved, "user", "a@example.com"));
        Assert.Equal("admin@example.com", saved.GetUserEmail("user"));
        Assert.True(string.IsNullOrEmpty(checkedCfg.GetUserEmail("user")));
    }

    [Fact]
    public void An_address_set_on_the_same_configuration_meanwhile_is_kept()
    {
        var cfg = new PluginConfiguration();
        cfg.SetUserEmail("user", "admin@example.com");

        Assert.False(TryFillEmail(cfg, cfg, "user", "a@example.com"));
        Assert.Equal("admin@example.com", cfg.GetUserEmail("user"));
    }

    // ---- decision ----

    [Fact]
    public void An_address_already_set_is_never_overwritten()
        => Assert.Equal(EmailAutoFill.AlreadySet, FromUserInfo(
            """{ "email": "new@example.com", "email_verified": true }""", current: "old@example.com"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void No_claim_fills_nothing(string? claim)
        => Assert.Equal(EmailAutoFill.NoClaim, DecideEmailAutoFill(Syncing, claim, emailVerified: true, () => null));

    [Fact]
    public void Sync_turned_off_fills_nothing()
        => Assert.Equal(EmailAutoFill.Off, DecideEmailAutoFill(new OidcProvider { SyncEmailFromClaim = false }, "user@example.com", emailVerified: true, () => null));

    [Fact]
    public void The_configuration_is_not_read_unless_the_claim_qualifies()
    {
        Func<string?> boom = () => throw new InvalidOperationException("configuration read");
        Assert.Equal(EmailAutoFill.Off, DecideEmailAutoFill(new OidcProvider { SyncEmailFromClaim = false }, "a@example.com", true, boom));
        Assert.Equal(EmailAutoFill.NoClaim, DecideEmailAutoFill(Syncing, null, true, boom));
        Assert.Equal(EmailAutoFill.Unverified, DecideEmailAutoFill(Syncing, "a@example.com", false, boom));
    }
}

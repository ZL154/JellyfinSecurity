using System;
using System.Security.Claims;
using System.Text.Json;
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
    public void UserInfo_custom_claim_matching_the_verified_email_fills()
        => Assert.Equal(EmailAutoFill.Fill, FromUserInfo(
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

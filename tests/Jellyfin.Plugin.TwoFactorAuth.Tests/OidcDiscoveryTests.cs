using System;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class OidcDiscoveryTests
{
    [Fact]
    public void IssuerRoot_IsRetriedAtStandardWellKnownPath()
    {
        using var root = JsonDocument.Parse("""{"realm":"master"}""");

        Assert.True(OidcService.NeedsStandardDiscoveryRetry(
            root.RootElement,
            "https://idp.example/realms/master/"));
        Assert.Equal(
            "https://idp.example/realms/master/.well-known/openid-configuration",
            OidcService.BuildStandardDiscoveryUrl("https://idp.example/realms/master/"));
    }

    [Fact]
    public void ExistingWellKnownUrl_IsNeverRecursivelySuffixed()
    {
        using var invalid = JsonDocument.Parse("""{}""");
        Assert.False(OidcService.NeedsStandardDiscoveryRetry(
            invalid.RootElement,
            "https://idp.example/.well-known/openid-configuration"));
    }

    [Fact]
    public void ValidDiscoveryDocument_DoesNotRetry()
    {
        using var valid = JsonDocument.Parse(
            """{"authorization_endpoint":"https://idp.example/authorize"}""");
        Assert.False(OidcService.NeedsStandardDiscoveryRetry(
            valid.RootElement,
            "https://idp.example/issuer"));
    }

    [Theory]
    [InlineData("authorization_endpoint")]
    [InlineData("token_endpoint")]
    [InlineData("jwks_uri")]
    [InlineData("issuer")]
    public void EveryMissingRequiredField_HasActionableError(string missingField)
    {
        using var document = JsonDocument.Parse(
            """
            {
              "authorization_endpoint":"https://idp.example/authorize",
              "token_endpoint":"https://idp.example/token",
              "jwks_uri":"https://idp.example/jwks",
              "issuer":"https://idp.example"
            }
            """);
        using var altered = JsonDocument.Parse(
            document.RootElement.GetRawText().Replace(
                $"\"{missingField}\"",
                $"\"removed_{missingField}\"",
                StringComparison.Ordinal));

        var error = Assert.Throws<InvalidOperationException>(() =>
            OidcService.RequireDiscoveryEndpoint(
                altered.RootElement,
                missingField,
                "https://idp.example/issuer"));

        Assert.Contains(missingField, error.Message);
        Assert.Contains(".well-known/openid-configuration", error.Message);
        Assert.DoesNotContain("KeyNotFoundException", error.ToString());
    }
}

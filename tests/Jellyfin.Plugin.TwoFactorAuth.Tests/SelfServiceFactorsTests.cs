using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#248] The self-service step-up and app password creation read the
/// same list of factors. Creation used to accept only a confirmed authenticator
/// app, so an account that signs in through SSO passed the step-up with its
/// provider and was then told to set up TOTP.</summary>
public class SelfServiceFactorsTests
{
    private static readonly PluginConfiguration Config = new();

    [Fact]
    public void An_account_with_no_factor_cannot_back_an_app_password()
    {
        Assert.False(SelfServiceFactors.HasAny(new UserTwoFactorData(), Config));
    }

    [Fact]
    public void A_confirmed_authenticator_app_counts()
    {
        var data = new UserTwoFactorData { TotpEnabled = true, TotpVerified = true };

        Assert.True(SelfServiceFactors.HasAny(data, Config));
    }

    [Fact]
    public void An_authenticator_app_that_was_never_confirmed_does_not_count()
    {
        var data = new UserTwoFactorData { TotpEnabled = true, TotpVerified = false };

        Assert.False(SelfServiceFactors.HasAny(data, Config));
    }

    [Fact]
    public void A_passkey_counts()
    {
        var data = new UserTwoFactorData();
        data.Passkeys.Add(new PasskeyCredential { Id = "pk1", CredentialId = "cred1" });

        Assert.True(SelfServiceFactors.HasAny(data, Config));
    }

    [Fact]
    public void A_linked_identity_provider_counts()
    {
        var data = new UserTwoFactorData();
        data.SsoLinks.Add(new SsoLink { ProviderId = "dex", Subject = "alice-sub" });

        Assert.True(SelfServiceFactors.HasAny(data, Config));
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void The_email_code_counts_only_while_the_server_allows_it(bool emailOtpEnabled, bool expected)
    {
        var data = new UserTwoFactorData { EmailOtpPreferred = true };

        Assert.Equal(expected, SelfServiceFactors.HasAny(data, new PluginConfiguration { EmailOtpEnabled = emailOtpEnabled }));
    }
}

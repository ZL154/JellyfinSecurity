using System;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#247] setup.html and inject.js decide what to show from
/// GET /TwoFactorAuth/public-config. A field the server does not send reads as
/// undefined on the page, which is how "Send code by email" stayed on offer
/// with email OTP turned off: the page read emailOtpEnabled, the server never
/// sent it.</summary>
public class PublicConfigTests
{
    private static JsonElement Body(PluginConfiguration cfg, bool passwordLoginDisabled = false)
        => JsonSerializer.SerializeToElement(TwoFactorAuthController.BuildPublicConfig(cfg, passwordLoginDisabled));

    [Fact]
    public void The_body_carries_every_field_the_pages_read()
    {
        var expected = new[]
        {
            "allowIndefiniteTrust",
            "defaultLanguage",
            "emailOtpEnabled",
            "hideBuiltInForgotPassword",
            "hideBuiltInPasskeyButton",
            "hideBuiltInTwoFactorButton",
            "hideTwoFactorSetupForSsoUsers",
            "loginLinksBelowQuickConnect",
            "passwordLoginDisabled",
            "passwordRecoveryEnabled",
            "supportedLanguages",
        };

        var keys = Body(new PluginConfiguration()).EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal);

        Assert.Equal(expected, keys);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Email_otp_availability_follows_the_admin_setting(bool enabled)
    {
        var body = Body(new PluginConfiguration { EmailOtpEnabled = enabled });

        Assert.Equal(enabled, body.GetProperty("emailOtpEnabled").GetBoolean());
    }

    [Fact]
    public void The_sso_account_page_is_off_until_an_admin_turns_it_on()
    {
        var cfg = new PluginConfiguration();

        Assert.False(cfg.HideTwoFactorSetupForSsoUsers);
        Assert.False(Body(cfg).GetProperty("hideTwoFactorSetupForSsoUsers").GetBoolean());
    }

    [Fact]
    public void The_sso_account_page_setting_reaches_the_page()
    {
        var body = Body(new PluginConfiguration { HideTwoFactorSetupForSsoUsers = true });

        Assert.True(body.GetProperty("hideTwoFactorSetupForSsoUsers").GetBoolean());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void The_password_answer_for_this_caller_is_passed_through(bool disabled)
    {
        var body = Body(new PluginConfiguration(), disabled);

        Assert.Equal(disabled, body.GetProperty("passwordLoginDisabled").GetBoolean());
    }
}

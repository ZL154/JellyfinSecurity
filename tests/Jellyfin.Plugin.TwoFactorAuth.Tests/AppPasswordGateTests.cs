using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#248] With "Disable password sign-in" on, the gate in
/// LockoutMessageMiddleware refused app passwords too, so on an SSO-only
/// server a remote user's app password got 403 even though the account was
/// allowed to create it. AllowAppPasswordsWhenPasswordLoginDisabled lets app
/// passwords through, and only them.</summary>
public class AppPasswordGateTests
{
    private static readonly AppPasswordService AppPasswords = new();

    private static (UserTwoFactorData Data, string AppPassword) AccountWithAppPassword()
    {
        var (plaintext, hash) = AppPasswords.Generate();
        var data = new UserTwoFactorData();
        data.AppPasswords.Add(new AppPassword { Id = "ap1", Label = "Seerr", PasswordHash = hash });
        return (data, plaintext);
    }

    private static PluginConfiguration Allowing(bool allow) =>
        new() { DisablePasswordLogin = true, AllowAppPasswordsWhenPasswordLoginDisabled = allow };

    [Fact]
    public void The_setting_is_off_until_an_admin_turns_it_on()
    {
        Assert.False(new PluginConfiguration().AllowAppPasswordsWhenPasswordLoginDisabled);
    }

    [Fact]
    public void While_the_setting_is_off_an_app_password_is_refused_as_before()
    {
        var (data, appPassword) = AccountWithAppPassword();

        Assert.False(LockoutMessageMiddleware.AppPasswordMayPass(Allowing(false), data, appPassword, AppPasswords));
    }

    [Fact]
    public void With_the_setting_on_an_app_password_of_the_account_passes()
    {
        var (data, appPassword) = AccountWithAppPassword();

        Assert.True(LockoutMessageMiddleware.AppPasswordMayPass(Allowing(true), data, appPassword, AppPasswords));
    }

    [Theory]
    [InlineData("the-account-password")]
    [InlineData("")]
    [InlineData(null)]
    public void With_the_setting_on_anything_else_is_still_refused(string? password)
    {
        var (data, _) = AccountWithAppPassword();

        Assert.False(LockoutMessageMiddleware.AppPasswordMayPass(Allowing(true), data, password, AppPasswords));
    }

    [Fact]
    public void Another_accounts_app_password_does_not_pass()
    {
        var (_, someoneElses) = AccountWithAppPassword();
        var (data, _) = AccountWithAppPassword();

        Assert.False(LockoutMessageMiddleware.AppPasswordMayPass(Allowing(true), data, someoneElses, AppPasswords));
    }

    [Fact]
    public void The_admin_page_loads_and_saves_the_setting()
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");
        Assert.NotNull(page);
        Assert.NotNull(script);

        Assert.Contains("id=\"cfgAllowAppPasswordsWhenPasswordLoginDisabled\"", page);
        Assert.Contains("apPwOffEl.checked = c.AllowAppPasswordsWhenPasswordLoginDisabled === true;", script);
        Assert.Contains("c.AllowAppPasswordsWhenPasswordLoginDisabled = apPwOffSaveEl ? apPwOffSaveEl.checked : false;", script);
    }
}

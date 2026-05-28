using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class I18nConfigTests
{
    [Fact]
    public void PluginConfiguration_DefaultLanguage_DefaultsToEnglish()
    {
        var cfg = new PluginConfiguration();
        Assert.Equal("en", cfg.DefaultLanguage);
    }

    [Fact]
    public void UserTwoFactorData_Language_DefaultsToNull()
    {
        var data = new UserTwoFactorData();
        Assert.Null(data.Language);
    }
}

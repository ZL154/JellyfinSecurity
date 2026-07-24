using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
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

    [Fact]
    public void PerUserLanguageRequestsCarryJellyfinAccessToken()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.tfa-i18n.js");

        Assert.NotNull(script);
        Assert.Contains("window.ApiClient.accessToken()", script);
        Assert.Contains("headers['X-Emby-Token'] = token;", script);
        Assert.Contains("headers: getAuthHeaders(false)", script);
        Assert.Contains("headers: getAuthHeaders(true)", script);
    }
}

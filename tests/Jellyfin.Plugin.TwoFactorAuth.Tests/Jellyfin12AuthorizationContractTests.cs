using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class Jellyfin12AuthorizationContractTests
{
    public static TheoryData<string> AuthenticatedBrowserResources => new()
    {
        "Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js",
        "Jellyfin.Plugin.TwoFactorAuth.Pages.setup.html",
        "Jellyfin.Plugin.TwoFactorAuth.Pages.login.html",
        "Jellyfin.Plugin.TwoFactorAuth.Pages.pairconfirm.html",
        "Jellyfin.Plugin.TwoFactorAuth.Pages.setpassword.html",
        "Jellyfin.Plugin.TwoFactorAuth.Pages.tfa-i18n.js"
    };

    [Theory]
    [MemberData(nameof(AuthenticatedBrowserResources))]
    public void Authenticated_browser_resources_use_current_jellyfin_authorization(string resource)
    {
        var content = ResourceReader.ReadEmbeddedText(resource);

        Assert.NotNull(content);
        Assert.Contains("Authorization", content);
        Assert.Contains("MediaBrowser Token", content);
        Assert.DoesNotContain("X-Emby-Token", content);
    }

    [Fact]
    public void Shared_helper_does_not_patch_global_fetch()
    {
        var script = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.tfa-i18n.js");

        Assert.NotNull(script);
        Assert.DoesNotContain("window.fetch =", script);
        Assert.DoesNotContain("modernizeAuthorization", script);
        Assert.DoesNotContain("_nativeFetch", script);
    }

    [Fact]
    public void Set_password_page_does_not_emit_deprecated_authorization_headers()
    {
        var page = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.setpassword.html");

        Assert.NotNull(page);
        Assert.Contains("Authorization", page);
        Assert.Contains("MediaBrowser Token", page);
        Assert.DoesNotContain("X-Emby-Token", page);
        Assert.DoesNotContain("X-Emby-Authorization", page);
    }
}

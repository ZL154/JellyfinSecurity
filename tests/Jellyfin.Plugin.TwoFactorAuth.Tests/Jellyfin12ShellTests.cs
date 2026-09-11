using System;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Jellyfin 12 ships the "modern" layout as default. It keeps the old
/// .mainDrawer in the DOM only so legacy scripts do not throw, hidden, and
/// its preferences page is React. The sidebar entry landed in the hidden
/// drawer and the settings tile anchored on the avatar menu's Profile item
/// (an MUI Menu that stays mounted while closed), so a regular user had no
/// visible way to the setup page. These pin the two new hooks and the guard.
/// </summary>
public class Jellyfin12ShellTests
{
    [Fact]
    public void TheAvatarMenuGetsATwoFactorEntryBelowProfile()
    {
        var js = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.Contains("function injectUserMenu()", js, StringComparison.Ordinal);
        Assert.Contains("getElementById('app-user-menu')", js, StringComparison.Ordinal);
        var inject = js.IndexOf("function injectUserMenu()", StringComparison.Ordinal);
        var belowProfile = js.IndexOf("list.insertBefore(item, profile.nextSibling)", inject, StringComparison.Ordinal);
        Assert.True(inject >= 0 && belowProfile > inject);
        // A real navigation to the setup page, recomputed at click time.
        Assert.Contains("withLang(serverUrl('TwoFactorAuth/Setup'))", js, StringComparison.Ordinal);
    }

    [Fact]
    public void TheLegacyTileNeverAnchorsInsideTheAvatarMenu()
    {
        // The preferences page is still the legacy view inside the new
        // shell. The tile anchored on the avatar menu's Profile item, which
        // matches the href selectors and the English text fallback before the
        // page has rendered, landed inside the closed menu, and its early
        // return then kept the real list without a tile.
        var js = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.Contains("function isInsideUserMenu(el)", js, StringComparison.Ordinal);
        var tile = js.IndexOf("function injectSettingsTile()", StringComparison.Ordinal);
        var heal = js.IndexOf("if (!isInsideUserMenu(existingTile)) return;", tile, StringComparison.Ordinal);
        var hrefGuard = js.IndexOf("if (!isInsideUserMenu(hrefCandidates[hi]))", heal, StringComparison.Ordinal);
        var textGuard = js.IndexOf("if (isInsideUserMenu(all[i])) continue;", hrefGuard, StringComparison.Ordinal);
        var lastResortGuard = js.IndexOf("if (!isInsideUserMenu(lastResort[li]))", textGuard, StringComparison.Ordinal);
        Assert.True(tile >= 0 && heal > tile && hrefGuard > heal && textGuard > hrefGuard && lastResortGuard > textGuard);

        var tryInject = js.IndexOf("function tryInject()", StringComparison.Ordinal);
        var userMenu = js.IndexOf("injectUserMenu();", tryInject, StringComparison.Ordinal);
        Assert.True(tryInject >= 0 && userMenu > tryInject);
    }

    [Theory]
    [InlineData("Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js")]
    [InlineData("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html")]
    public void NoAssetWritesTheDeprecatedBangRoutes(string resource)
    {
        // jellyfin-web 12 still redirects #!/ with a console warning that the
        // format will stop working; the routes have been #/ since 10.9.
        var text = ResourceReader.ReadEmbeddedText(resource);
        Assert.NotNull(text);
        var index = 0;
        while ((index = text!.IndexOf("#!/", index, StringComparison.Ordinal)) >= 0)
        {
            var lineStart = text.LastIndexOf('\n', index) + 1;
            var line = text.Substring(lineStart, index - lineStart);
            Assert.True(line.TrimStart().StartsWith("//", StringComparison.Ordinal), "a #!/ route outside a comment: " + line.Trim());
            index += 3;
        }
    }

}

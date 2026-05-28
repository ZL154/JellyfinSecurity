using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class TranslationLangSanitizationTests
{
    private static string Sanitize(string? lang)
    {
        var clean = new string((lang ?? "en").ToLowerInvariant()
            .Where(c => (c >= 'a' && c <= 'z') || c == '-').ToArray());
        return string.IsNullOrEmpty(clean) ? "en" : clean;
    }

    [Theory]
    [InlineData(null, "en")]
    [InlineData("", "en")]
    [InlineData("de", "de")]
    [InlineData("EN", "en")]
    [InlineData("zh-CN", "zh-cn")]
    [InlineData("../etc/passwd", "etcpasswd")]
    [InlineData("../../../secrets", "secrets")]
    [InlineData("en/../de", "ende")]
    [InlineData("de;rm -rf /", "derm-rf")]
    public void Sanitize_StripsDangerousChars(string? input, string expected)
    {
        Assert.Equal(expected, Sanitize(input));
    }
}

public class TranslationResourceLoadingTests
{
    [Fact]
    public void ReadEmbeddedText_EnJson_LoadsContent()
    {
        var content = Jellyfin.Plugin.TwoFactorAuth.Helpers.ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.translations.en.json");
        Assert.NotNull(content);
        Assert.Contains("tfa.admin.tab_overview", content);
    }

    [Fact]
    public void ReadEmbeddedText_NonexistentLang_ReturnsNull()
    {
        var content = Jellyfin.Plugin.TwoFactorAuth.Helpers.ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.translations.xx-fake.json");
        Assert.Null(content);
    }
}

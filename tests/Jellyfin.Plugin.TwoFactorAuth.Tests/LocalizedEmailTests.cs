using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#318] The password reset email and the sign-in code email went
/// out in English whatever the language of the account. They now come from the
/// translation files the pages use, in the recipient's language.</summary>
public class LocalizedEmailTests
{
    private static readonly string[] Languages = ["en", "de", "es", "fr", "it", "ja", "pt", "zh"];

    private static EmailOtpService Service(string? defaultLanguage, Func<Guid, Task<string?>> userLanguage)
        => new(
            NullLogger<EmailOtpService>.Instance,
            () => new PluginConfiguration { DefaultLanguage = defaultLanguage! },
            userLanguage);

    [Theory]
    [InlineData("fr", "de", "fr")]
    [InlineData(null, "de", "de")]
    [InlineData("", "de", "de")]
    [InlineData("xx", "de", "de")]
    [InlineData("FR", "de", "de")]
    [InlineData("../fr", "it", "it")]
    [InlineData(null, "xx", "en")]
    [InlineData(null, null, "en")]
    [InlineData(null, "en", "en")]
    public async Task The_recipient_language_is_theirs_then_the_server_default_then_English(
        string? userLanguage, string? defaultLanguage, string expected)
    {
        var service = Service(defaultLanguage, _ => Task.FromResult(userLanguage));

        Assert.Equal(expected, await service.ResolveRecipientLanguageAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task The_language_is_looked_up_for_the_recipient_account()
    {
        var owner = Guid.NewGuid();
        var service = Service("de", id => Task.FromResult<string?>(id == owner ? "ja" : "es"));

        Assert.Equal("ja", await service.ResolveRecipientLanguageAsync(owner));
    }

    [Fact]
    public async Task A_user_record_that_cannot_be_read_leaves_the_server_default()
    {
        var service = Service("pt", _ => throw new InvalidOperationException("unreadable"));

        Assert.Equal("pt", await service.ResolveRecipientLanguageAsync(Guid.NewGuid()));
    }

    [Fact]
    public void A_key_missing_from_a_language_falls_back_to_English()
    {
        var localized = new Dictionary<string, string> { ["a"] = "localized a" };
        var english = new Dictionary<string, string> { ["a"] = "english a", ["b"] = "english b" };

        Assert.Equal("localized a", ServerTranslations.Pick(localized, english, "a"));
        Assert.Equal("english b", ServerTranslations.Pick(localized, english, "b"));
        Assert.Equal("english b", ServerTranslations.Pick(null, english, "b"));
        Assert.Throws<KeyNotFoundException>(() => ServerTranslations.Pick(localized, english, "c"));
    }

    [Fact]
    public void A_language_without_a_bundle_reads_English()
    {
        Assert.Equal(
            ServerTranslations.Get("en", "tfa.email.reset.subject"),
            ServerTranslations.Get("xx", "tfa.email.reset.subject"));
    }

    [Fact]
    public void Placeholders_are_replaced_in_one_pass()
    {
        var values = new Dictionary<string, string>
        {
            ["username"] = "{link}",
            ["link"] = "https://jf.example.test/r?token=abc",
        };

        var text = ServerTranslations.Format("Hi {username}, open {link}. {unknown} stays.", values);

        Assert.Equal("Hi {link}, open https://jf.example.test/r?token=abc. {unknown} stays.", text);
    }

    [Fact]
    public void A_username_with_a_placeholder_cannot_change_the_reset_link()
    {
        const string link = "https://jf.example.test/TwoFactorAuth/PasswordReset?token=abc&lang=fr";

        var (_, body) = EmailOtpService.ComposePasswordReset("fr", "{link} {minutes}", link, 30);

        Assert.Equal(1, CountOf(body, link));
        Assert.Contains("Bonjour {link} {minutes},", body, StringComparison.Ordinal);
    }

    // Main wrote three em dashes in these emails. They became a semicolon
    // and a plain signature line, like the other languages; nothing else
    // may change. The dash is built from its code so this file has none.
    private static readonly string MainDash = ((char)0x2014).ToString();

    private static string WithoutMainDashes(string mainText)
        => mainText
            .Replace(" " + MainDash + " your password", "; your password", StringComparison.Ordinal)
            .Replace("\n\n" + MainDash + " Jellyfin 2FA", "\n\nJellyfin 2FA", StringComparison.Ordinal);

    [Fact]
    public void The_English_emails_are_main_without_its_dashes()
    {
        var mainReset = "Hi alice,\n\nWe received a request to reset your Jellyfin password. Open this link to choose a new one:\n\n"
            + "  https://jf.example.test/r\n\nThis link expires in 30 minutes and can be used once. If you didn't request this, "
            + "you can ignore this email " + MainDash + " your password won't change.\n\n" + MainDash + " Jellyfin 2FA";
        var mainCode = "Hi alice,\n\nYour Jellyfin sign-in code is:\n\n  12345678\n\nThis code expires in 5 minutes. If you did not "
            + "request this code, change your password and revoke active sessions immediately.\n\n" + MainDash + " Jellyfin 2FA";

        var reset = EmailOtpService.ComposePasswordReset("en", "alice", "https://jf.example.test/r", 30);
        Assert.Equal("Reset your Jellyfin password", reset.Subject);
        Assert.Equal(WithoutMainDashes(mainReset), reset.Body);

        var code = EmailOtpService.ComposeSignInCode("en", "alice", "12345678", 5);
        Assert.Equal("Jellyfin sign-in code", code.Subject);
        Assert.Equal(WithoutMainDashes(mainCode), code.Body);

        Assert.DoesNotContain(reset.Body + code.Body, c => c is >= (char)0x2012 and <= (char)0x2015);
    }

    [Theory]
    [InlineData("de")]
    [InlineData("es")]
    [InlineData("fr")]
    [InlineData("it")]
    [InlineData("ja")]
    [InlineData("pt")]
    [InlineData("zh")]
    public void Each_language_sends_its_own_text_with_the_link_and_the_code(string language)
    {
        const string link = "https://jf.example.test/r?token=abc";
        var englishReset = EmailOtpService.ComposePasswordReset("en", "alice", link, 30);
        var reset = EmailOtpService.ComposePasswordReset(language, "alice", link, 30);
        Assert.NotEqual(englishReset.Subject, reset.Subject);
        Assert.NotEqual(englishReset.Body, reset.Body);
        Assert.Equal(1, CountOf(reset.Body, link));
        Assert.Contains("alice", reset.Body, StringComparison.Ordinal);
        Assert.Contains("30", reset.Body, StringComparison.Ordinal);

        var englishCode = EmailOtpService.ComposeSignInCode("en", "alice", "12345680", 7);
        var code = EmailOtpService.ComposeSignInCode(language, "alice", "12345680", 7);
        Assert.NotEqual(englishCode.Subject, code.Subject);
        Assert.NotEqual(englishCode.Body, code.Body);
        Assert.Equal(1, CountOf(code.Body, "12345680"));
        Assert.Contains("alice", code.Body, StringComparison.Ordinal);
        Assert.Contains("7", code.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void The_reset_link_carries_the_email_language()
    {
        var link = PasswordResetService.BuildResetLink("https://jf.example.test/", "a b", "fr");

        Assert.Equal("https://jf.example.test/TwoFactorAuth/PasswordReset?token=a%20b&lang=fr", link);
    }

    [Fact]
    public void Every_language_has_every_new_key_translated_with_the_same_placeholders()
    {
        var english = Bundle("en");
        var newKeys = english.Keys
            .Where(k => k.StartsWith("tfa.email.", StringComparison.Ordinal) || k.StartsWith("tfa.pwreset.", StringComparison.Ordinal))
            .ToList();
        Assert.Contains("tfa.email.reset.body", newKeys);
        Assert.Contains("tfa.email.code.body", newKeys);
        Assert.Contains("tfa.pwreset.error_invalid_link", newKeys);

        foreach (var language in Languages.Where(l => l != "en"))
        {
            var bundle = Bundle(language);
            foreach (var key in newKeys)
            {
                Assert.True(bundle.TryGetValue(key, out var text), $"{language} lacks {key}");
                Assert.NotEqual(english[key], text);
                Assert.Equal(Placeholders(english[key]), Placeholders(text!));
            }
        }
    }

    private static int CountOf(string text, string part)
        => (text.Length - text.Replace(part, string.Empty, StringComparison.Ordinal).Length) / part.Length;

    private static string[] Placeholders(string text)
        => Regex.Matches(text, @"\{[a-z]+\}").Select(m => m.Value).Order(StringComparer.Ordinal).ToArray();

    private static Dictionary<string, string> Bundle(string language)
    {
        var json = ResourceReader.ReadEmbeddedText($"Jellyfin.Plugin.TwoFactorAuth.Pages.translations.{language}.json");
        Assert.NotNull(json);
        using var document = JsonDocument.Parse(json);
        return document.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
    }
}

/// <summary>[#318] The reset page had an English title and English messages.
/// Both standalone password pages now take every visible string from the
/// translation files.</summary>
public class PasswordPagesI18nTests
{
    private static readonly string[] Languages = ["en", "de", "es", "fr", "it", "ja", "pt", "zh"];

    [Theory]
    [InlineData("password-reset.html")]
    [InlineData("setpassword.html")]
    public void Every_key_the_page_uses_is_in_every_language(string page)
    {
        var html = Page(page);
        Assert.Contains("<script src=\"../TwoFactorAuth/tfa-i18n\"></script>", html, StringComparison.Ordinal);
        var keys = Regex.Matches(html, @"(?:data-i18n-key=""|_tr\('|show(?:Err|Ok)\(')(tfa\.[a-z_.]+)")
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(keys);

        foreach (var language in Languages)
        {
            var json = ResourceReader.ReadEmbeddedText($"Jellyfin.Plugin.TwoFactorAuth.Pages.translations.{language}.json");
            Assert.NotNull(json);
            using var document = JsonDocument.Parse(json);
            foreach (var key in keys)
            {
                Assert.True(document.RootElement.TryGetProperty(key, out _), $"{language} lacks {key} used by {page}");
            }
        }
    }

    [Fact]
    public void Every_visible_string_of_the_reset_page_is_translated()
    {
        var html = Page("password-reset.html");
        var markup = Regex.Replace(html, @"<(script|style)\b[^>]*>.*?</\1>", string.Empty, RegexOptions.Singleline);

        // Each element whose own text is more than whitespace or an entity
        // carries the key that translates it.
        var texts = Regex.Matches(markup, @"<(\w+)([^>]*)>([^<]*)(?=<)");
        var checkedTexts = 0;
        foreach (Match m in texts)
        {
            var text = Regex.Replace(m.Groups[3].Value, @"&\w+;", string.Empty).Trim();
            if (text.Length == 0)
            {
                continue;
            }

            checkedTexts++;
            Assert.True(m.Groups[2].Value.Contains("data-i18n-key=", StringComparison.Ordinal), "untranslated: " + text);
        }

        Assert.True(checkedTexts >= 8, "the check saw " + checkedTexts + " texts");

        // Messages shown by the script go through the translator too.
        var script = Regex.Match(html, @"<script>(.*?)</script>", RegexOptions.Singleline).Groups[1].Value;
        Assert.DoesNotMatch(@"show(Err|Ok)\('(?!tfa\.pwreset\.)", script);
        Assert.Contains("showOk('tfa.pwreset.success'", script, StringComparison.Ordinal);

        // The server's messages are English only and never reach the page.
        Assert.DoesNotContain(".message", script, StringComparison.Ordinal);
    }

    private static string Page(string name)
    {
        var html = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages." + name);
        Assert.NotNull(html);
        return html;
    }
}

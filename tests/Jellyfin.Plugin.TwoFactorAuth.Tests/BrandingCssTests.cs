using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Model.Branding;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#348] The pages the plugin serves itself (sign-in, challenge,
/// Setup and the rest) never load Jellyfin's index.html, so the custom CSS
/// from Dashboard → Branding never reached them.</summary>
public class BrandingCssTests
{
    private const string Page = "<head>\n<style>\nbody { color: #e0e0e0; }\n</style>\n</head>\n<body>\n<p>page</p>\n</body>";

    [Fact]
    public void A_script_at_the_end_of_the_body_adds_the_css_to_the_head()
    {
        Assert.Equal(
            "<head>\n<style>\nbody { color: #e0e0e0; }\n</style>\n</head>\n<body>\n<p>page</p>\n"
            + "<script>(function () { var s = document.createElement('style'); s.id = 'tfa-branding-css'; s.textContent = \"body { color: red; }\"; document.head.appendChild(s); })();</script>\n"
            + "</body>",
            BrandingCss.AddToPage(Page, "body { color: red; }"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \n ")]
    public void No_css_leaves_the_page_as_it_is(string? css)
    {
        Assert.Equal(Page, BrandingCss.AddToPage(Page, css));
    }

    [Fact]
    public void No_markup_in_the_css_can_end_the_script()
    {
        // The CSS travels as a script string with <, > and quotes escaped, so
        // nothing in it can close the script or start a tag.
        Assert.Equal(
            "<body><script>(function () { var s = document.createElement('style'); s.id = 'tfa-branding-css'; s.textContent = "
            + "\"/* \\u003C/STYLE\\u003E\\u003C/script\\u003E\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E */ a::after { content: \\u0022\\u003C/\\u0022; }\""
            + "; document.head.appendChild(s); })();</script>\n</body>",
            BrandingCss.AddToPage(
                "<body></body>",
                "/* </STYLE></script><script>alert(1)</script> */ a::after { content: \"</\"; }"));
    }

    [Fact]
    public void The_css_reaches_the_page_as_written()
    {
        const string css = "@import url('https://example.com/theme.css');\nbody::before { content: \"\u2192 \u00e9 \\\\ \\\"q\\\"\"; }\u2028";

        var html = BrandingCss.AddToPage("<body></body>", css);

        var start = html.IndexOf("s.textContent = ", StringComparison.Ordinal) + "s.textContent = ".Length;
        var end = html.IndexOf("; document.head", start, StringComparison.Ordinal);
        Assert.Equal(css, JsonSerializer.Deserialize<string>(html[start..end]));
        // A raw line separator ends a string literal in older script engines.
        Assert.DoesNotContain("\u2028", html, StringComparison.Ordinal);
    }

    [Fact]
    public void The_script_goes_before_the_last_body_end()
    {
        // A page script may hold "</body>" in a string; the end of the page
        // is the last one.
        Assert.Equal(
            "<body><script>var t = '</body>';</script>\n<script>(function () { var s = document.createElement('style'); s.id = 'tfa-branding-css'; s.textContent = \"p { color: red; }\"; document.head.appendChild(s); })();</script>\n</body>",
            BrandingCss.AddToPage("<body><script>var t = '</body>';</script>\n</body>", "p { color: red; }"));
    }

    [Fact]
    public void A_page_without_a_body_end_is_left_as_it_is()
    {
        Assert.Equal("<p>no body</p>", BrandingCss.AddToPage("<p>no body</p>", "p { color: red; }"));
    }
}

// The controller reads Plugin.Instance. Keep its temporary configuration away
// from every other collection and restore the singleton after each test.
[CollectionDefinition("Branding CSS", DisableParallelization = true)]
public sealed class BrandingCssCollection;

[Collection("Branding CSS")]
public sealed class BrandingCssPageTests
{
    private const string Css = "body { --tfa-issue: 348; }";

    private const string Script = "<script>(function () { var s = document.createElement('style'); s.id = 'tfa-branding-css'; "
        + "s.textContent = \"body { --tfa-issue: 348; }\"; document.head.appendChild(s); })();</script>\n</body>\n</html>";

    public static TheoryData<string, string> Pages => new()
    {
        { "Login", "tfa-page-login" },
        { "Challenge", "tfa-page-challenge" },
        { "Setup", "tfa-page-setup" },
        { "PairConfirm", "tfa-page-pair-confirm" },
        { "PasswordReset", "tfa-page-password-reset" },
        { "SetPassword", "tfa-page-set-password" },
    };

    [Theory]
    [MemberData(nameof(Pages))]
    public void With_the_option_on_every_page_carries_the_branding_css(string page, string pageClass)
    {
        using var fixture = new Fixture(apply: true);

        var html = fixture.Serve(page);

        Assert.EndsWith(Script, html.TrimEnd(), StringComparison.Ordinal);
        Assert.Contains($"<body class=\"tfa-page {pageClass}\">", html);
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void A_default_configuration_keeps_every_page_as_it_was(string page, string pageClass)
    {
        using var fixture = new Fixture(apply: null);

        var html = fixture.Serve(page);

        Assert.DoesNotContain("tfa-branding-css", html);
        Assert.DoesNotContain("--tfa-issue", html);
        Assert.Contains($"<body class=\"tfa-page {pageClass}\">", html);
    }

    [Fact]
    public void The_settings_page_loads_and_saves_the_option()
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);
        Assert.Contains("<input type=\"checkbox\" id=\"cfgApplyBrandingCss\" is=\"emby-checkbox\" />", page);
        Assert.Contains("var applyBrandingCssEl = page.querySelector('#cfgApplyBrandingCss');", script);
        Assert.Contains("if (applyBrandingCssEl) applyBrandingCssEl.checked = c.ApplyBrandingCss === true;", script);
        Assert.Contains("var applyBrandingCssSaveEl = page.querySelector('#cfgApplyBrandingCss');", script);
        Assert.Contains("if (applyBrandingCssSaveEl) c.ApplyBrandingCss = applyBrandingCssSaveEl.checked;", script);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _sandbox;
        private readonly Plugin? _previous = Plugin.Instance;
        private readonly TwoFactorAuthController _controller;

        // apply: null keeps the configuration a fresh install gets.
        public Fixture(bool? apply)
        {
            var paths = TestApplicationPaths.Create(out _sandbox);
            var serializer = Substitute.For<IXmlSerializer>();
            serializer.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
            var plugin = new Plugin(paths, serializer, Substitute.For<IApplicationHost>(), Substitute.For<ILogger<Plugin>>());
            if (apply is bool value)
            {
                plugin.Configuration.ApplyBrandingCss = value;
            }

            var serverConfig = Substitute.For<IServerConfigurationManager>();
            serverConfig.GetConfiguration("branding").Returns(new BrandingOptions { CustomCss = Css });
            _controller = new TwoFactorAuthController(
                store: null!, challengeStore: null!, totpService: null!, emailOtpService: null!,
                deviceTokenService: null!, devicePairingService: null!, notificationService: null!,
                sessionManager: null!, userManager: null!, cookieSigner: null!, rateLimiter: null!,
                recoveryCodes: null!, appPasswords: null!, pendingPairings: null!, deviceManager: null!,
                sessionTerm: null!, passkeys: null!, passkeyChallenges: null!, diagnostics: null!, stats: null!,
                userExport: null!, recoveryPdf: null!, ipBans: null!, allowlist: null!, stepUp: null!,
                scoreService: null!, configExport: null!, onboardingProofs: null!, externalUrls: null!,
                signInObserver: null!, logger: Substitute.For<ILogger<TwoFactorAuthController>>())
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext
                    {
                        RequestServices = new ServiceCollection().AddSingleton(serverConfig).BuildServiceProvider(),
                    },
                },
            };
        }

        public string Serve(string page)
        {
            var result = page switch
            {
                "Login" => _controller.GetLoginPage(),
                "Challenge" => _controller.GetChallengePage(),
                "Setup" => _controller.GetSetupPage(),
                "PairConfirm" => _controller.GetPairConfirmPage(),
                "PasswordReset" => _controller.PasswordResetPage(),
                "SetPassword" => _controller.SetPasswordPage(),
                _ => throw new ArgumentOutOfRangeException(nameof(page), page, null),
            };
            var content = Assert.IsType<ContentResult>(result);
            Assert.NotNull(content.Content);
            return content.Content;
        }

        public void Dispose()
        {
            typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
            Directory.Delete(_sandbox, recursive: true);
        }
    }
}

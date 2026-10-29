using System;
using System.IO;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>The email address and the linked Telegram chat receive the codes
/// that complete a sign-in and confirm a factor change, so pointing either one
/// somewhere else is itself a factor change. It needs the same self-service
/// step-up as adding a passkey or an authenticator app, and the Setup page has
/// to offer the prompt for it.</summary>
public class FactorChannelStepUpTests
{
    private const string Controller = "src/Jellyfin.Plugin.TwoFactorAuth/Api/TwoFactorAuthController.cs";

    [Theory]
    [InlineData("SetMyEmail", "config.SetUserEmail(")]
    [InlineData("LinkTelegram", "GenerateTelegramLinkCode(")]
    [InlineData("UnlinkTelegram", "ud.TelegramChatId = string.Empty")]
    public void A_code_channel_changes_only_after_the_step_up(string handler, string change)
    {
        var body = HandlerBody(handler);
        var gate = body.IndexOf("EnforceSelfServiceStepUpAsync(", StringComparison.Ordinal);
        var write = body.IndexOf(change, StringComparison.Ordinal);

        Assert.True(write >= 0, $"{handler} no longer contains {change}");
        Assert.True(gate >= 0 && gate < write, $"{handler} changes where codes go without the self-service step-up");
    }

    [Theory]
    [InlineData(typeof(SetEmailRequest))]
    [InlineData(typeof(LinkTelegramRequest))]
    public void The_request_carries_the_step_up_proof(Type request)
    {
        Assert.NotNull(request.GetProperty("Code"));
        Assert.NotNull(request.GetProperty("StepUpToken"));
    }

    [Fact]
    public void Disabling_2fa_reads_the_same_factor_list_as_the_step_up()
    {
        Assert.Contains("SelfServiceFactors.HasAny(", HandlerBody("DisableTotp"));
    }

    [Fact]
    public void Welcome_emails_are_limited_per_account()
    {
        var body = HandlerBody("SetMyEmail");
        var limit = body.IndexOf("CheckAndRecord(\"welcome_email:", StringComparison.Ordinal);
        var send = body.IndexOf("SendWelcomeEmailAsync(", StringComparison.Ordinal);

        Assert.True(send >= 0, "SetMyEmail no longer sends the welcome email");
        Assert.True(limit >= 0 && limit < send, "SetMyEmail mails every new address with no limit");
    }

    [Theory]
    [InlineData("mutateWithStepUp('POST', 'TwoFactorAuth/Email'")]
    [InlineData("mutateWithStepUp('POST', 'TwoFactorAuth/Telegram/Link'")]
    [InlineData("mutateWithStepUpUrl('DELETE', 'TwoFactorAuth/Telegram'")]
    public void The_setup_page_offers_the_step_up_prompt(string call)
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.setup.html");

        Assert.NotNull(page);
        Assert.Contains(call, page);
    }

    [Fact]
    public void Five_wrong_link_codes_end_the_pending_link()
    {
        var service = new EmailOtpService(NullLogger<EmailOtpService>.Instance, () => new PluginConfiguration());
        var user = Guid.NewGuid();
        var code = service.GenerateTelegramLinkCode(user, "4242");
        var wrong = code == "000000" ? "000001" : "000000";

        for (var i = 0; i < 5; i++)
        {
            Assert.Null(service.ConfirmTelegramLinkCode(user, wrong));
        }

        Assert.Null(service.ConfirmTelegramLinkCode(user, code));
    }

    [Fact]
    public void A_mistyped_link_code_leaves_the_right_one_valid()
    {
        var service = new EmailOtpService(NullLogger<EmailOtpService>.Instance, () => new PluginConfiguration());
        var user = Guid.NewGuid();
        var code = service.GenerateTelegramLinkCode(user, "4242");
        var wrong = code == "000000" ? "000001" : "000000";

        Assert.Null(service.ConfirmTelegramLinkCode(user, wrong));
        Assert.Equal("4242", service.ConfirmTelegramLinkCode(user, code));
    }

    /// <summary>The source of one controller action, from its signature to the
    /// brace that closes it.</summary>
    private static string HandlerBody(string name)
    {
        var source = SourceFile(Controller).Replace("\r\n", "\n", StringComparison.Ordinal);
        var signature = Regex.Match(source, @"public async Task<\w+> " + name + @"\(");
        Assert.True(signature.Success, $"{name} not found in {Controller}");

        var end = source.IndexOf("\n    }\n", signature.Index, StringComparison.Ordinal);
        Assert.True(end > signature.Index, $"the end of {name} not found");
        return source[signature.Index..end];
    }

    private static string SourceFile(string repoRelativePath)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, repoRelativePath);
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new FileNotFoundException(
            $"Could not find {repoRelativePath} walking up from {AppContext.BaseDirectory}");
    }
}

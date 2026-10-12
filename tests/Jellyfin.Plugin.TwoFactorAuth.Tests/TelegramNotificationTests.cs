using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#259] Telegram goes through the Bot API, whose URL carries the bot token.
// These tests pin how the plugin builds that request, what it shows when
// Telegram refuses, and that the token stays out of what the admin sees.
// Nothing here talks to Telegram: a setting with the wrong shape is refused
// before any request.
public class TelegramNotificationTests
{
    private const string Token = "123456789:AAH-fake_token-for-tests";

    [Theory]
    [InlineData("123456789:AAH-fake_token-for-tests", true)]
    [InlineData("123456789:", false)]
    [InlineData("bot123456789:AAH", false)]
    [InlineData("123456789:AAH/../getUpdates?", false)]
    [InlineData("", false)]
    public void Only_a_token_with_the_Telegram_shape_goes_into_the_URL(string token, bool valid)
        => Assert.Equal(valid, NotificationService.IsTelegramToken(token));

    [Theory]
    [InlineData("123456789", true)]
    [InlineData("-1001234567890", true)]
    [InlineData("@my_channel", true)]
    [InlineData("@ab", false)]
    [InlineData("my_channel", false)]
    [InlineData("12 34", false)]
    public void The_chat_is_a_numeric_id_or_a_channel_username(string chat, bool valid)
        => Assert.Equal(valid, NotificationService.IsTelegramChatId(chat));

    [Fact]
    public void The_request_goes_to_sendMessage_with_the_token_in_the_path()
        => Assert.Equal(
            "https://api.telegram.org/bot" + Token + "/sendMessage",
            NotificationService.TelegramSendMessageUrl(Token));

    [Fact]
    public void The_text_carries_the_title_the_message_and_the_event_and_fits_in_Telegram()
    {
        Assert.Equal("Title\n\nBody\n\nEvent: test", NotificationService.BuildTelegramText("Title", "Body", "test"));

        var cut = NotificationService.BuildTelegramText("T", new string('x', 5000), "e");
        Assert.Equal(4096, cut.Length);
        Assert.EndsWith("...", cut);
    }

    [Fact]
    public void Telegram_explains_a_refusal_and_the_token_is_scrubbed_from_it()
    {
        Assert.Equal(
            "Telegram refused the message (HTTP 400): Bad Request: chat not found",
            NotificationService.DescribeTelegramFailure(
                400, "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: chat not found\"}", Token));
        Assert.Equal(
            "Telegram refused the message (HTTP 401): Unauthorized for ***",
            NotificationService.DescribeTelegramFailure(
                401, "{\"ok\":false,\"description\":\"Unauthorized for " + Token + "\"}", Token));
        Assert.Equal(
            "Telegram refused the message (HTTP 502).",
            NotificationService.DescribeTelegramFailure(502, "<html>Bad gateway</html>", Token));
    }

    [Theory]
    [InlineData("not-a-token", "123456789", "bot token")]
    [InlineData(Token, "my channel", "chat ID")]
    public async Task A_setting_with_the_wrong_shape_is_reported_before_any_request(string token, string chat, string expected)
    {
        var cfg = new PluginConfiguration { TelegramBotToken = token, TelegramChatId = chat };
        var svc = new NotificationService(NullLogger<NotificationService>.Instance, null, () => cfg);

        var telegram = Assert.Single(await svc.SendTestAsync(), r => r.Channel == "telegram");

        Assert.True(telegram.Configured);
        Assert.False(telegram.Success);
        Assert.Contains(expected, telegram.Error);
        Assert.DoesNotContain(Token, telegram.Error);
    }

    [Fact]
    public async Task Without_both_settings_Telegram_is_skipped()
    {
        var cfg = new PluginConfiguration { TelegramBotToken = Token };
        var svc = new NotificationService(NullLogger<NotificationService>.Instance, null, () => cfg);

        var telegram = Assert.Single(await svc.SendTestAsync(), r => r.Channel == "telegram");

        Assert.False(telegram.Configured);
    }
}

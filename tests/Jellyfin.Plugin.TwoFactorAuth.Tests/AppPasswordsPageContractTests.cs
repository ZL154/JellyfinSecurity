using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#248] The Setup page offers app passwords from the server's
/// CanCreateAppPasswords answer. Before, the card only showed with TOTP, so an
/// account that signs in through SSO never saw it.</summary>
public class AppPasswordsPageContractTests
{
    private static string SetupPage()
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.setup.html");
        Assert.NotNull(page);
        return page;
    }

    [Fact]
    public void The_card_follows_the_servers_answer_rather_than_totp()
    {
        var page = SetupPage();

        // [#327] The page load and the factor read after a passkey change
        // both render the card from the same server answer.
        Assert.Contains("return !!(myStatus && (myStatus.canCreateAppPasswords || myStatus.CanCreateAppPasswords));", page);
        Assert.Contains("renderAppPasswords(canCreateAppPasswords(myStatus), r[5]);", page);
        Assert.Contains("renderAppPasswords(canCreateAppPasswords(r[0]), r[3]);", page);
        Assert.DoesNotContain("renderAppPasswords(totpOn", page);
    }

    [Fact]
    public void App_passwords_the_account_can_no_longer_create_stay_revocable()
    {
        var page = SetupPage();

        Assert.Contains("style.display = (canCreate || hasAny) ? 'block' : 'none';", page);
        Assert.Contains("document.getElementById('btnCreateAp').parentElement.style.display = canCreate ? '' : 'none';", page);
    }

    [Fact]
    public void An_account_without_totp_is_not_asked_for_a_totp_code()
    {
        var page = SetupPage();

        // [#327] The prompt picks the text from what the account has, so both
        // app password buttons hand it the two texts instead of choosing.
        Assert.Contains("window.__tfa_userTotpOn = !!(myStatus && (myStatus.totpEnabled || myStatus.TotpEnabled));", page);
        Assert.Equal(2, page.Split("messageNoTotp: _tr('tfa.setup.stepup.app_pw_msg_no_totp',").Length - 1);
        Assert.DoesNotContain("message: window.__tfa_userTotpOn", page);
    }
}

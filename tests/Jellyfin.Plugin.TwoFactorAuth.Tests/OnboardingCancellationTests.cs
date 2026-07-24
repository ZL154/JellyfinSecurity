using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class OnboardingCancellationTests
{
    [Fact]
    public void NewOidcProvisioning_CanBeAborted()
    {
        var data = new UserTwoFactorData
        {
            MustSetPassword = true,
            PendingOidcUserCreation = true,
        };

        Assert.True(TwoFactorAuthController.ShouldAbortOidcUserCreation(data));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void ExistingOrCompletedAccount_IsNeverDeleted(
        bool mustSetPassword,
        bool pendingOidcUserCreation)
    {
        var data = new UserTwoFactorData
        {
            MustSetPassword = mustSetPassword,
            PendingOidcUserCreation = pendingOidcUserCreation,
        };

        Assert.False(TwoFactorAuthController.ShouldAbortOidcUserCreation(data));
    }
}

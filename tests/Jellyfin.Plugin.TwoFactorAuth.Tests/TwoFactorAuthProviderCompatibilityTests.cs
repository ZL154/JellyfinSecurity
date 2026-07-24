using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller.Authentication;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class TwoFactorAuthProviderCompatibilityTests
{
    [Fact]
    public void Missing_user_for_resolved_user_provider_is_generic_auth_failure()
    {
        var exception = Assert.Throws<AuthenticationException>(
            () => TwoFactorAuthProvider.EnsureResolvedUserAvailable(
                providerRequiresResolvedUser: true,
                userExists: false));

        Assert.Equal("Invalid username or password.", exception.Message);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Valid_delegation_shapes_are_accepted(bool providerRequiresResolvedUser, bool userExists)
    {
        TwoFactorAuthProvider.EnsureResolvedUserAvailable(providerRequiresResolvedUser, userExists);
    }

    [Theory]
    [InlineData("dedicated", "MediaBrowser DeviceId=\"x-emby\"", "MediaBrowser DeviceId=\"standard\"", "standard")]
    [InlineData("dedicated", "MediaBrowser DeviceId=\"x-emby\"", null, "x-emby")]
    [InlineData("dedicated", null, null, "dedicated")]
    [InlineData(null, "MediaBrowser DeviceId=\"x-emby\"", "MediaBrowser DeviceId=\"standard\"", "standard")]
    [InlineData(null, null, "MediaBrowser Client=\"Web\", DeviceId=\"standard\", Version=\"1.0\"", "standard")]
    public void Device_identity_matches_Jellyfin_authorization_header_precedence(
        string? dedicated,
        string? xEmbyAuthorization,
        string? authorization,
        string expected)
    {
        Assert.Equal(
            expected,
            TwoFactorAuthProvider.ResolveDeviceHeaderValue(
                dedicated,
                xEmbyAuthorization,
                authorization,
                "DeviceId"));
    }

    [Theory]
    [InlineData(false, null, false)]
    [InlineData(false, "", false)]
    [InlineData(true, "password", false)]
    [InlineData(true, "", true)]
    [InlineData(true, "   ", true)]
    [InlineData(true, null, true)]
    public void Empty_password_hardening_is_shared_by_all_login_paths(
        bool gateEnabled,
        string? password,
        bool expected)
    {
        Assert.Equal(
            expected,
            TwoFactorAuthProvider.ShouldBlockEmptyPassword(gateEnabled, password));
    }
}

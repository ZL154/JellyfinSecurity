using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class AuthenticationEventHandlerTests
{
    [Fact]
    public void SelectMostRecentAccessToken_uses_freshest_matching_device_record()
    {
        var now = DateTime.UtcNow;
        var candidates = new[]
        {
            (DeviceId: "living-room", AccessToken: "stale", DateLastActivity: now.AddHours(-2)),
            (DeviceId: "other", AccessToken: "wrong-device", DateLastActivity: now),
            (DeviceId: "living-room", AccessToken: "current", DateLastActivity: now.AddMinutes(-1)),
        };

        var selected = AuthenticationEventHandler.SelectMostRecentAccessToken(
            "living-room",
            candidates);

        Assert.Equal("current", selected);
    }

    [Fact]
    public void SelectMostRecentAccessToken_rejects_missing_or_blank_device_identity()
    {
        var candidates = new[]
        {
            (DeviceId: "device", AccessToken: "token", DateLastActivity: DateTime.UtcNow),
        };

        Assert.Null(AuthenticationEventHandler.SelectMostRecentAccessToken(null, candidates));
        Assert.Null(AuthenticationEventHandler.SelectMostRecentAccessToken(" ", candidates));
    }
}

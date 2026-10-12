using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// #244: an app password is for an app that cannot show the plugin's 2FA
/// challenge. The Jellyfin web interface in a browser can, and an app password
/// typed there signed in with no second factor, admin rights included. These
/// pin how the client is identified and which client is refused.
/// </summary>
public class AppPasswordClientPolicyTests
{
    [Theory]
    // jellyfin-web URL-encodes the header values and Jellyfin decodes them, so
    // the session is "Jellyfin Web" while the raw header says Jellyfin%20Web.
    [InlineData("MediaBrowser Client=\"Jellyfin%20Web\", Device=\"Chrome\", DeviceId=\"abc\", Version=\"12.1.0\"", null, null, "Jellyfin Web")]
    [InlineData("MediaBrowser Client=\"Jellyfin+Web\", Device=\"Chrome\"", null, null, "Jellyfin Web")]
    // The legacy header, then the dedicated one, as fallbacks.
    [InlineData(null, "MediaBrowser Client=\"Jellyfin Web\", Device=\"Firefox\"", null, "Jellyfin Web")]
    [InlineData(null, null, "Jellyfin Web", "Jellyfin Web")]
    // Jellyfin's precedence: the standard Authorization header wins.
    [InlineData("MediaBrowser Client=\"Seerr\", Device=\"Seerr\"", "MediaBrowser Client=\"Jellyfin%20Web\"", "Jellyfin Web", "Seerr")]
    [InlineData(null, null, null, null)]
    [InlineData("MediaBrowser Device=\"Chrome\", DeviceId=\"abc\"", null, null, null)]
    public void The_client_is_named_the_way_Jellyfin_names_the_session(
        string? authorization,
        string? xEmbyAuthorization,
        string? xEmbyClient,
        string? expected)
    {
        Assert.Equal(expected, AppPasswordClientPolicy.ResolveClientName(authorization, xEmbyAuthorization, xEmbyClient));
    }

    [Theory]
    [InlineData("Jellyfin Web", true)]
    [InlineData("jellyfin web", true)]
    [InlineData(" Jellyfin Web ", true)]
    // Jellyfin's own apps that wrap the web interface send their own names
    // and keep working, as do the apps app passwords are meant for.
    [InlineData("Jellyfin for Android", false)]
    [InlineData("Jellyfin Desktop", false)]
    [InlineData("Jellyfin for Tizen", false)]
    [InlineData("Jellyfin for WebOS", false)]
    [InlineData("Seerr", false)]
    [InlineData("Swiftfin", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    public void Only_the_web_interface_refuses_app_passwords(string? client, bool refused)
    {
        Assert.Equal(refused, AppPasswordClientPolicy.IsRefused(client));
    }
}

using System.Diagnostics;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// The verified-token sidecar is what keeps a completed 2FA across a restart.
/// Each test checks the disk the way a restart does: through a new instance
/// loading the same file.
/// </summary>
public class VerifiedTokenPersistenceTests
{
    [Fact]
    public void A_restarted_store_reloads_the_marks_it_wrote()
    {
        var paths = TestApplicationPaths.Create();
        using var store = New(paths, TimeSpan.FromMilliseconds(100));

        store.MarkVerified("first-token");

        Assert.True(Eventually(() => VerifiedAfterRestart(paths, "first-token")));
    }

    [Fact]
    public void A_mark_set_inside_the_write_window_still_reaches_the_disk()
    {
        // At most one write per window, and the first mark writes at once. A
        // second mark inside the window used to be dropped from the write
        // schedule: it reached the disk only with some later mark after the
        // window, and a restart before that lost it.
        var paths = TestApplicationPaths.Create();
        using var store = New(paths, TimeSpan.FromMilliseconds(300));

        store.MarkVerified("first-token");
        Assert.True(Eventually(() => VerifiedAfterRestart(paths, "first-token")));
        store.MarkVerified("second-token");

        Assert.True(Eventually(() => VerifiedAfterRestart(paths, "second-token")));
    }

    [Fact]
    public void Disposing_writes_the_marks_that_have_not_reached_the_disk()
    {
        // Jellyfin disposes this singleton when it shuts down. With a long
        // window nothing else would write the second mark before the restart.
        var paths = TestApplicationPaths.Create();
        var store = New(paths, TimeSpan.FromMinutes(10));

        store.MarkVerified("first-token");
        Assert.True(Eventually(() => VerifiedAfterRestart(paths, "first-token")));
        store.MarkVerified("second-token");
        store.Dispose();

        Assert.True(VerifiedAfterRestart(paths, "first-token"));
        Assert.True(VerifiedAfterRestart(paths, "second-token"));
    }

    private static VerifiedTokenPersistence New(MediaBrowser.Common.Configuration.IApplicationPaths paths, TimeSpan window)
        => new(paths, NullLogger<VerifiedTokenPersistence>.Instance, window);

    private static bool VerifiedAfterRestart(MediaBrowser.Common.Configuration.IApplicationPaths paths, string token)
    {
        using var restarted = new VerifiedTokenPersistence(paths, NullLogger<VerifiedTokenPersistence>.Instance);
        return restarted.IsVerified(token);
    }

    private static bool Eventually(Func<bool> condition)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(50);
        }

        return condition();
    }
}

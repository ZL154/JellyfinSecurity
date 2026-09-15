using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#215] The GeoIP detectors were implemented, registered and never called.
// These tests pin the observer that now carries a completed sign-in to them:
// which sign-ins are worth resolving, and that a server with no GeoIP database
// (the default) is left untouched rather than failing the caller.
public class SignInObserverTests
{
    private static SignInObserver Build(out UserTwoFactorStore store)
    {
        var paths = TestApplicationPaths.Create();
        store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        var notifications = new NotificationService(NullLogger<NotificationService>.Instance);
        var geo = new GeoIpService(NullLogger<GeoIpService>.Instance);
        var suspicious = new SuspiciousLoginDetector(
            store, geo, notifications, NullLogger<SuspiciousLoginDetector>.Instance);
        var travel = new ImpossibleTravelDetector(
            store, notifications, NullLogger<ImpossibleTravelDetector>.Instance);
        return new SignInObserver(suspicious, travel, NullLogger<SignInObserver>.Instance);
    }

    [Fact]
    public void A_sign_in_with_a_user_and_an_address_is_worth_observing()
    {
        Assert.True(SignInObserver.ShouldObserve(Guid.NewGuid(), "8.8.8.8"));
        Assert.True(SignInObserver.ShouldObserve(Guid.NewGuid(), "2001:4860:4860::8888"));
    }

    [Fact]
    public void An_unidentified_user_or_a_missing_address_is_skipped()
    {
        // Guid.Empty reaches the detectors from paths where Jellyfin could not
        // resolve the account; both detectors would refuse it anyway, and
        // stopping here keeps the refusal at one place.
        Assert.False(SignInObserver.ShouldObserve(Guid.Empty, "8.8.8.8"));
        Assert.False(SignInObserver.ShouldObserve(Guid.NewGuid(), null));
        Assert.False(SignInObserver.ShouldObserve(Guid.NewGuid(), string.Empty));
        Assert.False(SignInObserver.ShouldObserve(Guid.NewGuid(), "   "));
    }

    [Fact]
    public async Task With_no_geoip_database_the_sign_in_is_recorded_as_observed_and_the_user_is_untouched()
    {
        var observer = Build(out var store);
        var userId = Guid.NewGuid();

        Assert.Null(observer.LastObservedAt);
        observer.Observe(userId, "alice", "8.8.8.8");
        Assert.NotNull(observer.LastObservedAt);

        // The detectors run on a background task. Give them room to finish so
        // the assertion below is about their decision, not about timing.
        await Task.Delay(200);

        var data = await store.GetUserDataAsync(userId);
        Assert.Empty(data.SeenContexts);
        Assert.Null(data.LastLocation);
    }

    [Fact]
    public void A_skipped_sign_in_does_not_count_as_observed()
    {
        var observer = Build(out _);

        observer.Observe(Guid.Empty, "alice", "8.8.8.8");
        observer.Observe(Guid.NewGuid(), "alice", null);

        Assert.Null(observer.LastObservedAt);
    }

    [Fact]
    public void Every_completed_sign_in_path_in_the_controller_hands_the_resolved_address_to_the_observer()
    {
        // The wiring is the whole point of #215, so pin the call sites: each
        // one passes the proxy-resolved address, never the raw peer. Reading
        // the controller source is the only way to assert this without a full
        // DI harness; the file is found relative to the test assembly.
        var controller = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Api/TwoFactorAuthController.cs");

        var calls = controller
            .Split('\n')
            .Where(line => line.Contains("_signInObserver.Observe(", StringComparison.Ordinal))
            .ToList();

        Assert.Equal(4, calls.Count);
        Assert.All(calls, call => Assert.Matches(@"_signInObserver\.Observe\([^)]*,\s*(clientIp|ip)\);", call));
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

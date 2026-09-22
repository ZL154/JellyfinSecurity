using System;
using System.Collections.Generic;
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
        // the source is the only way to assert this without a full DI harness;
        // the file is found relative to the test assembly.
        var calls = ObserveCalls("src/Jellyfin.Plugin.TwoFactorAuth/Api/TwoFactorAuthController.cs");

        Assert.Equal(4, calls.Count);
        Assert.All(calls, call => Assert.Matches(@"_signInObserver\.Observe\([^)]*,\s*(clientIp|ip)\);", call));
    }

    [Fact]
    public void Every_completed_sign_in_path_in_the_session_handler_hands_the_resolved_address_to_the_observer()
    {
        // The sign-ins that never reach the controller: device pre-verified,
        // QuickConnect, app password, paired device and bypass. The reconnect
        // path is deliberately absent, since a websocket reconnect on an
        // already-verified token is not a fresh sign-in, and so is the
        // challenge path, where no sign-in has happened yet.
        var handler = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/AuthenticationEventHandler.cs");
        var calls = ObserveCalls("src/Jellyfin.Plugin.TwoFactorAuth/Services/AuthenticationEventHandler.cs");

        Assert.Equal(5, calls.Count);
        Assert.All(calls, call => Assert.Matches(@"_signInObserver\.Observe\([^)]*,\s*observedIp\);", call));

        // observedIp must come from the proxy-aware resolution, not RemoteEndPoint.
        Assert.Contains(
            "var observedIp = BypassEvaluator.ResolveClientIp(info.RemoteEndPoint, forwardedFor);",
            handler,
            StringComparison.Ordinal);

        var reconnect = handler.IndexOf("Method = \"reconnect\"", StringComparison.Ordinal);
        Assert.True(reconnect > 0, "the reconnect path should still exist");
        var afterReconnect = handler.Substring(reconnect, Math.Min(400, handler.Length - reconnect));
        Assert.DoesNotContain("_signInObserver.Observe(", afterReconnect, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, false, "no GeoIP database is loaded, so sign-ins are not resolved")]
    [InlineData(true, false, "no sign-in observed since the server started")]
    public void Diagnostics_says_when_no_sign_in_has_reached_the_detectors(
        bool anyDatabaseLoaded, bool observed, string expectedDetail)
    {
        DateTime? last = observed ? DateTime.UtcNow : null;
        var row = DiagnosticsService.SignInObservationCheck(last, anyDatabaseLoaded, DateTime.UtcNow);

        Assert.Equal("signin_observation", row.Id);
        Assert.Equal("Sign-ins reach the GeoIP detectors", row.Label);
        Assert.Equal(DiagnosticsService.CheckStatus.Ok, row.Status);
        Assert.Equal(expectedDetail, row.Detail);
    }

    [Fact]
    public void Diagnostics_reports_how_long_ago_the_last_sign_in_was_observed()
    {
        var now = new DateTime(2026, 9, 15, 20, 0, 0, DateTimeKind.Utc);

        Assert.StartsWith("last sign-in observed less than a minute ago",
            DiagnosticsService.SignInObservationCheck(now.AddSeconds(-30), true, now).Detail);
        Assert.StartsWith("last sign-in observed 5 minute(s) ago",
            DiagnosticsService.SignInObservationCheck(now.AddMinutes(-5), true, now).Detail);
        Assert.StartsWith("last sign-in observed 3 hour(s) ago",
            DiagnosticsService.SignInObservationCheck(now.AddHours(-3), true, now).Detail);
        Assert.EndsWith("(2026-09-15 17:00:00Z)",
            DiagnosticsService.SignInObservationCheck(now.AddHours(-3), true, now).Detail);
    }

    private static List<string> ObserveCalls(string repoRelativePath)
        => SourceFile(repoRelativePath)
            .Split('\n')
            .Where(line => line.Contains("_signInObserver.Observe(", StringComparison.Ordinal))
            .ToList();

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

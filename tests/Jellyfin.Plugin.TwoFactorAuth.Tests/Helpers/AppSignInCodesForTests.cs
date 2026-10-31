using System;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;

/// <summary>[#313] An AppSignInCodeService on real collaborators, reading
/// <paramref name="config"/> instead of Plugin.Instance. Mail and Telegram
/// aren't configured, so codes are issued but nothing is delivered; tests
/// set <see cref="AppSignInCodeService.NewCode"/> to know the code.</summary>
internal static class AppSignInCodesForTests
{
    internal static AppSignInCodeService Build(
        IApplicationPaths paths,
        UserTwoFactorStore store,
        IUserManager users,
        IApplicationHost host,
        ChallengeStore challenges,
        Func<PluginConfiguration?> config,
        ILogger<AppSignInCodeService>? logger = null)
    {
        var notifications = new NotificationService(NullLogger<NotificationService>.Instance);
        var geo = new GeoIpService(NullLogger<GeoIpService>.Instance);
        var observer = new SignInObserver(
            new SuspiciousLoginDetector(store, geo, notifications, NullLogger<SuspiciousLoginDetector>.Instance),
            new ImpossibleTravelDetector(store, notifications, NullLogger<ImpossibleTravelDetector>.Instance),
            NullLogger<SignInObserver>.Instance);
        return new AppSignInCodeService(
            store,
            users,
            host,
            new EmailOtpService(NullLogger<EmailOtpService>.Instance),
            notifications,
            new RateLimiter(),
            challenges,
            new PendingPairingService(NullLogger<PendingPairingService>.Instance),
            observer,
            new IpBanService(paths, NullLogger<IpBanService>.Instance),
            logger ?? NullLogger<AppSignInCodeService>.Instance,
            config);
    }
}

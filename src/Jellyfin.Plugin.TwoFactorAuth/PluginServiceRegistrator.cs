using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Jellyfin.Plugin.TwoFactorAuth;

public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<UserTwoFactorStore>();
        serviceCollection.AddSingleton<ChallengeStore>();
        serviceCollection.AddSingleton<TotpService>();
        serviceCollection.AddSingleton<EmailOtpService>();
        serviceCollection.AddSingleton<DeviceTokenService>();
        serviceCollection.AddSingleton<DevicePairingService>();
        serviceCollection.AddSingleton<BypassEvaluator>();
        serviceCollection.AddSingleton<NotificationService>();
        serviceCollection.AddSingleton<CookieSigner>();
        serviceCollection.AddSingleton<RateLimiter>();
        serviceCollection.AddSingleton<RecoveryCodeService>();
        serviceCollection.AddSingleton<AppPasswordService>();
        serviceCollection.AddSingleton<PendingPairingService>();
        serviceCollection.AddSingleton<SessionTerminationService>();
        serviceCollection.AddSingleton<PasskeyChallengeStore>();
        serviceCollection.AddSingleton<PasskeyService>();
        serviceCollection.AddSingleton<GeoIpService>();
        serviceCollection.AddSingleton<SuspiciousLoginDetector>();
        serviceCollection.AddSingleton<DiagnosticsService>();
        serviceCollection.AddSingleton<StatsService>();
        serviceCollection.AddSingleton<UserExportService>();
        serviceCollection.AddSingleton<RecoveryCodePdfService>();
        serviceCollection.AddHostedService<SelfIpDetector>();
        // v2.0
        serviceCollection.AddSingleton<OidcService>();
        serviceCollection.AddSingleton<IpBanService>();
        serviceCollection.AddSingleton<ImpossibleTravelDetector>();
        serviceCollection.AddSingleton<IpAllowlistService>();
        serviceCollection.AddSingleton<OidcLoginTokenStore>();
        // v2.4: HIBP password-breach check. Typed HttpClient gets its own
        // configured client so the 3-second timeout in HibpService doesn't
        // bleed into other Jellyfin HTTP calls.
        serviceCollection.AddHttpClient<HibpService>();
        serviceCollection.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        serviceCollection.AddSingleton<IStartupFilter, TwoFactorStartupFilter>();
        serviceCollection.AddHostedService<AuthenticationEventHandler>();

        // CRITICAL: Jellyfin discovers auth providers through DI, not MEF.
        // Without this line the provider class is never invoked — which is
        // why app passwords and the 2FA gate were completely inert in every
        // release prior to this one. The LDAP plugin does it the same way:
        // https://github.com/jellyfin/jellyfin-plugin-ldapauth/blob/master/LDAP-Auth/ServiceRegistrator.cs
        serviceCollection.AddSingleton<IAuthenticationProvider, TwoFactorAuthProvider>();
    }
}

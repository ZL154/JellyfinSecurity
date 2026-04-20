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
    public void RegisterServices(IServiceCollection services, IServerApplicationHost appHost)
    {
        services.AddSingleton<UserTwoFactorStore>();
        services.AddSingleton<ChallengeStore>();
        services.AddSingleton<TotpService>();
        services.AddSingleton<EmailOtpService>();
        services.AddSingleton<DeviceTokenService>();
        services.AddSingleton<DevicePairingService>();
        services.AddSingleton<BypassEvaluator>();
        services.AddSingleton<NotificationService>();
        services.AddSingleton<CookieSigner>();
        services.AddSingleton<RateLimiter>();
        services.AddSingleton<RecoveryCodeService>();
        services.AddSingleton<AppPasswordService>();
        services.AddSingleton<PendingPairingService>();
        services.AddSingleton<SessionTerminationService>();
        services.AddSingleton<PasskeyChallengeStore>();
        services.AddSingleton<PasskeyService>();
        services.AddSingleton<GeoIpService>();
        services.AddSingleton<SuspiciousLoginDetector>();
        services.AddSingleton<DiagnosticsService>();
        services.AddSingleton<StatsService>();
        services.AddSingleton<UserExportService>();
        services.AddSingleton<RecoveryCodePdfService>();
        services.AddHostedService<SelfIpDetector>();
        // v2.0
        services.AddSingleton<OidcService>();
        services.AddSingleton<IpBanService>();
        services.AddSingleton<ImpossibleTravelDetector>();
        services.AddSingleton<IpAllowlistService>();
        services.AddSingleton<OidcLoginTokenStore>();
        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.AddSingleton<IStartupFilter, TwoFactorStartupFilter>();
        services.AddHostedService<AuthenticationEventHandler>();

        // CRITICAL: Jellyfin discovers auth providers through DI, not MEF.
        // Without this line the provider class is never invoked — which is
        // why app passwords and the 2FA gate were completely inert in every
        // release prior to this one. The LDAP plugin does it the same way:
        // https://github.com/jellyfin/jellyfin-plugin-ldapauth/blob/master/LDAP-Auth/ServiceRegistrator.cs
        services.AddSingleton<IAuthenticationProvider, TwoFactorAuthProvider>();
    }
}

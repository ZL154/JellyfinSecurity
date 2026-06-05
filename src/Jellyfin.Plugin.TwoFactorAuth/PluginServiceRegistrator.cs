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
        // [v2.5.7] (issue #52): persistent verified-token hash store must
        // register BEFORE ChallengeStore so DI can inject it via the ctor.
        serviceCollection.AddSingleton<VerifiedTokenPersistence>();
        serviceCollection.AddSingleton<ChallengeStore>();
        serviceCollection.AddSingleton<StepUpService>();
        serviceCollection.AddSingleton<SecurityScoreService>();
        serviceCollection.AddSingleton<ConfigExportService>();
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
        // v2.5.5: scans all users at startup, warns about any with empty
        // password hash. Read-only audit; the auth-time block in
        // TwoFactorAuthProvider does the actual exploit mitigation.
        serviceCollection.AddHostedService<EmptyPasswordAuditService>();
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

        // SECURITY [v2.5.6] (ext review admin step-up incomplete): register a
        // global MVC action filter that gates POSTs to Jellyfin's generic
        // /Plugins/<our-guid>/Configuration endpoint via the existing
        // StepUpService. The filter and the IConfigureOptions<MvcOptions>
        // adapter are both DI-resolved.
        serviceCollection.AddSingleton<PluginConfigStepUpFilter>();
        serviceCollection.AddSingleton<
            Microsoft.Extensions.Options.IConfigureOptions<Microsoft.AspNetCore.Mvc.MvcOptions>,
            PluginMvcOptionsSetup>();
        serviceCollection.AddHostedService<AuthenticationEventHandler>();

        // CRITICAL: Jellyfin discovers auth providers through DI, not MEF.
        // Without this line the provider class is never invoked — which is
        // why app passwords and the 2FA gate were completely inert in every
        // release prior to this one. The LDAP plugin does it the same way:
        // https://github.com/jellyfin/jellyfin-plugin-ldapauth/blob/master/LDAP-Auth/ServiceRegistrator.cs
        serviceCollection.AddSingleton<IAuthenticationProvider, TwoFactorAuthProvider>();
    }
}

using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

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
        services.AddSingleton<NotificationService>();
        services.AddSingleton<BypassEvaluator>();
        services.AddSingleton<TwoFactorAuthProvider>();
        services.AddSingleton<IAuthenticationProvider>(sp => sp.GetRequiredService<TwoFactorAuthProvider>());
        services.AddHttpClient("TwoFactorAuth");
    }
}

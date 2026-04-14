using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller;
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
        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.AddSingleton<IStartupFilter, TwoFactorStartupFilter>();
        services.AddHostedService<AuthenticationEventHandler>();
    }
}

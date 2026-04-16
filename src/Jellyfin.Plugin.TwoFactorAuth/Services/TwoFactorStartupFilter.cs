using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class TwoFactorStartupFilter : IStartupFilter
{
    private readonly ILogger<TwoFactorStartupFilter> _logger;

    public TwoFactorStartupFilter(ILogger<TwoFactorStartupFilter> logger)
    {
        _logger = logger;
    }

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        _logger.LogInformation("[2FA] Startup filter invoked — registering middleware");
        return app =>
        {
            app.UseMiddleware<IndexHtmlInjectionMiddleware>();
            app.UseMiddleware<TwoFactorEnforcementMiddleware>();
            app.UseMiddleware<RequestBlockerMiddleware>();
            _logger.LogInformation("[2FA] Middleware registered into pipeline");
            next(app);
        };
    }
}

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
        _logger.LogDebug("[2FA] Startup filter invoked — registering middleware");
        return app =>
        {
            app.UseMiddleware<IndexHtmlInjectionMiddleware>();
            // [v2.5.10] (#55) emits a recognizable lockout 401 on AuthenticateByName
            // so the login page can show a "temporarily locked" message.
            app.UseMiddleware<LockoutMessageMiddleware>();
            // [#312] After the lockout middleware, so its gates see what was
            // typed and it counts the outcome; before the rest, so they all
            // see the password alone.
            app.UseMiddleware<CodeAfterPasswordMiddleware>();
            app.UseMiddleware<TrustCookieMiddleware>();
            app.UseMiddleware<TwoFactorEnforcementMiddleware>();
            app.UseMiddleware<RequestBlockerMiddleware>();
            _logger.LogDebug("[2FA] Middleware registered into pipeline");
            next(app);
        };
    }
}

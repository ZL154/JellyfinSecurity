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
            // [#298] First of all, before Jellyfin's forwarded-headers handling
            // can rewrite it: the address the TCP connection really came from,
            // the only one the proxy header sign-in will trust.
            app.Use((context, nextMiddleware) =>
            {
                HeaderSignIn.RememberRawPeer(context);
                return nextMiddleware(context);
            });
            app.UseMiddleware<IndexHtmlInjectionMiddleware>();
            // [v2.5.10] (#55) emits a recognizable lockout 401 on AuthenticateByName
            // so the login page can show a "temporarily locked" message.
            app.UseMiddleware<LockoutMessageMiddleware>();
            app.UseMiddleware<TrustCookieMiddleware>();
            app.UseMiddleware<TwoFactorEnforcementMiddleware>();
            app.UseMiddleware<RequestBlockerMiddleware>();
            _logger.LogDebug("[2FA] Middleware registered into pipeline");
            next(app);
        };
    }
}

using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#268] On Jellyfin's GET /Plugins/&lt;our-guid&gt;/Configuration, hands the
/// admin page <see cref="ConfigSecrets.Redact"/>'s copy instead of the live
/// configuration, so no saved password, token or key reaches the browser. The
/// action still returns the live object; only what is sent is swapped.
/// Registered globally next to <see cref="PluginConfigStepUpFilter"/>, since
/// that controller belongs to Jellyfin core.
/// </summary>
public class PluginConfigSecretsFilter : IAsyncResultFilter
{
    public Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        var request = context.HttpContext.Request;
        if (HttpMethods.IsGet(request.Method)
            && PluginConfigStepUpFilter.IsThisPluginsConfigurationPath(request.Path.Value)
            && context.Result is ObjectResult { Value: PluginConfiguration live } result)
        {
            result.Value = ConfigSecrets.Redact(live);
        }

        return next();
    }
}

using System;
using System.Threading.Tasks;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#213] Jellyfin's Disable only rewrites the plugin's meta.json and never tells
/// the plugin, and a disabled plugin is not loaded at the next start, so every
/// account on <see cref="TwoFactorAuthProvider"/> was refused from then on,
/// administrators included. Once Jellyfin has disabled this plugin, the accounts
/// are handed back the way an uninstall hands them back; enabling the plugin
/// again and restarting takes them back (<see cref="SignInProviderReclaimService"/>).
/// Registered globally by <see cref="PluginMvcOptionsSetup"/>, because the action
/// belongs to Jellyfin's own PluginsController.
/// </summary>
public class PluginDisableHandBackFilter : IAsyncActionFilter
{
    // Plugin.Id, kept in sync by hand as in PluginConfigStepUpFilter.
    private static readonly Guid PluginGuid = new("94879a0c-da24-4eb1-aa06-f28b4b9333b1");

    private const string PluginsControllerType = "Jellyfin.Api.Controllers.PluginsController";

    private readonly IApplicationHost _appHost;
    private readonly IApplicationPaths _paths;
    private readonly ILogger<PluginDisableHandBackFilter> _logger;

    public PluginDisableHandBackFilter(
        IApplicationHost appHost,
        IApplicationPaths paths,
        ILogger<PluginDisableHandBackFilter> logger)
    {
        _appHost = appHost;
        _paths = paths;
        _logger = logger;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var executed = await next().ConfigureAwait(false);
        if (IsThisPluginsDisable(context) && Succeeded(executed))
        {
            await SignInProviderRestore.HandBackAsync(_appHost, _paths, "Disable", _logger).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Jellyfin's own DisablePlugin action, for this plugin. The id is compared
    /// by value after model binding, so every GUID format the route accepts
    /// matches.
    /// </summary>
    internal static bool IsThisPluginsDisable(ActionExecutingContext context)
        => context.ActionDescriptor is ControllerActionDescriptor action
            && string.Equals(action.ControllerTypeInfo.FullName, PluginsControllerType, StringComparison.Ordinal)
            && string.Equals(action.ActionName, "DisablePlugin", StringComparison.Ordinal)
            && context.ActionArguments.TryGetValue("pluginId", out var id)
            && id is Guid pluginId
            && pluginId == PluginGuid;

    /// <summary>Jellyfin answers 204 once the plugin is marked disabled, and 404 when it has no such version.</summary>
    internal static bool Succeeded(ActionExecutedContext executed)
        => executed.Exception is null
            && executed.Result is IStatusCodeActionResult { StatusCode: StatusCodes.Status204NoContent };
}

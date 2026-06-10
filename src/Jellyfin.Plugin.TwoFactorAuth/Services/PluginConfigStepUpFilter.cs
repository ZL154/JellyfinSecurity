using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// SECURITY [v2.5.6] (ext review admin step-up incomplete): a global
/// IAsyncActionFilter that gates POSTs to Jellyfin's generic
/// /Plugins/&lt;our-guid&gt;/Configuration endpoint when step-up is
/// configured. Jellyfin's controller saves the entire PluginConfiguration
/// blob — including security-critical fields like EnforcementScope,
/// StepUpLevel, BareDeviceIdBypassEnabled — without going through our
/// plugin-owned hardening endpoints. A stolen admin session could
/// therefore disable the step-up requirement itself before performing
/// other config changes.
///
/// Action filter runs AFTER Jellyfin's authentication middleware (so
/// HttpContext.User has the Jellyfin-UserId claim) and BEFORE the
/// controller action executes — perfect place to short-circuit with 403
/// when the admin lacks a valid step-up token. Matches StepUpGuard's
/// classification (StepUpAction.ConfigChange → AllConfigChanges level).
///
/// Registered globally via PluginMvcOptionsSetup so the filter is
/// installed even though the target controller belongs to Jellyfin core,
/// not this plugin.
/// </summary>
public class PluginConfigStepUpFilter : IAsyncActionFilter
{
    // Match the literal in Plugin.Id (kept in sync manually since Plugin.Id
    // is an instance property and we need a static path-string at construct).
    private static readonly Guid PluginGuid = new("94879a0c-da24-4eb1-aa06-f28b4b9333b1");

    private readonly StepUpService _stepUp;
    private readonly ILogger<PluginConfigStepUpFilter> _logger;

    public PluginConfigStepUpFilter(StepUpService stepUp, ILogger<PluginConfigStepUpFilter> logger)
    {
        _stepUp = stepUp;
        _logger = logger;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (!ShouldGate(context.HttpContext))
        {
            await next().ConfigureAwait(false);
            return;
        }

        // User identity should be populated by Jellyfin's auth middleware
        // before any action filter runs. If we can't find it, we deny
        // (fail-closed) — the request didn't go through normal auth.
        var claim = context.HttpContext.User?.FindFirst("Jellyfin-UserId");
        if (claim is null || !Guid.TryParse(claim.Value, out var userId))
        {
            context.Result = new ObjectResult(new
            {
                message = "Plugin configuration writes require an authenticated admin session.",
                stepUpRequired = true,
            })
            {
                StatusCode = StatusCodes.Status403Forbidden,
            };
            return;
        }

        // Classify as ConfigChange — same level as our plugin-owned config endpoints.
        if (_stepUp.NeedsStepUpToken(userId, StepUpAction.ConfigChange))
        {
            _logger.LogWarning(
                "[2FA] Blocked plugin-config POST by admin {UserId} — step-up required",
                userId);
            context.Result = new ObjectResult(new
            {
                message = "Step-up authentication required to save plugin configuration. Verify a fresh TOTP/recovery code, then retry.",
                stepUpRequired = true,
            })
            {
                StatusCode = StatusCodes.Status403Forbidden,
            };
            return;
        }

        await next().ConfigureAwait(false);
    }

    private static bool ShouldGate(HttpContext ctx)
    {
        if (!HttpMethods.IsPost(ctx.Request.Method)) return false;
        var path = ctx.Request.Path.Value;
        if (string.IsNullOrEmpty(path)) return false;

        // SECURITY [v2.5.9] (audit top-tier #2): do NOT string-match the
        // hyphenated GUID with EndsWith. ASP.NET's Guid route constraint also
        // accepts the compact "N" form (32 hex, no hyphens), the "B"/"P"
        // forms, and a trailing slash — all of which still route to
        // Jellyfin's PluginsController config-save action but slipped past
        // the old check, letting a hijacked admin session disable step-up
        // via POST /Plugins/<compact-guid>/Configuration. Instead, scan the
        // path for the [Plugins / <guid> / Configuration] triple and compare
        // the GUID BY VALUE (Guid.TryParse accepts every format), case- and
        // trailing-slash-insensitive, and tolerant of reverse-proxy subpaths.
        var seg = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i <= seg.Length - 3; i++)
        {
            if (seg[i].Equals("Plugins", StringComparison.OrdinalIgnoreCase)
                && Guid.TryParse(seg[i + 1], out var g) && g == PluginGuid
                && seg[i + 2].Equals("Configuration", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}

/// <summary>SECURITY [v2.5.6]: registers <see cref="PluginConfigStepUpFilter"/>
/// as a global MVC filter so it runs against every controller action,
/// including Jellyfin core's PluginsController. Plugin-owned controllers
/// also pay this filter but short-circuit on path mismatch — no
/// observable cost.</summary>
public class PluginMvcOptionsSetup : IConfigureOptions<Microsoft.AspNetCore.Mvc.MvcOptions>
{
    public void Configure(Microsoft.AspNetCore.Mvc.MvcOptions options)
    {
        options.Filters.Add<PluginConfigStepUpFilter>();
    }
}

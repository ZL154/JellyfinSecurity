using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [v2.5.10] (issue #55) Surfaces account lockout at the LOGIN step so the user
/// sees a clear "temporarily locked" message instead of Jellyfin's generic
/// "Invalid username or password".
///
/// The provider (TwoFactorAuthProvider) enforces the lockout by throwing an
/// AuthenticationException, but Jellyfin's ExceptionMiddleware strips the
/// message in production and returns a generic 401 ("Error processing
/// request."), so the web client can't distinguish a lockout from a wrong
/// password. This middleware checks lockout for the submitted username on
/// POST /Users/AuthenticateByName and, when locked, short-circuits with a
/// recognizable 401 JSON body ({"accountLocked":true,...}). inject.js detects
/// that marker (the same way it detects twoFactorRequired) and shows a toast.
///
/// Fails OPEN: any error in the pre-check lets the request flow to the normal
/// pipeline, so a bug here can never block legitimate logins. IsLockedOutAsync
/// honours the admin exemption, so an exempt administrator is never blocked.
/// </summary>
public class LockoutMessageMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly ILogger<LockoutMessageMiddleware> _logger;

    public LockoutMessageMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        IUserManager userManager,
        ILogger<LockoutMessageMiddleware> logger)
    {
        _next = next;
        _store = store;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (await ShouldBlockAsync(context).ConfigureAwait(false))
        {
            _logger.LogInformation("[2FA] Login short-circuited with lockout message for a locked account.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Your account is temporarily locked due to too many failed sign-in attempts. Please try again later.\",\"accountLocked\":true}")
                .ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private async Task<bool> ShouldBlockAsync(HttpContext context)
    {
        try
        {
            if (!HttpMethods.IsPost(context.Request.Method))
            {
                return false;
            }

            var path = (context.Request.Path.Value ?? string.Empty).TrimEnd('/');
            if (!path.EndsWith("/Users/AuthenticateByName", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var config = Plugin.Instance?.Configuration;
            if (config is null || !config.Enabled)
            {
                return false;
            }

            // The auth payload is tiny; refuse to buffer anything unexpectedly large.
            if (context.Request.ContentLength is > 8192)
            {
                return false;
            }

            var username = await PeekUsernameAsync(context.Request).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(username))
            {
                return false;
            }

            var user = _userManager.GetUserByName(username);
            if (user is null)
            {
                // Unknown username — don't reveal anything; let the normal 401 flow run.
                return false;
            }

            return await _store.IsLockedOutAsync(user.Id).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Fail OPEN — never block a login because the lockout-message
            // pre-check threw.
            _logger.LogDebug(ex, "[2FA] lockout-message pre-check failed; passing the request through");
            return false;
        }
    }

    /// <summary>Read the JSON body's username without consuming it for the
    /// downstream pipeline (EnableBuffering + rewind).</summary>
    private static async Task<string?> PeekUsernameAsync(HttpRequest request)
    {
        request.EnableBuffering();
        string body;
        using (var reader = new StreamReader(
            request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
        {
            body = await reader.ReadToEndAsync().ConfigureAwait(false);
        }

        request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var name in new[] { "Username", "username", "Name", "name" })
        {
            if (doc.RootElement.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
            {
                return el.GetString();
            }
        }

        return null;
    }
}

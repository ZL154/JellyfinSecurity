using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Injects a small script tag into Jellyfin's web index.html that intercepts
/// the 2FA 401 response from the login API and redirects the browser to the
/// challenge page. Non-web requests pass through untouched.
/// </summary>
public class IndexHtmlInjectionMiddleware
{
    private const string ScriptTag = "<script src=\"/TwoFactorAuth/inject.js\" defer></script>";
    private const string InjectionMarker = "<!-- twofactor-inject -->";

    private readonly RequestDelegate _next;
    private readonly ILogger<IndexHtmlInjectionMiddleware> _logger;

    // v1.4 diagnostics: count requests we've SEEN (regardless of whether we
    // injected). Used by DiagnosticsService to confirm the middleware is
    // actually wired into the pipeline. Counter resets on Jellyfin restart.
    private static long _requestsSeen;
    public static long RequestsSeen => System.Threading.Interlocked.Read(ref _requestsSeen);

    public IndexHtmlInjectionMiddleware(RequestDelegate next, ILogger<IndexHtmlInjectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsIndexHtmlRequest(context))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        System.Threading.Interlocked.Increment(ref _requestsSeen);

        // Strip Accept-Encoding on the INCOMING request so upstream handlers
        // (Kestrel static file, Jellyfin web) respond with identity-encoded
        // bytes we can safely inject a script tag into. Restoring the header
        // afterwards isn't needed — this middleware only runs on /web/ index
        // requests, and downstream handlers don't re-read the request header.
        // The browser gets its response uncompressed; slightly larger payload
        // but /web/ index is tiny.
        context.Request.Headers.Remove("Accept-Encoding");

        var originalBody = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch
        {
            context.Response.Body = originalBody;
            buffer.Position = 0;
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            throw;
        }

        context.Response.Body = originalBody;
        buffer.Position = 0;

        var contentType = context.Response.ContentType ?? string.Empty;
        if (!contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase)
            || context.Response.StatusCode != StatusCodes.Status200OK)
        {
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            return;
        }

        // If the upstream response is already compressed (Kestrel's static
        // file handler gzips pre-encoded .gz assets), we'd need to decompress,
        // inject, and recompress. Simpler and safer: pass through untouched.
        // The inject.js script is also served via a direct plugin route so
        // non-patched /web/ responses don't break functionality — the browser
        // still loads inject.js on other pages where we DO manage to inject.
        var contentEncoding = context.Response.Headers.ContentEncoding.ToString();
        if (!string.IsNullOrEmpty(contentEncoding) && !contentEncoding.Equals("identity", StringComparison.OrdinalIgnoreCase))
        {
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
            return;
        }

        try
        {
            var html = Encoding.UTF8.GetString(buffer.ToArray());
            if (html.Contains(InjectionMarker, StringComparison.Ordinal))
            {
                // Already patched
                await originalBody.WriteAsync(Encoding.UTF8.GetBytes(html)).ConfigureAwait(false);
                return;
            }

            var bodyCloseIndex = html.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
            if (bodyCloseIndex < 0)
            {
                await originalBody.WriteAsync(Encoding.UTF8.GetBytes(html)).ConfigureAwait(false);
                return;
            }

            var patched = html.Insert(bodyCloseIndex, InjectionMarker + ScriptTag);
            var patchedBytes = Encoding.UTF8.GetBytes(patched);
            context.Response.ContentLength = patchedBytes.Length;
            await originalBody.WriteAsync(patchedBytes).ConfigureAwait(false);
            _logger.LogDebug("[2FA] Injected inject.js script into {Path}", context.Request.Path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to inject 2FA script into index.html; serving original");
            buffer.Position = 0;
            await buffer.CopyToAsync(originalBody).ConfigureAwait(false);
        }
    }

    private static bool IsIndexHtmlRequest(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            return false;
        }

        var path = context.Request.Path.Value;
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        return path.Equals("/web/", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/web", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/web/index.html", StringComparison.OrdinalIgnoreCase);
    }
}

using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class IndexHtmlInjectionMiddlewareTests
{
    [Theory]
    [InlineData("", "/web/index.html")]
    [InlineData("/jellyfin", "/web/index.html")]
    [InlineData("", "/jellyfin/web/index.html")]
    public async Task InjectedScriptUrl_IsRelativeToJellyfinWebDirectory(string pathBase, string requestPath)
    {
        var middleware = new IndexHtmlInjectionMiddleware(
            async context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.WriteAsync("<html><head><title>Jellyfin</title></head><body></body></html>");
            },
            NullLogger<IndexHtmlInjectionMiddleware>.Instance);

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.PathBase = pathBase;
        context.Request.Path = requestPath;
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8);
        var html = await reader.ReadToEndAsync();
        Assert.Contains("<script src=\"../TwoFactorAuth/inject?v=", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script src=\"/TwoFactorAuth/inject", html, StringComparison.Ordinal);

        var documentUrl = new Uri($"https://example.test{pathBase}/web/index.html");
        var expected = new Uri($"https://example.test{pathBase}/TwoFactorAuth/inject");
        Assert.Equal(expected.AbsolutePath, new Uri(documentUrl, "../TwoFactorAuth/inject").AbsolutePath);
    }

    [Fact]
    public async Task PatchedIndex_DiscardsUpstreamValidatorsAndPreventsCaching()
    {
        var middleware = new IndexHtmlInjectionMiddleware(
            async context =>
            {
                Assert.False(context.Request.Headers.ContainsKey("If-None-Match"));
                Assert.False(context.Request.Headers.ContainsKey("If-Modified-Since"));
                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "text/html; charset=utf-8";
                context.Response.Headers.ETag = "\"jellyfin-original\"";
                context.Response.Headers.LastModified = "Wed, 22 Jul 2026 00:00:00 GMT";
                await context.Response.WriteAsync("<html><head></head><body></body></html>");
            },
            NullLogger<IndexHtmlInjectionMiddleware>.Instance);

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/web/index.html";
        context.Request.Headers.IfNoneMatch = "\"old-unpatched-shell\"";
        context.Request.Headers.IfModifiedSince = "Tue, 21 Jul 2026 00:00:00 GMT";
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        Assert.False(context.Response.Headers.ContainsKey("ETag"));
        Assert.False(context.Response.Headers.ContainsKey("Last-Modified"));
        Assert.Contains("no-store", context.Response.Headers.CacheControl.ToString(), StringComparison.Ordinal);
        Assert.Equal("no-cache", context.Response.Headers.Pragma.ToString());
        Assert.Equal("0", context.Response.Headers.Expires.ToString());
    }

    [Fact]
    public void RequestBlocker_NormalizesConfiguredBaseUrl()
    {
        Assert.Equal(
            "/TwoFactorAuth/Verify",
            RequestBlockerMiddleware.NormalizePluginPath("/jellyfin/TwoFactorAuth/Verify/"));
        Assert.Equal(
            "/TwoFactorAuth/Verify",
            RequestBlockerMiddleware.NormalizePluginPath("/TwoFactorAuth/Verify"));
    }

    [Fact]
    public void AndroidOidcBreakout_UsesBaseAwareServerUrls()
    {
        var html = SecurityController.BuildWebViewBreakoutHtml(
            "https://idp.example/authorize",
            "Example",
            "oidcpoll_test");

        Assert.Contains("function su(p)", html, StringComparison.Ordinal);
        Assert.Contains("fetch(su('Users/AuthenticateByName')", html, StringComparison.Ordinal);
        Assert.Contains("fetch(su('TwoFactorAuth/Oidc/DevicePoll", html, StringComparison.Ordinal);
        Assert.DoesNotContain("fetch('/Users/AuthenticateByName", html, StringComparison.Ordinal);
        Assert.DoesNotContain("window.location.href='/web/index.html'", html, StringComparison.Ordinal);
    }
}

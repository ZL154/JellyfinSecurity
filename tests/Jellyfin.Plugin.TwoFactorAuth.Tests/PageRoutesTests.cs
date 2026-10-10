using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#254] The Setup page asked <c>GET TwoFactorAuth/Setup/Status</c>
/// whether to show two of its cards. No controller ever declared that route:
/// it answered 404, the page swallowed the error, and both cards stayed hidden
/// for every account. The page-contract tests read the pages and the server
/// tests read the controllers, so nothing compared the two.</summary>
public class PageRoutesTests
{
    private const string PagePrefix = "Jellyfin.Plugin.TwoFactorAuth.Pages.";

    /// <summary>A quoted path into the plugin's API, the way the pages write
    /// it: <c>'TwoFactorAuth/...'</c>, <c>'/TwoFactorAuth/...'</c> or
    /// <c>'../TwoFactorAuth/...'</c>. A literal that a value is appended to
    /// (<c>'TwoFactorAuth/Devices/' + id</c>) keeps its trailing slash.</summary>
    private static readonly Regex PathLiteral = new(
        @"['""`](?:\.\./|/)?TwoFactorAuth/(?<path>[A-Za-z][^'""`\s]*)['""`]",
        RegexOptions.Compiled);

    /// <summary>The same literal behind a request helper that takes the HTTP
    /// method first: <c>api('GET', ...)</c> and
    /// <c>mutateWithStepUp('POST', ...)</c> on the Setup page.</summary>
    private static readonly Regex VerbFirstCall = new(
        @"\b(?:api|apiCall|tfaApi|apiFetch|mutateWithStepUp)\(\s*['""](?<verb>GET|POST|PUT|DELETE|PATCH)['""]\s*,\s*['""]TwoFactorAuth/(?<path>[^'""]*)['""]",
        RegexOptions.Compiled);

    /// <summary>... or one named after the method:
    /// <c>apiGet('TwoFactorAuth/...')</c> and the like in the admin script.</summary>
    private static readonly Regex VerbInNameCall = new(
        @"\bapi(?<verb>Get|Post|Put|Delete|Patch)\(\s*['""]TwoFactorAuth/(?<path>[^'""]*)['""]",
        RegexOptions.Compiled);

    private sealed record DeclaredRoute(string Verb, string[] Segments);

    [Fact]
    public void Every_plugin_route_a_page_calls_is_declared_by_a_controller()
    {
        var routes = DeclaredRoutes();
        var missing = new List<string>();
        var found = 0;
        var foundWithVerb = 0;

        foreach (var page in PageResources())
        {
            var text = ResourceReader.ReadEmbeddedText(page);
            Assert.NotNull(text);
            var withVerb = new HashSet<string>(StringComparer.Ordinal);

            foreach (var call in VerbFirstCall.Matches(text).Concat(VerbInNameCall.Matches(text)))
            {
                var verb = call.Groups["verb"].Value.ToUpperInvariant();
                var path = call.Groups["path"].Value;
                withVerb.Add(path);
                found++;
                foundWithVerb++;
                if (!routes.Any(r => r.Verb == verb && Serves(r.Segments, path)))
                {
                    missing.Add($"{page[PagePrefix.Length..]}: {verb} TwoFactorAuth/{path}");
                }
            }

            foreach (Match literal in PathLiteral.Matches(text))
            {
                var path = literal.Groups["path"].Value;
                if (withVerb.Contains(path))
                {
                    continue;
                }

                found++;
                if (!routes.Any(r => Serves(r.Segments, path)))
                {
                    missing.Add($"{page[PagePrefix.Length..]}: TwoFactorAuth/{path}");
                }
            }
        }

        // Floors, so a change in how the pages build their URLs or call their
        // helpers cannot turn this into a test that checks nothing.
        Assert.True(found >= 100, $"Only {found} plugin paths found in the pages.");
        Assert.True(foundWithVerb >= 60, $"Only {foundWithVerb} of them came with an HTTP method.");
        Assert.Empty(missing);
    }

    [Fact]
    public void Setup_page_finishes_a_rotation_on_the_server_and_offers_no_qr_pairing()
    {
        var page = ResourceReader.ReadEmbeddedText(PagePrefix + "setup.html");
        Assert.NotNull(page);

        Assert.Contains("document.getElementById('cardTotpRotate').style.display = totpOn ? 'block' : 'none';", page);
        Assert.Contains("api('POST', 'TwoFactorAuth/Setup/Totp/Rotate/Confirm', { code: code })", page);
        Assert.DoesNotContain("Setup/Status", page);
        Assert.DoesNotContain("QrPair", page);
    }

    private static IEnumerable<string> PageResources()
        => typeof(Plugin).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(PagePrefix, StringComparison.Ordinal)
                        && (n.EndsWith(".html", StringComparison.Ordinal) || n.EndsWith(".js", StringComparison.Ordinal)));

    private static List<DeclaredRoute> DeclaredRoutes()
    {
        var routes = new List<DeclaredRoute>();
        var controllers = typeof(Plugin).Assembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract);
        foreach (var controller in controllers)
        {
            var prefixes = controller.GetCustomAttributes<RouteAttribute>()
                .Select(r => r.Template)
                .DefaultIfEmpty(string.Empty)
                .ToList();
            foreach (var method in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                foreach (var http in method.GetCustomAttributes<HttpMethodAttribute>())
                {
                    foreach (var prefix in prefixes)
                    {
                        var segments = Segments(prefix + "/" + http.Template);
                        routes.AddRange(http.HttpMethods.Select(verb => new DeclaredRoute(verb, segments)));
                    }
                }
            }
        }

        Assert.True(routes.Count >= 100, $"Only {routes.Count} routes found on the controllers.");
        return routes;
    }

    /// <summary>Whether a route serves a path a page builds. A path ending in
    /// '/' is a prefix: the route must go on with a parameter right there. A
    /// route parameter matches any single segment.</summary>
    private static bool Serves(string[] route, string pagePath)
    {
        var path = pagePath.Split('?')[0];
        var isPrefix = path.EndsWith('/') && !pagePath.Contains('?', StringComparison.Ordinal);
        var wanted = Segments("TwoFactorAuth/" + path);

        if (isPrefix)
        {
            if (route.Length <= wanted.Length || route[wanted.Length] != "{}")
            {
                return false;
            }
        }
        else if (route.Length != wanted.Length)
        {
            return false;
        }

        for (var i = 0; i < wanted.Length; i++)
        {
            if (route[i] != "{}" && route[i] != wanted[i])
            {
                return false;
            }
        }

        return true;
    }

    private static string[] Segments(string template)
        => template.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.StartsWith('{') ? "{}" : s.ToLowerInvariant())
            .ToArray();
}

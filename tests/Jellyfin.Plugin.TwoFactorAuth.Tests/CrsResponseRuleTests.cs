using System;
using System.Linq;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#320] OWASP CRS inspects response bodies too. Rule 953101 ("PHP
/// Information Leakage", paranoia level 2) matches plain English phrases that
/// PHP prints in its errors, and "empty password" is one of them: the English
/// translation bundle, the admin page and the blank password refusal all
/// carried it, so a WAF scored every one of those answers as a leak.</summary>
public class CrsResponseRuleTests
{
    private const string PagePrefix = "Jellyfin.Plugin.TwoFactorAuth.Pages.";

    // Rule 953101, copied verbatim from rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
    // (identical in CRS 4.29.0 and 4.30.0). ModSecurity applies it to the whole
    // body with no transformation.
    private static readonly Regex Crs953101 = new(
        @"(?i)Empty string|F(?:ile size is|reeing memory)|Header (?:name )?""|Invalid date|No active class|(?:Out of memor|cannot be empt)y|Pa(?:ir level|ssword is too long)|Re(?:ading file|starting!)|S(?:ession is not active|tatic function\b)|T(?:elling\.\.\.|he function\b)|(?:Unknown reas|invalid opti)on|e(?:mpty password|rror reading)",
        RegexOptions.None,
        TimeSpan.FromSeconds(5));

    [Fact]
    public void No_page_script_or_translation_the_plugin_serves_matches_rule_953101()
    {
        var resources = typeof(Plugin).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(PagePrefix, StringComparison.Ordinal))
            .ToList();

        Assert.Contains(PagePrefix + "admin.html", resources);
        Assert.Contains(PagePrefix + "translations.en.json", resources);
        Assert.Equal(8, resources.Count(n => n.StartsWith(PagePrefix + "translations.", StringComparison.Ordinal)));
        var matching = resources
            .Select(resource => (resource, match: Crs953101.Match(ResourceReader.ReadEmbeddedText(resource) ?? string.Empty)))
            .Where(hit => hit.match.Success)
            .Select(hit => hit.resource + ": \"" + hit.match.Value + "\"")
            .ToList();
        Assert.Empty(matching);
    }

    [Fact]
    public void The_blank_password_refusal_does_not_match_rule_953101()
    {
        Assert.Contains("\"emptyPasswordBlocked\":true", LockoutMessageMiddleware.BlankSignInRefusalJson, StringComparison.Ordinal);
        var match = Crs953101.Match(LockoutMessageMiddleware.BlankSignInRefusalJson);
        Assert.False(match.Success, "the refusal matches CRS 953101 with \"" + match.Value + "\"");
    }
}

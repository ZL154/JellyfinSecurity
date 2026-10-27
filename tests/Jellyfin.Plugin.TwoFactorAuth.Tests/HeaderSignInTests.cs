using System;
using System.Linq;
using System.Net;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#298] Sign-in through a trusted reverse proxy that names the
/// user in a header: the trust decision on the raw TCP peer, the header
/// parsing, the account matching, the audit label, the login-page flag and
/// the admin page.</summary>
public class HeaderSignInTests
{
    [Fact]
    public void Defaults_leave_the_feature_off()
    {
        var cfg = new PluginConfiguration();

        Assert.False(cfg.HeaderSignInEnabled);
        Assert.Equal(string.Empty, cfg.HeaderSignInUserHeader);
        Assert.Equal(string.Empty, cfg.HeaderSignInGroupsHeader);
        Assert.Equal(string.Empty, cfg.HeaderSignInAllowedGroups);
        Assert.Empty(cfg.HeaderSignInProxyCidrs);
        Assert.Equal(string.Empty, cfg.HeaderSignInEmailDomains);
        Assert.True(cfg.HeaderSignInBypassPluginTwoFa);
        Assert.False(cfg.HeaderSignInAllowAdmins);
    }

    [Theory]
    [InlineData("172.17.0.5", "172.17.0.5/32", true)]
    [InlineData("172.17.0.6", "172.17.0.5/32", false)]
    [InlineData("::ffff:172.17.0.5", "172.17.0.5/32", true)]
    [InlineData("fd00::5", "fd00::/64", true)]
    // A bare address is that one host, however it is written.
    [InlineData("172.17.0.5", "172.17.0.5", true)]
    [InlineData("172.17.0.6", "172.17.0.5", false)]
    [InlineData("fd00::5", "fd00:0:0::5", true)]
    [InlineData("172.17.0.5", "172.17.0.5/33", false)]
    [InlineData("100.64.1.2", "0.0.0.0/0", false)]
    [InlineData("100.64.1.2", "proxy.lan", false)]
    [InlineData("100.64.1.2", "100.64.0.0/10", true)]
    [InlineData("10.1.2.3", "10.0.0.0/8", true)]
    // Broader than the import guard's /8 (IPv4) and /16 (IPv6) floor: a list
    // that wide would let most of the internet assert who it is.
    [InlineData("10.1.2.3", "10.0.0.0/7", false)]
    [InlineData("100.64.1.2", "0.0.0.0/1", false)]
    [InlineData("2001:db8::1", "2000::/3", false)]
    public void Only_the_listed_proxy_addresses_are_trusted(string peer, string cidr, bool trusted)
    {
        Assert.Equal(trusted, HeaderSignIn.FromTrustedProxy(peer, new[] { cidr }));
    }

    [Fact]
    public void No_list_or_no_peer_trusts_nothing()
    {
        Assert.False(HeaderSignIn.FromTrustedProxy("172.17.0.5", Array.Empty<string>()));
        Assert.False(HeaderSignIn.FromTrustedProxy(null, new[] { "172.17.0.5/32" }));
    }

    [Fact]
    public void The_raw_peer_is_what_the_first_middleware_recorded()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:172.17.0.5");
        HeaderSignIn.RememberRawPeer(context);

        // Jellyfin's forwarded-headers handling may rewrite the connection
        // address later in the pipeline; the recorded peer must not follow.
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.9");

        Assert.Equal("172.17.0.5", HeaderSignIn.RawPeer(context));
    }

    [Fact]
    public void Without_a_recorded_peer_nothing_is_trusted()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("172.17.0.5");

        Assert.Null(HeaderSignIn.RawPeer(context));
    }

    [Theory]
    [InlineData("  alice@example.test ", "alice@example.test")]
    [InlineData("alice", "alice")]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("alice\nbob", null)]
    // A proxy that appends instead of replacing would turn a client's own
    // header into "client, proxy": two names, so nobody.
    [InlineData("mallory, alice", null)]
    public void The_named_user_is_one_clean_value(string header, string? expected)
    {
        Assert.Equal(expected, HeaderSignIn.NamedUser(new StringValues(header)));
    }

    [Fact]
    public void A_missing_repeated_or_oversized_user_header_names_nobody()
    {
        Assert.Null(HeaderSignIn.NamedUser(StringValues.Empty));
        Assert.Null(HeaderSignIn.NamedUser(new StringValues(new[] { "alice", "bob" })));
        Assert.Null(HeaderSignIn.NamedUser(new StringValues(new string('a', 300))));
    }

    [Fact]
    public void Groups_are_split_on_commas()
    {
        Assert.Equal(new[] { "media", "family" }, HeaderSignIn.NamedGroups(new StringValues(" media, family ,,")));
        Assert.Empty(HeaderSignIn.NamedGroups(StringValues.Empty)!);
    }

    [Fact]
    public void A_groups_header_that_arrives_twice_lists_nothing_trustworthy()
    {
        // The same rule as the user header: a proxy that appends instead of
        // replacing would otherwise let the client add a group of its own.
        Assert.Null(HeaderSignIn.NamedGroups(new StringValues(new[] { "media", "guests" })));
        Assert.Null(HeaderSignIn.NamedGroups(new StringValues("guests\u0001media")));
    }

    [Fact]
    public void Untrustworthy_groups_refuse_only_when_groups_are_required()
    {
        Assert.False(HeaderSignIn.InAllowedGroup("media", null));
        Assert.True(HeaderSignIn.InAllowedGroup("", null));
    }

    [Theory]
    [InlineData("", "", true)]
    [InlineData("", "media", true)]
    [InlineData("media", "Media", true)]
    [InlineData("media, family", "family", true)]
    [InlineData("media", "family", false)]
    [InlineData("media", "", false)]
    public void Allowed_groups_gate_the_sign_in(string allowed, string groups, bool expected)
    {
        var named = HeaderSignIn.NamedGroups(new StringValues(groups));
        Assert.Equal(expected, HeaderSignIn.InAllowedGroup(allowed, named));
    }

    [Theory]
    [InlineData("alice", "", new[] { "alice" })]
    [InlineData("alice@example.test", "", new[] { "alice@example.test" })]
    [InlineData("alice@example.test", "example.test", new[] { "alice@example.test", "alice" })]
    [InlineData("alice@EXAMPLE.test", "other.test, Example.Test", new[] { "alice@EXAMPLE.test", "alice" })]
    [InlineData("alice@other.test", "example.test", new[] { "alice@other.test" })]
    [InlineData("@example.test", "example.test", new[] { "@example.test" })]
    [InlineData("alice@", "example.test", new[] { "alice@" })]
    public void Usernames_tried_come_from_the_header_and_the_listed_domains(string named, string domains, string[] expected)
    {
        Assert.Equal(expected, HeaderSignIn.UsernameCandidates(named, domains));
    }

    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(true, false, false, true)]
    [InlineData(true, false, true, true)]
    [InlineData(false, true, false, true)]
    [InlineData(false, true, true, false)]
    // The option lets administrators in; it never lets a disabled one in.
    [InlineData(true, true, true, true)]
    public void Disabled_accounts_and_administrators_without_the_option_are_refused(
        bool disabled, bool administrator, bool allowAdministrators, bool refused)
    {
        Assert.Equal(refused, HeaderSignIn.Refusal(disabled, administrator, allowAdministrators) is not null);
    }

    [Fact]
    public void The_login_page_is_told_only_when_the_proxy_names_a_user()
    {
        var cfg = new PluginConfiguration
        {
            HeaderSignInEnabled = true,
            HeaderSignInUserHeader = "X-NetBird-User",
            HeaderSignInProxyCidrs = new[] { "172.17.0.5/32" },
        };
        var named = new HeaderDictionary { ["X-NetBird-User"] = "alice@example.test" };
        var unnamed = new HeaderDictionary();

        Assert.True(HeaderSignIn.Available(cfg, "172.17.0.5", named));
        Assert.False(HeaderSignIn.Available(cfg, "172.17.0.6", named));
        Assert.False(HeaderSignIn.Available(cfg, "172.17.0.5", unnamed));
        Assert.False(HeaderSignIn.Available(new PluginConfiguration(), "172.17.0.5", named));
    }

    [Theory]
    // The login page's own call.
    [InlineData("same-origin", false)]
    // A script on another site, or a sibling subdomain, in the user's
    // browser: a proxy that knows the user by the connection would name them
    // on that request too.
    [InlineData("same-site", true)]
    [InlineData("cross-site", true)]
    [InlineData("none", true)]
    // No Fetch Metadata (an older browser, or not a browser): judged on the
    // proxy address alone.
    [InlineData(null, false)]
    public void Only_the_login_page_itself_may_ask(string? secFetchSite, bool refused)
    {
        var header = secFetchSite is null ? StringValues.Empty : new StringValues(secFetchSite);
        Assert.Equal(refused, HeaderSignIn.FromAnotherSite(header));
    }

    [Fact]
    public void A_user_named_from_an_unlisted_address_is_reported_for_setup()
    {
        var cfg = new PluginConfiguration
        {
            HeaderSignInEnabled = true,
            HeaderSignInUserHeader = "X-NetBird-User",
            HeaderSignInProxyCidrs = new[] { "172.17.0.5/32" },
        };
        var named = new HeaderDictionary { ["X-NetBird-User"] = "alice@example.test" };

        // The usual setup mistake: the proxy reaches Jellyfin from an address
        // missing from the list. The log names that address.
        Assert.True(HeaderSignIn.NamedFromUnlistedAddress(cfg, "172.18.0.9", named));
        Assert.False(HeaderSignIn.NamedFromUnlistedAddress(cfg, "172.17.0.5", named));
        Assert.False(HeaderSignIn.NamedFromUnlistedAddress(cfg, "172.18.0.9", new HeaderDictionary()));
        Assert.False(HeaderSignIn.NamedFromUnlistedAddress(new PluginConfiguration(), "172.18.0.9", named));
    }

    [Fact]
    public void The_public_config_carries_the_flag()
    {
        var body = JsonSerializer.SerializeToElement(
            TwoFactorAuthController.BuildPublicConfig(new PluginConfiguration(), false, proxySignInAvailable: true));

        Assert.True(body.GetProperty("proxySignInAvailable").GetBoolean());
    }

    [Theory]
    [InlineData("trusted-proxy", true, "proxy_header")]
    [InlineData("trusted-proxy", false, "proxy_header_primary")]
    [InlineData("google", true, "oidc:google")]
    [InlineData("google", false, "oidc_primary:google")]
    [InlineData("passkey", true, "oidc:passkey")]
    public void The_audit_row_names_the_proxy_sign_in(string providerId, bool bypass, string method)
    {
        Assert.Equal(method, TwoFactorAuthProvider.BridgeAuditMethod(providerId, bypass));
    }

    [Fact]
    public void Admin_page_exposes_the_settings_and_script_round_trips_them()
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");

        Assert.NotNull(page);
        Assert.NotNull(script);

        foreach (var id in new[]
        {
            "cfgHeaderSignIn", "cfgHeaderUser", "cfgHeaderGroups", "cfgHeaderAllowedGroups",
            "cfgHeaderProxyCidrs", "cfgHeaderEmailDomains", "cfgHeaderBypass2fa", "cfgHeaderAllowAdmins",
        })
        {
            Assert.Contains("id=\"" + id + "\"", page);
        }

        Assert.Contains("tfa.admin.settings.header_heading", page);
        Assert.Contains("tfa.admin.settings.header_help", page);

        // Read back into the form, and sent on save.
        foreach (var field in new[]
        {
            "HeaderSignInEnabled", "HeaderSignInUserHeader", "HeaderSignInGroupsHeader", "HeaderSignInAllowedGroups",
            "HeaderSignInProxyCidrs", "HeaderSignInEmailDomains", "HeaderSignInBypassPluginTwoFa", "HeaderSignInAllowAdmins",
        })
        {
            Assert.Contains("c." + field, script);
            Assert.Contains("c." + field + " =", script);
        }
    }
}

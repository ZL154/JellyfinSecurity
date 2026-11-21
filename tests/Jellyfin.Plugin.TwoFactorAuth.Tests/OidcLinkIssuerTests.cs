using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>Account links are bound to the issuer of the id_token they were
/// made with, since a subject is only unique within one issuer.</summary>
public class OidcLinkIssuerMatchingTests
{
    private const string Issuer = "https://idp.example";

    [Fact]
    public void A_link_from_another_issuer_does_not_match()
    {
        var link = new SsoLink { ProviderId = "corp", Subject = "42", Issuer = "https://other.example" };

        Assert.False(OidcService.LinkMatches(link, "corp", Issuer, "42"));
    }

    [Fact]
    public void A_link_from_the_same_issuer_matches()
    {
        var link = new SsoLink { ProviderId = "corp", Subject = "42", Issuer = Issuer };

        Assert.True(OidcService.LinkMatches(link, "corp", Issuer, "42"));
        Assert.False(OidcService.LinkMatches(link, "corp", Issuer, "43"));
        Assert.False(OidcService.LinkMatches(link, "other", Issuer, "42"));
    }

    [Fact]
    public void A_legacy_link_without_an_issuer_matches_and_is_backfilled()
    {
        var link = new SsoLink { ProviderId = "corp", Subject = "42" };

        Assert.True(OidcService.LinkMatches(link, "corp", Issuer, "42"));
        OidcService.BackfillIssuer(link, Issuer);
        Assert.Equal(Issuer, link.Issuer);

        // A recorded issuer is never overwritten.
        OidcService.BackfillIssuer(link, "https://other.example");
        Assert.Equal(Issuer, link.Issuer);
    }

    [Fact]
    public void A_same_subject_link_from_another_issuer_is_a_conflict()
    {
        var data = new UserTwoFactorData
        {
            SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "42", Issuer = "https://other.example" } },
        };

        Assert.True(OidcService.HasConflictingProviderLink(data, "corp", Issuer, "42"));
    }

    [Fact]
    public void Stored_user_data_without_an_issuer_loads_with_an_empty_one()
    {
        var data = System.Text.Json.JsonSerializer.Deserialize<UserTwoFactorData>(
            "{\"SsoLinks\":[{\"ProviderId\":\"corp\",\"Subject\":\"42\",\"Email\":\"\"}]}")!;

        Assert.Equal(string.Empty, Assert.Single(data.SsoLinks).Issuer);
    }

    [Theory]
    [InlineData("https://idp.example/realms/a", "https://IDP.example/realms/a/")]
    [InlineData("https://idp.example/realms/a", "https://idp.example/realms/a/.well-known/openid-configuration")]
    [InlineData(" https://idp.example:443/realms/a ", "https://idp.example/realms/a")]
    public void Equivalent_discovery_urls_normalize_the_same(string a, string b)
    {
        Assert.Equal(OidcService.NormalizeDiscoveryUrl(a), OidcService.NormalizeDiscoveryUrl(b));
    }

    [Theory]
    [InlineData("https://idp.example/realms/a", "https://idp.example/realms/b")]
    [InlineData("https://idp.example/realms/a", "https://idp.example/realms/A")]
    [InlineData("https://idp.example/realms/a", "https://other.example/realms/a")]
    public void Different_discovery_urls_normalize_differently(string a, string b)
    {
        Assert.NotEqual(OidcService.NormalizeDiscoveryUrl(a), OidcService.NormalizeDiscoveryUrl(b));
    }
}

/// <summary>The sign-in pipeline, run through the native token-exchange entry
/// point against preloaded discovery metadata and a locally signed id_token.</summary>
public sealed class OidcLinkIssuerSignInTests : IDisposable
{
    private const string ProviderId = "corp";
    private const string ClientId = "jellyfin";
    private const string Issuer = "https://idp.example";
    private const string DefaultProvider = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    private readonly string _sandbox;
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly OidcService _oidc;
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly RsaSecurityKey _signingKey;
    private readonly User _alice = new("alice", DefaultProvider, "reset");
    private readonly OidcProvider _provider = new()
    {
        Id = ProviderId,
        DisplayName = "Corp",
        ClientId = ClientId,
        DiscoveryUrl = Issuer + "/.well-known/openid-configuration",
        Enabled = true,
    };

    public OidcLinkIssuerSignInTests()
    {
        var paths = TestApplicationPaths.Create(out _sandbox);
        _store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        _users.GetUserById(_alice.Id).Returns(_alice);
        _users.GetUserByName(_alice.Username).Returns(_alice);
        _oidc = new OidcService(
            _store,
            _users,
            NullLogger<OidcService>.Instance,
            Substitute.For<IProviderManager>(),
            Substitute.For<IServerConfigurationManager>(),
            Substitute.For<ILibraryManager>());

        _signingKey = new RsaSecurityKey(_rsa) { KeyId = "test-key" };
        var publicKey = new RsaSecurityKey(_rsa.ExportParameters(false)) { KeyId = "test-key" };
        var keys = new JsonWebKeySet();
        keys.Keys.Add(JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey));
        _oidc.SeedProviderMetadataForTest(ProviderId, Issuer, keys);
    }

    public void Dispose()
    {
        _oidc.Dispose();
        _rsa.Dispose();
        _store.Dispose();
        try { Directory.Delete(_sandbox, recursive: true); } catch (IOException) { /* best-effort cleanup */ }
    }

    [Fact]
    public async Task A_link_from_another_issuer_does_not_sign_in()
    {
        await LinkAliceAsync("https://previous-idp.example");

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42"), accessToken: null);

        Assert.False(result.Success);
        Assert.Null(result.UserId);
        var link = Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
        Assert.Equal("https://previous-idp.example", link.Issuer);
        Assert.Null(link.LastUsedAt);
    }

    [Fact]
    public async Task A_link_from_another_issuer_blocks_the_username_fallback()
    {
        _provider.LinkExistingUsersByUsername = true;
        await LinkAliceAsync("https://previous-idp.example");

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42", username: "alice"), accessToken: null);

        Assert.False(result.Success);
        Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
    }

    [Fact]
    public async Task A_legacy_link_signs_in_and_records_the_issuer()
    {
        await LinkAliceAsync(issuer: string.Empty);

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42"), accessToken: null);

        Assert.True(result.Success, result.Error);
        Assert.Equal(_alice.Id, result.UserId);
        var link = Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
        Assert.Equal(Issuer, link.Issuer);
        Assert.NotNull(link.LastUsedAt);
    }

    [Fact]
    public async Task A_link_from_the_same_issuer_signs_in()
    {
        await LinkAliceAsync(Issuer);

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42"), accessToken: null);

        Assert.True(result.Success, result.Error);
        Assert.Equal(_alice.Id, result.UserId);
        Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
    }

    [Fact]
    public async Task A_new_link_stores_the_issuer()
    {
        _provider.LinkExistingUsersByUsername = true;

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42", username: "alice"), accessToken: null);

        Assert.True(result.Success, result.Error);
        Assert.Equal(Issuer, result.Link!.Issuer);
        var link = Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
        Assert.Equal(ProviderId, link.ProviderId);
        Assert.Equal("42", link.Subject);
        Assert.Equal(Issuer, link.Issuer);
    }

    private Task LinkAliceAsync(string issuer) => _store.MutateAsync(_alice.Id, d => d.SsoLinks.Add(new SsoLink
    {
        ProviderId = ProviderId,
        Subject = "42",
        Issuer = issuer,
        LinkedAt = DateTime.UtcNow.AddDays(-30),
    }));

    private string IdToken(string subject, string? username = null)
    {
        var claims = new List<Claim> { new("sub", subject) };
        if (username is not null) claims.Add(new Claim("preferred_username", username));
        var now = DateTime.UtcNow;
        return new JwtSecurityTokenHandler().CreateEncodedJwt(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
        });
    }
}

// The provider endpoints read Plugin.Instance. Keep its temporary
// configuration away from every other collection and restore it afterwards.
[CollectionDefinition("OIDC provider links", DisableParallelization = true)]
public sealed class OidcProviderLinksCollection;

[Collection("OIDC provider links")]
public sealed class OidcProviderLinkPurgeTests : IDisposable
{
    private const string DiscoveryUrl = "https://idp.example/realms/corp/.well-known/openid-configuration";
    private const string DefaultProvider = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    private readonly string _sandbox;
    private readonly Plugin? _previous = Plugin.Instance;
    private readonly Plugin _plugin;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challenges = new();
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly OidcService _oidc;
    private readonly SecurityController _controller;
    private readonly User _alice = new("alice", DefaultProvider, "reset");
    private readonly User _bob = new("bob", DefaultProvider, "reset");

    public OidcProviderLinkPurgeTests()
    {
        var paths = TestApplicationPaths.Create(out _sandbox);
        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        _plugin = new Plugin(paths, serializer, Substitute.For<IApplicationHost>(), Substitute.For<ILogger<Plugin>>());
        _plugin.Configuration.OidcProviders.Add(new OidcProvider
        {
            Id = "corp",
            DisplayName = "Corp",
            DiscoveryUrl = DiscoveryUrl,
            ClientId = "jellyfin",
            Enabled = true,
        });

        _store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        foreach (var user in new[] { _alice, _bob })
        {
            _users.GetUserById(user.Id).Returns(user);
        }

        _oidc = new OidcService(
            _store,
            _users,
            NullLogger<OidcService>.Instance,
            Substitute.For<IProviderManager>(),
            Substitute.For<IServerConfigurationManager>(),
            Substitute.For<ILibraryManager>());
        var totp = new TotpService(paths, NullLogger<TotpService>.Instance);

        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("Jellyfin-UserId", _alice.Id.ToString()) }, "test")),
        };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("jellyfin.example");
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
        _controller = new SecurityController(
            oidc: _oidc,
            oidcBridge: null!,
            bans: null!,
            allowlist: null!,
            store: _store,
            passkeys: null!,
            passkeyChallenges: null!,
            userManager: _users,
            rateLimiter: new RateLimiter(),
            stepUp: new StepUpService(totp, _challenges, NullLogger<StepUpService>.Instance),
            challenges: _challenges,
            onboardingProofs: null!,
            sessionManager: null!,
            externalUrls: new ExternalUrlResolver(Substitute.For<IServerConfigurationManager>(), NullLogger<ExternalUrlResolver>.Instance),
            logger: NullLogger<SecurityController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };

        SeedLinksAsync().GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        _oidc.Dispose();
        _challenges.Dispose();
        _store.Dispose();
        typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
        try { Directory.Delete(_sandbox, recursive: true); } catch (IOException) { /* best-effort cleanup */ }
    }

    [Fact]
    public async Task Changing_the_discovery_url_removes_the_providers_links()
    {
        var result = await _controller.UpdateProvider("corp", Request("https://other-idp.example/.well-known/openid-configuration"));

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(new[] { "other" }, await ProviderIdsAsync(_alice));
        Assert.Empty(await ProviderIdsAsync(_bob));

        var audit = await _store.GetAuditLogAsync();
        var removed = audit.Where(e => e.Method == "oidc_links_removed").ToList();
        Assert.Equal(2, removed.Count);
        Assert.All(removed, e => Assert.Equal(AuditResult.ConfigChanged, e.Result));
        Assert.Contains(removed, e => e.UserId == _alice.Id && e.Username == "alice");
        Assert.Contains(removed, e => e.UserId == _bob.Id);
    }

    [Theory]
    [InlineData(DiscoveryUrl)]
    [InlineData("https://idp.example/realms/corp")]
    public async Task An_edit_that_keeps_the_discovery_url_keeps_the_links(string discoveryUrl)
    {
        var request = Request(discoveryUrl);
        request.DisplayName = "Corporate sign-in";

        var result = await _controller.UpdateProvider("corp", request);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("Corporate sign-in", _plugin.Configuration.OidcProviders.Single().DisplayName);
        Assert.Equal(new[] { "corp", "other" }, await ProviderIdsAsync(_alice));
        Assert.Equal(new[] { "corp" }, await ProviderIdsAsync(_bob));
        Assert.DoesNotContain(await _store.GetAuditLogAsync(), e => e.Method == "oidc_links_removed");
    }

    [Fact]
    public async Task Deleting_a_provider_removes_its_links()
    {
        var result = await _controller.DeleteProvider("corp");

        Assert.IsType<OkResult>(result);
        Assert.Empty(_plugin.Configuration.OidcProviders);
        Assert.Equal(new[] { "other" }, await ProviderIdsAsync(_alice));
        Assert.Empty(await ProviderIdsAsync(_bob));
        Assert.Equal(2, (await _store.GetAuditLogAsync()).Count(e => e.Method == "oidc_links_removed"));
    }

    [Fact]
    public async Task A_new_provider_does_not_inherit_links_left_under_its_slug()
    {
        _plugin.Configuration.OidcProviders.Clear();

        var request = Request(DiscoveryUrl);
        request.DisplayName = "Corp";
        var result = await _controller.CreateProvider(request);

        Assert.IsType<OkObjectResult>(result.Result);
        Assert.Equal("corp", _plugin.Configuration.OidcProviders.Single().Id);
        Assert.Equal(new[] { "other" }, await ProviderIdsAsync(_alice));
        Assert.Empty(await ProviderIdsAsync(_bob));
    }

    private static SecurityController.OidcProviderUpsertRequest Request(string discoveryUrl) => new()
    {
        DisplayName = "Corp",
        DiscoveryUrl = discoveryUrl,
        ClientId = "jellyfin",
        Enabled = true,
    };

    private async Task SeedLinksAsync()
    {
        await _store.MutateAsync(_alice.Id, d =>
        {
            d.SsoLinks.Add(new SsoLink { ProviderId = "corp", Subject = "a-1", Issuer = "https://idp.example/realms/corp" });
            d.SsoLinks.Add(new SsoLink { ProviderId = "other", Subject = "a-2", Issuer = "https://other.example" });
        });
        await _store.MutateAsync(_bob.Id, d =>
            d.SsoLinks.Add(new SsoLink { ProviderId = "corp", Subject = "b-1" }));
    }

    private async Task<string[]> ProviderIdsAsync(User user)
        => (await _store.GetUserDataAsync(user.Id)).SsoLinks.Select(l => l.ProviderId).OrderBy(id => id).ToArray();
}

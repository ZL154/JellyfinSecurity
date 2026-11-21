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

    // Shared with tests/discovery-url-compare.test.mjs, so the settings
    // page warns for exactly the edits that retire links.
    private static System.Text.Json.JsonElement UrlCases([System.Runtime.CompilerServices.CallerFilePath] string here = "")
        => System.Text.Json.JsonDocument.Parse(File.ReadAllText(
            Path.Combine(Path.GetDirectoryName(here)!, "..", "discovery-url-cases.json"))).RootElement;

    public static IEnumerable<object[]> Cases(string kind)
        => UrlCases().GetProperty(kind).EnumerateArray()
            .Select(c => new object[] { c[0].GetString()!, c[1].GetString()! });

    [Theory]
    [MemberData(nameof(Cases), "same")]
    public void Discovery_urls_differing_only_in_scheme_host_case_or_whitespace_are_the_same(string a, string b)
        => Assert.True(OidcService.SameDiscoveryUrl(a, b));

    [Theory]
    // GetDiscoveryAsync reads the configured URL first and only then tries the
    // well-known suffix, so those can serve different documents.
    [MemberData(nameof(Cases), "different")]
    public void Any_other_difference_is_a_different_discovery_url(string a, string b)
        => Assert.False(OidcService.SameDiscoveryUrl(a, b));

    [Theory]
    [MemberData(nameof(Cases), "canonical")]
    public void The_canonical_form_keeps_everything_after_the_authority_as_written(string input, string expected)
        => Assert.Equal(expected, OidcService.CanonicalDiscoveryUrl(input));

    [Fact]
    public void A_retired_row_stays_retired_after_a_rollback_rewrites_it()
    {
        var data = new UserTwoFactorData { SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "42", Issuer = Issuer } } };
        OidcLinkRetirement.Retire(data, new HashSet<string> { "corp" }, "test", DateTime.UtcNow);

        // v2.7.0 knows none of the new fields: it drops them when it rewrites
        // the file, and this version then reads the row back.
        var node = System.Text.Json.Nodes.JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(data))!;
        foreach (var row in node["SsoLinks"]!.AsArray())
        {
            foreach (var field in new[] { "Id", "Issuer", "RetiredAt", "RetiredReason", "RenamedFrom", "RenamedWithDiscoveryUrl" })
            {
                row!.AsObject().Remove(field);
            }
        }

        var reread = System.Text.Json.JsonSerializer.Deserialize<UserTwoFactorData>(node.ToJsonString())!;
        var link = Assert.Single(reread.SsoLinks);
        Assert.Null(link.RetiredAt);
        Assert.Empty(link.Issuer);
        Assert.True(link.IsRetired);
        Assert.False(OidcService.LinkMatches(link, "corp", Issuer, "42"));
        Assert.True(OidcService.HasConflictingProviderLink(reread, "corp", Issuer, "42"));
        Assert.False(SelfServiceFactors.HasAny(reread, new PluginConfiguration()));
        Assert.Equal("42", OidcLinkRetirement.DisplaySubject(link));
    }

    [Fact]
    public void An_active_subject_that_starts_with_the_old_ascii_prefix_stays_active()
    {
        var data = new UserTwoFactorData { SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "retired:42", Issuer = Issuer } } };

        OidcLinkRetirement.NormalizeRetired(data);

        var link = Assert.Single(data.SsoLinks);
        Assert.False(link.IsRetired);
        Assert.Equal("retired:42", link.Subject);
        Assert.True(OidcService.LinkMatches(link, "corp", Issuer, "retired:42"));
        Assert.True(SelfServiceFactors.HasAny(data, new PluginConfiguration()));
    }

    [Fact]
    public void A_pre_release_retired_row_gets_the_current_prefix()
    {
        var data = new UserTwoFactorData { SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "retired:42", RetiredAt = DateTime.UtcNow } } };

        OidcLinkRetirement.NormalizeRetired(data);

        Assert.Equal(SsoLink.RetiredSubjectPrefix + "42", data.SsoLinks[0].Subject);
        Assert.Equal("42", OidcLinkRetirement.DisplaySubject(data.SsoLinks[0]));
    }

    [Fact]
    public void A_stored_link_with_null_fields_loads_as_an_inert_retired_row()
    {
        const string json = """{"SsoLinks":[{"ProviderId":"corp","Subject":null,"Issuer":null},{"ProviderId":"corp","Subject":"42"}]}""";
        var data = System.Text.Json.JsonSerializer.Deserialize<UserTwoFactorData>(json)!;

        OidcLinkRetirement.NormalizeRetired(data);

        Assert.True(data.SsoLinks[0].IsRetired);
        Assert.DoesNotContain(data.SsoLinks, l => OidcService.LinkMatches(l, "corp", Issuer, string.Empty));
        Assert.True(OidcService.LinkMatches(data.SsoLinks[1], "corp", Issuer, "42"));
    }

    [Fact]
    public void The_retired_prefix_cannot_be_a_conforming_subject()
        => Assert.Contains(SsoLink.RetiredSubjectPrefix, c => c > 0x7F);

    [Fact]
    public void A_row_retired_without_the_prefix_gets_it_when_read()
    {
        var data = new UserTwoFactorData { SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "42", RetiredAt = DateTime.UtcNow } } };

        OidcLinkRetirement.NormalizeRetired(data);
        OidcLinkRetirement.NormalizeRetired(data);

        Assert.Equal(SsoLink.RetiredSubjectPrefix + "42", data.SsoLinks[0].Subject);
    }

    [Fact]
    public void Only_an_active_link_counts_as_a_self_service_factor()
    {
        var data = new UserTwoFactorData { SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "42", RetiredAt = DateTime.UtcNow } } };

        Assert.False(SelfServiceFactors.HasAny(data, new PluginConfiguration()));
        data.SsoLinks.Add(new SsoLink { ProviderId = "corp", Subject = "43" });
        Assert.True(SelfServiceFactors.HasAny(data, new PluginConfiguration()));
    }

    [Theory]
    // An active matching link is updated, however the user was found.
    [InlineData(true, true, "Update")]
    [InlineData(true, false, "Update")]
    // Resolved through a link that was removed meanwhile.
    [InlineData(false, true, "Refused")]
    // A fallback match with no link to this provider adds one.
    [InlineData(false, false, "Add")]
    public void A_sign_in_commits_against_the_current_links(bool hasActiveLink, bool resolvedViaLink, string expected)
    {
        var data = new UserTwoFactorData();
        if (hasActiveLink) data.SsoLinks.Add(new SsoLink { ProviderId = "corp", Subject = "42", Issuer = Issuer });

        var commit = OidcService.DecideSignInLinkCommit(data, "corp", Issuer, "42", resolvedViaLink, providerUnchanged: true);

        Assert.Equal(expected, commit.ToString());
    }

    [Fact]
    public void A_sign_in_is_refused_when_a_link_was_retired_meanwhile_or_the_provider_moved()
    {
        var retired = new UserTwoFactorData { SsoLinks = { new SsoLink { ProviderId = "corp", Subject = "42", Issuer = Issuer, RetiredAt = DateTime.UtcNow } } };

        Assert.Equal(OidcService.LinkCommit.Refused, OidcService.DecideSignInLinkCommit(retired, "corp", Issuer, "42", resolvedViaLink: false, providerUnchanged: true));
        Assert.Equal(OidcService.LinkCommit.Refused, OidcService.DecideSignInLinkCommit(new UserTwoFactorData(), "corp", Issuer, "42", resolvedViaLink: false, providerUnchanged: false));
    }

    [Fact]
    public void A_retired_link_never_matches_but_still_conflicts()
    {
        var link = new SsoLink { ProviderId = "corp", Subject = "42", Issuer = Issuer, RetiredAt = DateTime.UtcNow };
        var data = new UserTwoFactorData { SsoLinks = { link } };

        Assert.False(OidcService.LinkMatches(link, "corp", Issuer, "42"));
        Assert.True(OidcService.HasConflictingProviderLink(data, "corp", Issuer, "42"));
    }

    [Fact]
    public void Changed_providers_are_the_added_removed_and_re_pointed_slugs()
    {
        var before = new[]
        {
            new OidcProvider { Id = "same", DiscoveryUrl = "https://a.example" },
            new OidcProvider { Id = "moved", DiscoveryUrl = "https://b.example" },
            new OidcProvider { Id = "gone", DiscoveryUrl = "https://c.example" },
        };
        var after = new[]
        {
            new OidcProvider { Id = "same", DiscoveryUrl = "https://A.example" },
            new OidcProvider { Id = "moved", DiscoveryUrl = "https://b.example/.well-known/openid-configuration" },
            new OidcProvider { Id = "new", DiscoveryUrl = "https://d.example" },
        };

        Assert.Equal(new[] { "gone", "moved", "new" }, OidcLinkRetirement.ChangedProviderIds(before, after).OrderBy(x => x));
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
    private readonly string _jwksJson;
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
        _oidc.SeedProviderMetadataForTest(_provider, Issuer, keys);
        var rsaPublic = _rsa.ExportParameters(false);
        _jwksJson = System.Text.Json.JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", kid = "test-key", use = "sig", alg = "RS256", n = Base64UrlEncoder.Encode(rsaPublic.Modulus), e = Base64UrlEncoder.Encode(rsaPublic.Exponent) },
            },
        });
        _oidc.CurrentProviderLookup = id => id == ProviderId ? _provider : null;
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

    [Fact]
    public async Task A_retired_link_does_not_sign_in_and_blocks_the_username_fallback()
    {
        _provider.LinkExistingUsersByUsername = true;
        await LinkAliceAsync(Issuer, retired: true);

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42", username: "alice"), accessToken: null);

        Assert.False(result.Success);
        var link = Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
        Assert.NotNull(link.RetiredAt);
    }

    [Fact]
    public async Task A_step_up_only_completes_while_the_link_is_active()
    {
        await LinkAliceAsync(Issuer);
        Assert.True(await _oidc.CompleteStepUpLinkAsync(_alice.Id, ProviderId, Issuer, "42"));
        Assert.NotNull(Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks).LastUsedAt);

        // Retired or removed while the step-up was in flight.
        await _store.MutateAsync(_alice.Id, d => d.SsoLinks[0].RetiredAt = DateTime.UtcNow);
        Assert.False(await _oidc.CompleteStepUpLinkAsync(_alice.Id, ProviderId, Issuer, "42"));
        await _store.MutateAsync(_alice.Id, d => d.SsoLinks.Clear());
        Assert.False(await _oidc.CompleteStepUpLinkAsync(_alice.Id, ProviderId, Issuer, "42"));
    }

    [Fact]
    public async Task A_sign_in_does_not_link_when_the_provider_was_re_pointed_meanwhile()
    {
        _provider.LinkExistingUsersByUsername = true;
        var moved = new OidcProvider { Id = ProviderId, DiscoveryUrl = "https://other-idp.example/.well-known/openid-configuration" };
        _oidc.CurrentProviderLookup = _ => moved;

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42", username: "alice"), accessToken: null);

        Assert.False(result.Success);
        Assert.Empty((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
    }

    [Fact]
    public async Task A_sign_in_does_not_link_when_the_provider_was_disabled_meanwhile()
    {
        _provider.LinkExistingUsersByUsername = true;
        var disabled = new OidcProvider { Id = ProviderId, DiscoveryUrl = _provider.DiscoveryUrl, Enabled = false };
        _oidc.CurrentProviderLookup = _ => disabled;

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("42", username: "alice"), accessToken: null);

        Assert.False(result.Success);
        Assert.Empty((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
    }

    [Fact]
    public async Task A_token_whose_subject_carries_the_retired_prefix_is_refused()
    {
        _provider.LinkExistingUsersByUsername = true;

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken(SsoLink.RetiredSubjectPrefix + "42", username: "alice"), accessToken: null);

        Assert.False(result.Success);
        Assert.Empty((await _store.GetUserDataAsync(_alice.Id)).SsoLinks);
    }

    [Fact]
    public async Task An_existing_link_whose_subject_starts_with_the_old_ascii_prefix_signs_in()
    {
        await _store.MutateAsync(_alice.Id, d => d.SsoLinks.Add(new SsoLink { ProviderId = ProviderId, Subject = "retired:42", Issuer = Issuer }));

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("retired:42"), accessToken: null);

        Assert.True(result.Success, result.Error);
        Assert.Equal(_alice.Id, result.UserId);
    }

    [Fact]
    public async Task A_sign_in_validates_with_the_settings_it_started_with()
    {
        // An admin rotates the client while discovery is still in flight.
        var live = new OidcProvider
        {
            Id = ProviderId,
            ClientId = ClientId,
            DiscoveryUrl = Issuer + "/held/.well-known/openid-configuration",
            Enabled = true,
            LinkExistingUsersByUsername = true,
        };
        _oidc.CurrentProviderLookup = _ => live;
        _oidc.OutboundCheck = (_, _, _) => Task.CompletedTask;
        var held = new TaskCompletionSource<System.Text.Json.JsonElement>();
        _oidc.DiscoveryFetcher = _ => held.Task;
        _oidc.JwksFetcher = _ => Task.FromResult(_jwksJson);

        var signIn = _oidc.ExchangeIdTokenAsync(live, IdToken("42", username: "alice"), accessToken: null);
        live.ClientId = "rotated-client";
        held.SetResult(DiscoveryDocument(Issuer));

        // The token was issued to the client the sign-in started with.
        var result = await signIn;
        Assert.True(result.Success, result.Error);
    }

    [Fact]
    public async Task An_auto_created_user_is_removed_when_the_sign_in_cannot_link_it()
    {
        var created = new User("newcomer", DefaultProvider, "reset");
        _users.CreateUserAsync("newcomer").Returns(created);
        _provider.AutoCreateUsers = true;
        var moved = new OidcProvider { Id = ProviderId, DiscoveryUrl = "https://other-idp.example/.well-known/openid-configuration", Enabled = true };
        var lookups = 0;
        // Current when the user is created, re-pointed by the time the link is saved.
        _oidc.CurrentProviderLookup = _ => ++lookups == 1 ? _provider : moved;

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("77", username: "newcomer"), accessToken: null);

        Assert.False(result.Success);
        await _users.Received(1).DeleteUserAsync(created.Id);
        Assert.Empty((await _store.GetUserDataAsync(created.Id)).SsoLinks);
    }

    [Fact]
    public async Task No_user_is_auto_created_for_a_provider_that_changed_during_the_sign_in()
    {
        _provider.AutoCreateUsers = true;
        _oidc.CurrentProviderLookup = _ => new OidcProvider { Id = ProviderId, DiscoveryUrl = _provider.DiscoveryUrl, Enabled = false };

        var result = await _oidc.ExchangeIdTokenAsync(_provider, IdToken("77", username: "newcomer"), accessToken: null);

        Assert.False(result.Success);
        await _users.DidNotReceiveWithAnyArgs().CreateUserAsync(default!);
    }

    [Fact]
    public async Task A_discovery_fetch_that_spans_an_edit_is_cached_under_the_url_it_read()
    {
        const string oldUrl = "https://old-idp.example/.well-known/openid-configuration";
        const string newUrl = "https://new-idp.example/.well-known/openid-configuration";
        var editable = new OidcProvider { Id = "edited", DiscoveryUrl = oldUrl, Enabled = true };
        var fetched = new List<string>();
        var held = new TaskCompletionSource<System.Text.Json.JsonElement>();
        _oidc.OutboundCheck = (_, _, _) => Task.CompletedTask;
        _oidc.DiscoveryFetcher = url =>
        {
            fetched.Add(url);
            var doc = DiscoveryDocument("https://" + new Uri(url).Host);
            if (fetched.Count > 1) return Task.FromResult(doc);
            return held.Task;
        };

        var inFlight = _oidc.GetDiscoveryForTestAsync(editable);
        editable.DiscoveryUrl = newUrl;
        held.SetResult(DiscoveryDocument("https://old-idp.example"));
        Assert.Equal(("https://old-idp.example", oldUrl), await inFlight);

        // The old document is not served for the new URL...
        Assert.Equal(("https://new-idp.example", newUrl), await _oidc.GetDiscoveryForTestAsync(editable));
        Assert.Equal(new[] { oldUrl, newUrl }, fetched);

        // ...and stays where it was read from.
        editable.DiscoveryUrl = oldUrl;
        Assert.Equal(("https://old-idp.example", oldUrl), await _oidc.GetDiscoveryForTestAsync(editable));
        Assert.Equal(2, fetched.Count);
    }

    private static System.Text.Json.JsonElement DiscoveryDocument(string issuer)
        => System.Text.Json.JsonSerializer.SerializeToElement(new Dictionary<string, string>
        {
            ["issuer"] = issuer,
            ["authorization_endpoint"] = issuer + "/authorize",
            ["token_endpoint"] = issuer + "/token",
            ["jwks_uri"] = issuer + "/jwks",
        });

    [Fact]
    public async Task Cached_metadata_is_not_reused_once_the_discovery_url_changes()
    {
        await LinkAliceAsync(Issuer);
        _provider.DiscoveryUrl = "https://idp.invalid/.well-known/openid-configuration";

        // The seeded metadata belongs to the old URL, so discovery is fetched
        // again for the new one, which does not resolve.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _oidc.ExchangeIdTokenAsync(_provider, IdToken("42"), accessToken: null));
        Assert.Contains("idp.invalid", ex.Message);
        Assert.Null(Assert.Single((await _store.GetUserDataAsync(_alice.Id)).SsoLinks).LastUsedAt);
    }

    private Task LinkAliceAsync(string issuer, bool retired = false) => _store.MutateAsync(_alice.Id, d => d.SsoLinks.Add(new SsoLink
    {
        ProviderId = ProviderId,
        Subject = "42",
        Issuer = issuer,
        LinkedAt = DateTime.UtcNow.AddDays(-30),
        RetiredAt = retired ? DateTime.UtcNow : null,
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
public sealed class OidcProviderLinkRetirementTests : IDisposable
{
    private const string DiscoveryUrl = "https://idp.example/realms/corp/.well-known/openid-configuration";
    private const string DefaultProvider = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    private readonly string _sandbox;
    private readonly MediaBrowser.Common.Configuration.IApplicationPaths _paths;
    private readonly Plugin? _previous = Plugin.Instance;
    private readonly Plugin _plugin;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challenges = new();
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly OidcService _oidc;
    private readonly SecurityController _controller;
    private readonly User _alice = new("alice", DefaultProvider, "reset");
    private readonly User _bob = new("bob", DefaultProvider, "reset");
    private readonly IApplicationHost _host = Substitute.For<IApplicationHost>();

    public OidcProviderLinkRetirementTests()
    {
        var paths = TestApplicationPaths.Create(out _sandbox);
        _paths = paths;
        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        _plugin = new Plugin(paths, serializer, _host, Substitute.For<ILogger<Plugin>>());
        _plugin.Configuration.OidcProviders.Add(new OidcProvider
        {
            Id = "corp",
            DisplayName = "Corp",
            DiscoveryUrl = DiscoveryUrl,
            ClientId = "jellyfin",
            Enabled = true,
        });

        _store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        _host.Resolve<UserTwoFactorStore>().Returns(_store);
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
    public async Task Changing_the_discovery_url_retires_the_providers_links()
    {
        var result = await _controller.UpdateProvider("corp", Request("https://other-idp.example/.well-known/openid-configuration"));

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(new[] { "corp:retired", "other:active" }, await LinksAsync(_alice));
        Assert.Equal(new[] { "corp:retired" }, await LinksAsync(_bob));

        var audit = await _store.GetAuditLogAsync();
        var retired = audit.Where(e => e.Method == "oidc_links_retired").ToList();
        Assert.Equal(2, retired.Count);
        Assert.All(retired, e => Assert.Equal(AuditResult.ConfigChanged, e.Result));
        Assert.Contains(retired, e => e.UserId == _alice.Id && e.Username == "alice");
        Assert.Contains(retired, e => e.UserId == _bob.Id);
    }

    [Fact]
    public async Task Moving_between_the_root_and_the_well_known_url_counts_as_a_change()
    {
        var result = await _controller.UpdateProvider("corp", Request("https://idp.example/realms/corp"));

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(new[] { "corp:retired" }, await LinksAsync(_bob));
    }

    [Fact]
    public async Task An_edit_that_keeps_the_discovery_url_keeps_the_links()
    {
        var request = Request("https://IDP.example/realms/corp/.well-known/openid-configuration");
        request.DisplayName = "Corporate sign-in";

        var result = await _controller.UpdateProvider("corp", request);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("Corporate sign-in", _plugin.Configuration.OidcProviders.Single().DisplayName);
        Assert.Equal(new[] { "corp:active", "other:active" }, await LinksAsync(_alice));
        Assert.Equal(new[] { "corp:active" }, await LinksAsync(_bob));
        Assert.DoesNotContain(await _store.GetAuditLogAsync(), e => e.Method == "oidc_links_retired");
    }

    [Fact]
    public async Task A_rejected_slug_changes_neither_the_provider_nor_its_links()
    {
        _plugin.Configuration.OidcProviders.Add(new OidcProvider { Id = "taken", DisplayName = "Taken", DiscoveryUrl = "https://t.example" });
        var request = Request("https://other-idp.example/.well-known/openid-configuration");
        request.DisplayName = "Renamed";
        request.CallbackSlug = "taken";

        var result = await _controller.UpdateProvider("corp", request);

        Assert.IsType<ConflictObjectResult>(result);
        var corp = _plugin.Configuration.OidcProviders.Single(p => p.Id == "corp");
        Assert.Equal(DiscoveryUrl, corp.DiscoveryUrl);
        Assert.Equal("Corp", corp.DisplayName);
        Assert.Equal(new[] { "corp:active" }, await LinksAsync(_bob));

        // The retry, with a free slug, still sees the URL change.
        request.CallbackSlug = "corp-new";
        Assert.IsType<OkObjectResult>(await _controller.UpdateProvider("corp", request));
        Assert.Equal(new[] { "corp-new:retired" }, await LinksAsync(_bob));
    }

    [Fact]
    public async Task Deleting_a_provider_retires_its_links()
    {
        var result = await _controller.DeleteProvider("corp");

        Assert.IsType<OkResult>(result);
        Assert.Empty(_plugin.Configuration.OidcProviders);
        Assert.Equal(new[] { "corp:retired", "other:active" }, await LinksAsync(_alice));
        Assert.Equal(new[] { "corp:retired" }, await LinksAsync(_bob));
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
        Assert.Equal(new[] { "corp:retired", "other:active" }, await LinksAsync(_alice));
        Assert.Equal(new[] { "corp:retired" }, await LinksAsync(_bob));
    }

    [Fact]
    public async Task The_generic_settings_save_retires_links_of_a_re_pointed_provider()
    {
        var incoming = new PluginConfiguration();
        incoming.OidcProviders.Add(new OidcProvider { Id = "corp", DisplayName = "Corp", DiscoveryUrl = "https://other-idp.example", ClientId = "jellyfin" });

        _plugin.UpdateConfiguration(incoming);

        Assert.Equal(new[] { "corp:retired" }, await LinksAsync(_bob));
        Assert.Equal(new[] { "corp:retired", "other:active" }, await LinksAsync(_alice));
    }

    [Fact]
    public async Task Unlinking_one_row_keeps_a_row_that_differs_only_by_issuer()
    {
        await _store.MutateAsync(_alice.Id, d =>
            d.SsoLinks.Add(new SsoLink { ProviderId = "corp", Subject = "a-1", Issuer = "https://new-idp.example" }));
        await ListAliceLinksAsync();
        var oldId = (await _store.GetUserDataAsync(_alice.Id)).SsoLinks.Single(l => l.Issuer == "https://idp.example/realms/corp").Id;

        // The old route cannot tell the two rows apart and removes nothing.
        Assert.IsType<ConflictObjectResult>(await _controller.UnlinkMine("corp", "a-1"));
        Assert.Equal(3, (await _store.GetUserDataAsync(_alice.Id)).SsoLinks.Count);

        Assert.IsType<OkResult>(await _controller.UnlinkMineById(oldId));
        var remaining = (await _store.GetUserDataAsync(_alice.Id)).SsoLinks;
        Assert.Equal(2, remaining.Count);
        Assert.Contains(remaining, l => l.ProviderId == "corp" && l.Issuer == "https://new-idp.example");
    }

    [Fact]
    public async Task The_old_unlink_route_refuses_a_subject_shown_by_a_retired_and_an_active_row()
    {
        // Retire the corp row, then link the same subject again.
        await _store.MutateAsync(_alice.Id, d =>
        {
            OidcLinkRetirement.Retire(d, new HashSet<string> { "corp" }, "test", DateTime.UtcNow);
            d.SsoLinks.Add(new SsoLink { ProviderId = "corp", Subject = "a-1", Issuer = "https://new-idp.example" });
        });
        var listed = await ListAliceLinksAsync();
        Assert.Equal(2, listed.Count(l => l.GetProperty("subject").GetString() == "a-1"));

        Assert.IsType<ConflictObjectResult>(await _controller.UnlinkMine("corp", "a-1"));
        Assert.Equal(3, (await _store.GetUserDataAsync(_alice.Id)).SsoLinks.Count);
    }

    [Fact]
    public async Task Listing_links_gives_every_row_a_stable_id_and_marks_retired_ones()
    {
        await _store.MutateAsync(_alice.Id, d => d.SsoLinks[0].RetiredAt = DateTime.UtcNow);

        var first = await ListAliceLinksAsync();
        var second = await ListAliceLinksAsync();

        Assert.All(first, l => Assert.False(string.IsNullOrEmpty(l.GetProperty("id").GetString())));
        Assert.Equal(first.Select(l => l.GetProperty("id").GetString()), second.Select(l => l.GetProperty("id").GetString()));
        Assert.Equal(new[] { true, false }, first.Select(l => l.GetProperty("retired").GetBoolean()));
    }

    private async Task<List<System.Text.Json.JsonElement>> ListAliceLinksAsync()
    {
        var result = await _controller.ListMyLinks();
        var ok = Assert.IsType<OkObjectResult>(result.Result);
        return System.Text.Json.JsonSerializer.SerializeToElement(ok.Value).EnumerateArray().ToList();
    }

    [Fact]
    public async Task A_failed_write_leaves_the_link_active_and_a_retry_retires_it()
    {
        // Make Bob's next write fail: the temp file path is a directory.
        var bobFile = Directory.GetFiles(_sandbox, $"{_bob.Id}.json", SearchOption.AllDirectories).Single();
        Directory.CreateDirectory(bobFile + ".tmp");

        await Assert.ThrowsAnyAsync<Exception>(() => _controller.UpdateProvider("corp", Request("https://other-idp.example")));
        Assert.Equal(new[] { "corp:active" }, await LinksAsync(_bob));
        Assert.Equal(DiscoveryUrl, _plugin.Configuration.OidcProviders.Single().DiscoveryUrl);

        Directory.Delete(bobFile + ".tmp");
        Assert.IsType<OkObjectResult>(await _controller.UpdateProvider("corp", Request("https://other-idp.example")));
        Assert.Equal(new[] { "corp:retired" }, await LinksAsync(_bob));

        // What is on disk agrees after a restart.
        using var restarted = new UserTwoFactorStore(_paths, Substitute.For<IServiceProvider>());
        Assert.NotNull(Assert.Single((await restarted.GetUserDataAsync(_bob.Id)).SsoLinks).RetiredAt);
    }

    [Fact]
    public async Task A_retried_rename_spares_the_rows_it_already_moved()
    {
        // An earlier provider left a stale row under the destination slug.
        await _store.MutateAsync(_alice.Id, d => d.SsoLinks.Add(new SsoLink { ProviderId = "corp-new", Subject = "stale" }));
        var request = Request(DiscoveryUrl);
        request.CallbackSlug = "corp-new";

        // First attempt moved the rows, then the save was lost: config still says "corp".
        Assert.IsType<OkObjectResult>(await _controller.UpdateProvider("corp", request));
        _plugin.Configuration.OidcProviders.Single().Id = "corp";
        Assert.IsType<OkObjectResult>(await _controller.UpdateProvider("corp", request));

        var alice = (await _store.GetUserDataAsync(_alice.Id)).SsoLinks;
        Assert.Null(alice.Single(l => l.Issuer == "https://idp.example/realms/corp").RetiredAt);
        Assert.NotNull(alice.Single(l => l.Subject.EndsWith("stale", StringComparison.Ordinal)).RetiredAt);
        Assert.Equal(new[] { "corp-new:active" }, await LinksAsync(_bob));
    }

    [Fact]
    public async Task A_retried_rename_with_another_discovery_url_retires_the_rows_it_moved()
    {
        var request = Request(DiscoveryUrl);
        request.CallbackSlug = "corp-new";
        Assert.IsType<OkObjectResult>(await _controller.UpdateProvider("corp", request));
        _plugin.Configuration.OidcProviders.Single().Id = "corp";

        // The admin revises the lost edit and points it at another IdP.
        var revised = Request("https://other-idp.example");
        revised.CallbackSlug = "corp-new";
        Assert.IsType<OkObjectResult>(await _controller.UpdateProvider("corp", revised));

        Assert.Equal(new[] { "corp-new:retired" }, await LinksAsync(_bob));
        Assert.True((await _store.GetUserDataAsync(_alice.Id)).SsoLinks.Single(l => l.RenamedFrom == "corp").IsRetired);
    }

    [Fact]
    public async Task A_row_retired_without_the_prefix_is_converted_when_the_store_restarts()
    {
        await _store.MutateAsync(_bob.Id, d => d.SsoLinks[0].RetiredAt = DateTime.UtcNow);

        using var restarted = new UserTwoFactorStore(_paths, Substitute.For<IServiceProvider>());
        Assert.Equal(SsoLink.RetiredSubjectPrefix + "b-1", Assert.Single((await restarted.GetUserDataAsync(_bob.Id)).SsoLinks).Subject);
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

    private async Task<string[]> LinksAsync(User user)
        => (await _store.GetUserDataAsync(user.Id)).SsoLinks
            .Select(l => l.ProviderId + (l.IsRetired ? ":retired" : ":active"))
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();
}

using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#319] Passkey sign-in without typing the username first. The
/// controller runs against the real stores and Fido2NetLib; a software ES256
/// authenticator signs the assertions the browser would send.</summary>
public sealed class UsernamelessPasskeySignInTests : IDisposable
{
    private const string Origin = "http://localhost:8096";
    private const string ClientAddress = "203.0.113.7";
    private const string DefaultProvider = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    private readonly string _sandbox;
    private readonly UserTwoFactorStore _store;
    private readonly IpBanService _bans;
    private readonly PasskeyChallengeStore _challenges = new();
    private readonly OidcLoginTokenStore _bridge = new();
    private readonly RateLimiter _rateLimiter = new();
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly PasskeyService _passkeys;
    private readonly IpAllowlistService _allowlist;

    private readonly User _alice = new("alice", DefaultProvider, "reset");
    private readonly User _bob = new("bob", DefaultProvider, "reset");
    private readonly SoftwarePasskey _alicePasskey;
    private readonly SoftwarePasskey _bobPasskey;

    public UsernamelessPasskeySignInTests()
    {
        var paths = TestApplicationPaths.Create(out _sandbox);
        _store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        _bans = new IpBanService(paths, NullLogger<IpBanService>.Instance);
        _passkeys = new PasskeyService(_store, NullLogger<PasskeyService>.Instance);
        _allowlist = new IpAllowlistService(_store, NullLogger<IpAllowlistService>.Instance);

        foreach (var user in new[] { _alice, _bob })
        {
            _users.GetUserByName(user.Username).Returns(user);
            _users.GetUserById(user.Id).Returns(user);
        }

        // Jellyfin's IUserManager.GetUserById throws ArgumentException for an empty Guid.
        _users.GetUserById(Guid.Empty).Returns(_ => throw new ArgumentException("id is an empty Guid."));

        _alicePasskey = new SoftwarePasskey(_alice.Id);
        _bobPasskey = new SoftwarePasskey(_bob.Id);
        Register(_alice.Id, _alicePasskey).GetAwaiter().GetResult();
        Register(_bob.Id, _bobPasskey).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        _alicePasskey.Dispose();
        _bobPasskey.Dispose();
        _challenges.Dispose();
        _bridge.Dispose();
        _bans.Dispose();
        _store.Dispose();
        try { Directory.Delete(_sandbox, recursive: true); } catch (IOException) { /* best-effort cleanup */ }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Begin_without_a_username_offers_every_discoverable_passkey(string? username)
    {
        var (options, nonce) = await BeginAsync(username);

        Assert.Equal(0, AllowCredentialCount(options));
        Assert.Equal("required", options.GetProperty("userVerification").GetString());

        // The nonce belongs to nobody, so no flow keyed to a user accepts it.
        var stored = _challenges.Consume(nonce);
        Assert.NotNull(stored.OptionsJson);
        Assert.Null(stored.UserId);
    }

    [Fact]
    public async Task Complete_without_a_username_signs_in_the_passkey_owner()
    {
        var (options, nonce) = await BeginAsync(null);
        var assertion = _alicePasskey.Sign(options, counter: 1);

        var result = await CompleteAsync(null, nonce, assertion);

        var body = AssertOk(result);
        Assert.Equal("alice", body.GetProperty("username").GetString());
        var token = body.GetProperty("token").GetString()!;
        Assert.NotNull(_bridge.Consume(token, "alice"));

        var stored = Passkey(await _store.GetUserDataAsync(_alice.Id));
        Assert.Equal(1u, stored.SignatureCounter);
        Assert.NotNull(stored.LastUsedAt);
        Assert.Equal(typeof(TwoFactorAuthProvider).FullName, _alice.AuthenticationProviderId);
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Fact]
    public async Task Complete_with_a_username_still_works_as_before()
    {
        var (options, nonce) = await BeginAsync("alice");
        Assert.Equal(1, AllowCredentialCount(options));

        var result = await CompleteAsync("alice", nonce, _alicePasskey.Sign(options, counter: 1));

        Assert.Equal("alice", AssertOk(result).GetProperty("username").GetString());
    }

    [Fact]
    public async Task A_user_handle_naming_another_account_is_refused()
    {
        var (options, nonce) = await BeginAsync(null);
        // Alice's credential and signature, but the handle names Bob.
        var assertion = _alicePasskey.Sign(options, counter: 1, userHandle: _bob.Id);

        var result = await CompleteAsync(null, nonce, assertion);

        AssertGenericRefusal(result);
        Assert.Equal(0, await FailedAttempts(_bob));
        Assert.Equal(0, await FailedAttempts(_alice));
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_alice.Id)).SignatureCounter);
    }

    [Fact]
    public async Task A_credential_of_another_account_is_refused()
    {
        var (options, nonce) = await BeginAsync(null);
        // Bob's credential and signature, but the handle names Alice.
        var assertion = _bobPasskey.Sign(options, counter: 1, userHandle: _alice.Id);

        var result = await CompleteAsync(null, nonce, assertion);

        AssertGenericRefusal(result);
        Assert.Equal(0, await FailedAttempts(_alice));
        Assert.Equal(0, await FailedAttempts(_bob));
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_bob.Id)).SignatureCounter);
    }

    [Fact]
    public async Task An_unknown_credential_is_refused()
    {
        using var stranger = new SoftwarePasskey(_alice.Id);
        var (options, nonce) = await BeginAsync(null);

        var result = await CompleteAsync(null, nonce, stranger.Sign(options, counter: 1));

        AssertGenericRefusal(result);
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Fact]
    public async Task A_user_handle_of_no_account_is_refused()
    {
        var (options, nonce) = await BeginAsync(null);
        var assertion = _alicePasskey.Sign(options, counter: 1, userHandle: Guid.NewGuid());

        AssertGenericRefusal(await CompleteAsync(null, nonce, assertion));
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task An_assertion_without_a_user_handle_is_refused(bool emptyHandle)
    {
        var (options, nonce) = await BeginAsync(null);
        var assertion = _alicePasskey.Sign(options, counter: 1, omitUserHandle: !emptyHandle, userHandleBytes: emptyHandle ? Array.Empty<byte>() : null);

        AssertGenericRefusal(await CompleteAsync(null, nonce, assertion));
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Fact]
    public async Task A_nonce_is_single_use()
    {
        var (options, nonce) = await BeginAsync(null);
        var assertion = _alicePasskey.Sign(options, counter: 1);
        AssertOk(await CompleteAsync(null, nonce, assertion));

        var replay = await CompleteAsync(null, nonce, assertion);

        AssertGenericRefusal(replay);
        // A spent nonce is refused before any account is looked at, so the
        // replay counts against the address only.
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Fact]
    public async Task A_nonce_from_the_username_flow_is_refused_without_a_username()
    {
        var (options, nonce) = await BeginAsync("alice");

        var result = await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 1));

        AssertGenericRefusal(result);
        Assert.Equal(0, await FailedAttempts(_alice));
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_alice.Id)).SignatureCounter);
    }

    [Fact]
    public async Task A_nonce_without_a_username_is_refused_in_the_username_flow()
    {
        var (options, nonce) = await BeginAsync(null);

        var result = await CompleteAsync("alice", nonce, _alicePasskey.Sign(options, counter: 1));

        AssertGenericRefusal(result);
        Assert.Equal(1, await FailedAttempts(_alice));
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_alice.Id)).SignatureCounter);
    }

    [Fact]
    public async Task A_bad_signature_counts_against_the_account_until_it_locks()
    {
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var (options, nonce) = await BeginAsync(null);
            var assertion = _alicePasskey.Sign(options, counter: (uint)attempt, corruptSignature: true);

            AssertGenericRefusal(await CompleteAsync(null, nonce, assertion));
            Assert.Equal(attempt, await FailedAttempts(_alice));
        }

        Assert.True(await _store.IsLockedOutAsync(_alice.Id));
    }

    [Fact]
    public async Task The_network_allowlist_of_the_owner_applies()
    {
        await _store.MutateAsync(_alice.Id, d => d.IpAllowlistCidrs.Add("10.0.0.0/8"));
        var (options, nonce) = await BeginAsync(null);

        var result = await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 1));

        // Without a username the refusal is the generic one: a network message
        // would confirm that the handle and credential belong to an account.
        AssertGenericRefusal(result);
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_alice.Id)).SignatureCounter);
        Assert.Equal(DefaultProvider, _alice.AuthenticationProviderId);
    }

    [Fact]
    public async Task Every_refusal_without_a_username_looks_the_same()
    {
        await _store.MutateAsync(_alice.Id, d => d.IpAllowlistCidrs.Add("10.0.0.0/8"));
        using var stranger = new SoftwarePasskey(Guid.NewGuid());
        var (knownOptions, knownNonce) = await BeginAsync(null);
        var (unknownOptions, unknownNonce) = await BeginAsync(null);

        var refusals = new[]
        {
            // A real account and credential, refused by the account's allowlist.
            await CompleteAsync(null, knownNonce, _alicePasskey.Sign(knownOptions, counter: 1, corruptSignature: true)),
            // A handle and credential of no account.
            await CompleteAsync(null, unknownNonce, stranger.Sign(unknownOptions, counter: 1)),
            // A real account and credential with a nonce that was never issued.
            await CompleteAsync(null, "never-issued", _alicePasskey.Sign(knownOptions, counter: 1)),
        };

        var bodies = refusals.Select(r =>
        {
            AssertGenericRefusal(r);
            return JsonSerializer.Serialize(((ObjectResult)r).Value);
        });
        Assert.Single(bodies.Distinct());
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Fact]
    public async Task A_refused_attempt_spends_its_nonce()
    {
        var (options, nonce) = await BeginAsync(null);
        AssertGenericRefusal(await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 1, userHandle: _bob.Id)));

        var retry = await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 2));

        AssertGenericRefusal(retry);
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_alice.Id)).SignatureCounter);
    }

    [Fact]
    public async Task A_zero_user_handle_gets_the_generic_refusal()
    {
        var (options, nonce) = await BeginAsync(null);

        var result = await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 1, userHandle: Guid.Empty));

        AssertGenericRefusal(result);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public async Task A_user_handle_of_the_wrong_length_is_refused(int length)
    {
        var (options, nonce) = await BeginAsync(null);
        var handle = _alice.Id.ToByteArray().Concat(new byte[1]).Take(length).ToArray();

        var result = await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 1, userHandleBytes: handle));

        AssertGenericRefusal(result);
        Assert.Equal(0, await FailedAttempts(_alice));
    }

    [Fact]
    public async Task A_banned_address_is_refused_before_anything_else()
    {
        var (options, nonce) = await BeginAsync(null);
        _bans.Ban(ClientAddress, "test", "test", 1);

        var begin = Assert.IsType<ObjectResult>(await Controller().PasskeyLoginBegin(new SecurityController.PasskeyLoginBeginRequest()));
        var complete = Assert.IsType<ObjectResult>(await CompleteAsync(null, nonce, _alicePasskey.Sign(options, counter: 1)));

        Assert.Equal(StatusCodes.Status403Forbidden, begin.StatusCode);
        Assert.Equal(StatusCodes.Status403Forbidden, complete.StatusCode);
        Assert.Equal(0u, Passkey(await _store.GetUserDataAsync(_alice.Id)).SignatureCounter);
    }

    [Fact]
    public async Task Begin_without_a_username_shares_the_rate_limit()
    {
        for (var i = 0; i < 20; i++)
        {
            await BeginAsync(null);
        }

        var limited = Assert.IsType<ObjectResult>(await Controller().PasskeyLoginBegin(new SecurityController.PasskeyLoginBeginRequest { Username = "alice" }));
        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public void Registration_asks_for_a_discoverable_credential_without_requiring_one()
    {
        var context = HttpContextFor(ClientAddress);
        var json = _passkeys.BuildRegistrationOptions(context, _alice.Id, "alice", Array.Empty<PasskeyCredential>());

        using var options = JsonDocument.Parse(json);
        var selection = options.RootElement.GetProperty("authenticatorSelection");
        Assert.Equal("preferred", selection.GetProperty("residentKey").GetString());
        Assert.False(selection.GetProperty("requireResidentKey").GetBoolean());
        Assert.Equal(_alice.Id.ToByteArray(), Base64UrlDecode(options.RootElement.GetProperty("user").GetProperty("id").GetString()!));
    }

    [Fact]
    public void A_malformed_response_names_no_account()
    {
        Assert.Null(PasskeyService.ReadDiscoverableAssertion("not json"));
        Assert.Null(PasskeyService.ReadDiscoverableAssertion("{}"));
        Assert.Null(PasskeyService.ReadDiscoverableAssertion("{\"rawId\":\"@@@\",\"response\":{\"userHandle\":\"AAAAAAAAAAAAAAAAAAAAAA\"}}"));
        Assert.Null(PasskeyService.ReadDiscoverableAssertion("{\"rawId\":\"AAAA\",\"response\":{\"userHandle\":\"@@@\"}}"));
        Assert.Null(PasskeyService.ReadDiscoverableAssertion("{\"rawId\":\"AAAA\",\"response\":{\"userHandle\":\"AAAAAAAAAAAAAAAAAAAAAA\"}}"));
    }

    [Fact]
    public async Task A_malformed_response_without_a_username_gets_the_generic_refusal()
    {
        var (_, nonce) = await BeginAsync(null);

        AssertGenericRefusal(await CompleteAsync(null, nonce, "{\"rawId\":\"@@@\",\"response\":{\"userHandle\":\"@@@\"}}"));
        AssertGenericRefusal(await CompleteAsync(null, nonce, "not json"));
    }

    private async Task Register(Guid userId, SoftwarePasskey passkey)
        => await _store.MutateAsync(userId, d => d.Passkeys.Add(new PasskeyCredential
        {
            Id = Guid.NewGuid().ToString("N"),
            CredentialId = Base64UrlEncode(passkey.CredentialId),
            PublicKeyCose = Convert.ToBase64String(passkey.CoseKey),
            Label = "test",
            CreatedAt = DateTime.UtcNow,
        }));

    private SecurityController Controller() => new(
        oidc: null!,
        oidcBridge: _bridge,
        bans: _bans,
        allowlist: _allowlist,
        store: _store,
        passkeys: _passkeys,
        passkeyChallenges: _challenges,
        userManager: _users,
        rateLimiter: _rateLimiter,
        stepUp: null!,
        challenges: null!,
        onboardingProofs: null!,
        sessionManager: null!,
        externalUrls: null!,
        logger: NullLogger<SecurityController>.Instance)
    {
        ControllerContext = new ControllerContext { HttpContext = HttpContextFor(ClientAddress) },
    };

    private static DefaultHttpContext HttpContextFor(string address)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("localhost", 8096);
        context.Connection.RemoteIpAddress = IPAddress.Parse(address);
        return context;
    }

    private async Task<(JsonElement Options, string Nonce)> BeginAsync(string? username)
    {
        var result = await Controller().PasskeyLoginBegin(new SecurityController.PasskeyLoginBeginRequest { Username = username });
        var body = AssertOk(result);
        using var options = JsonDocument.Parse(body.GetProperty("options").GetString()!);
        return (options.RootElement.Clone(), body.GetProperty("nonce").GetString()!);
    }

    private Task<IActionResult> CompleteAsync(string? username, string nonce, string response)
        => Controller().PasskeyLoginComplete(new SecurityController.PasskeyLoginCompleteRequest
        {
            Username = username,
            Nonce = nonce,
            Response = response,
        });

    private static JsonElement AssertOk(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return JsonSerializer.SerializeToElement(ok.Value);
    }

    private static void AssertGenericRefusal(IActionResult result)
    {
        var refusal = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Passkey verification failed.", JsonSerializer.SerializeToElement(refusal.Value).GetProperty("message").GetString());
    }

    private static int AllowCredentialCount(JsonElement options)
        => options.TryGetProperty("allowCredentials", out var allow) ? allow.GetArrayLength() : 0;

    private async Task<int> FailedAttempts(User user) => (await _store.GetUserDataAsync(user.Id)).FailedAttemptCount;

    private static PasskeyCredential Passkey(UserTwoFactorData data) => Assert.Single(data.Passkeys);

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + ((4 - (t.Length % 4)) % 4), '='));
    }

    /// <summary>An ES256 authenticator holding one discoverable credential.</summary>
    private sealed class SoftwarePasskey : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly Guid _userId;

        public SoftwarePasskey(Guid userId)
        {
            _userId = userId;
            CredentialId = RandomNumberGenerator.GetBytes(16);
            var point = _key.ExportParameters(false).Q;
            // COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
            CoseKey = new byte[] { 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 }
                .Concat(point.X!)
                .Concat(new byte[] { 0x22, 0x58, 0x20 })
                .Concat(point.Y!)
                .ToArray();
        }

        public byte[] CredentialId { get; }

        public byte[] CoseKey { get; }

        /// <summary>The JSON inject.js posts to LoginComplete as Response.</summary>
        public string Sign(
            JsonElement options,
            uint counter,
            Guid? userHandle = null,
            bool omitUserHandle = false,
            byte[]? userHandleBytes = null,
            bool corruptSignature = false)
        {
            var clientData = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get",
                challenge = options.GetProperty("challenge").GetString(),
                origin = Origin,
                crossOrigin = false,
            });

            // rpIdHash, flags UP|UV, signature counter (big-endian)
            var signCount = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(signCount, counter);
            var authData = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"))
                .Concat(new byte[] { 0x05 })
                .Concat(signCount)
                .ToArray();
            var signature = _key.SignData(
                authData.Concat(SHA256.HashData(clientData)).ToArray(),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            if (corruptSignature)
            {
                signature[^1] ^= 0xFF;
            }

            var handle = userHandleBytes ?? (userHandle ?? _userId).ToByteArray();
            var id = Base64UrlEncode(CredentialId);
            return JsonSerializer.Serialize(new
            {
                id,
                rawId = id,
                type = "public-key",
                response = new
                {
                    authenticatorData = Base64UrlEncode(authData),
                    clientDataJSON = Base64UrlEncode(clientData),
                    signature = Base64UrlEncode(signature),
                    userHandle = omitUserHandle ? null : Base64UrlEncode(handle),
                },
            });
        }

        public void Dispose() => _key.Dispose();
    }
}

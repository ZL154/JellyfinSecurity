using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class PasskeyChallengeSuccessTests
{
    [Fact]
    public async Task Successful_passkey_clears_prior_wrong_codes_and_only_the_matching_limiter_keys()
    {
        using var flow = new SignInFlow();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await flow.RegisterKey(key);
        var challenge = flow.Challenge();
        for (var i = 0; i < 3; i++)
        {
            var result = await flow.Controller.Verify(new VerifyRequest
            {
                ChallengeToken = challenge.Token, Method = "recovery", Code = "WRONG",
            });
            Assert.IsType<UnauthorizedObjectResult>(result.Result);
        }
        Assert.Equal(3, (await flow.Store.GetUserDataAsync(flow.UserId)).FailedAttemptCount);
        var other = Guid.NewGuid();
        await flow.Store.RecordFailedAttemptAsync(other);
        flow.Fill("verify_user:" + other.ToString("N"), 15);
        flow.Fill("verify:198.51.100.2", 10);
        flow.Fill("verify_user:" + flow.UserId.ToString("N"), 12);
        flow.Fill("verify:" + SignInFlow.Address, 7);

        var resultOk = await flow.Finish(challenge, key, false);

        Assert.Equal(challenge.PendingAuthResponse, Assert.IsType<ContentResult>(resultOk).Content);
        var data = await flow.Store.GetUserDataAsync(flow.UserId);
        Assert.Equal(0, data.FailedAttemptCount);
        Assert.Null(data.LockoutEnd);
        Assert.Equal(1, (await flow.Store.GetUserDataAsync(other)).FailedAttemptCount);
        Assert.True(flow.Limiter.CheckAndRecord("verify_user:" + flow.UserId.ToString("N"), 15, TimeSpan.FromMinutes(15)).allowed);
        Assert.True(flow.Limiter.CheckAndRecord("verify:" + SignInFlow.Address, 10, TimeSpan.FromMinutes(1)).allowed);
        Assert.False(flow.Limiter.CheckAndRecord("verify_user:" + other.ToString("N"), 15, TimeSpan.FromMinutes(15)).allowed);
        Assert.False(flow.Limiter.CheckAndRecord("verify:198.51.100.2", 10, TimeSpan.FromMinutes(1)).allowed);
        Assert.True(flow.Challenges.IsDevicePreVerified(flow.UserId, "browser"));
        Assert.Null(flow.Challenges.GetChallenge(challenge.Token));
        // Begin and Finish share the ceremony budget; completing a ceremony
        // must not let a client evade its cryptographic-work limit.
        flow.Fill("pk_assert:" + SignInFlow.Address, 18);
        Assert.False(flow.Limiter.CheckAndRecord("pk_assert:" + SignInFlow.Address, 20, TimeSpan.FromMinutes(1)).allowed);
    }

    [Theory]
    [InlineData(true, "browser", "Test browser")]
    [InlineData(false, "browser", "Test browser")]
    [InlineData(true, null, "Test browser")]
    [InlineData(true, "", "Test browser")]
    [InlineData(true, "browser", null)]
    public async Task Code_and_passkey_apply_the_same_device_choice(bool remember, string? device, string? name)
    {
        using var flow = new SignInFlow();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await flow.RegisterKey(key);
        var byCode = flow.Challenge(device, name);
        await flow.Store.MutateAsync(flow.UserId, data => data.RecoveryCodes.Add(new RecoveryCode
        {
            Hash = RecoveryCodeService.HashCodeV2("ABCDE23456"),
        }));
        var codeResult = await flow.Controller.Verify(new VerifyRequest
        {
            ChallengeToken = byCode.Token, Method = "recovery", Code = "ABCDE23456", TrustDevice = remember,
        });
        Assert.IsType<ContentResult>(codeResult.Result);
        await flow.AssertDeviceChoice(remember, device, name);
        await flow.Store.MutateAsync(flow.UserId, data => data.TrustedDevices.Clear());
        flow.Controller.Response.Headers.Clear();

        var byKey = flow.Challenge(device, name);
        Assert.IsType<ContentResult>(await flow.Finish(byKey, key, remember));
        await flow.AssertDeviceChoice(remember, device, name);
    }

    [Fact]
    public async Task Invalid_passkey_preserves_failures_limits_challenge_and_device_choice()
    {
        using var flow = new SignInFlow();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await flow.RegisterKey(key);
        await flow.Store.RecordFailedAttemptAsync(flow.UserId);
        flow.Fill("verify_user:" + flow.UserId.ToString("N"), 15);
        flow.Fill("verify:" + SignInFlow.Address, 10);
        var challenge = flow.Challenge();

        Assert.IsType<UnauthorizedObjectResult>(await flow.Finish(challenge, key, true, corrupt: true));

        var data = await flow.Store.GetUserDataAsync(flow.UserId);
        Assert.Equal(2, data.FailedAttemptCount);
        Assert.Empty(data.TrustedDevices);
        Assert.NotNull(flow.Challenges.GetChallenge(challenge.Token));
        Assert.False(flow.Challenges.IsDevicePreVerified(flow.UserId, "browser"));
        Assert.False(flow.Controller.Response.Headers.ContainsKey("X-TwoFactor-Device-Token"));
        Assert.False(flow.Limiter.CheckAndRecord("verify_user:" + flow.UserId.ToString("N"), 15, TimeSpan.FromMinutes(15)).allowed);
        Assert.False(flow.Limiter.CheckAndRecord("verify:" + SignInFlow.Address, 10, TimeSpan.FromMinutes(1)).allowed);
    }

    private sealed class SignInFlow : IDisposable
    {
        public const string Address = "198.51.100.1";
        private readonly string _root;
        private readonly PasskeyChallengeStore _ceremonies = new();
        private readonly PendingPairingService _pairings = new(NullLogger<PendingPairingService>.Instance);
        private readonly IpBanService _bans;
        private readonly GeoIpService _geo = new(NullLogger<GeoIpService>.Instance);
        private readonly byte[] _credential = RandomNumberGenerator.GetBytes(16);
        public Guid UserId { get; } = Guid.NewGuid();
        public UserTwoFactorStore Store { get; }
        public ChallengeStore Challenges { get; } = new();
        public RateLimiter Limiter { get; } = new();
        public TwoFactorAuthController Controller { get; }

        public SignInFlow()
        {
            var paths = TestApplicationPaths.Create(out _root);
            Store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
            _bans = new IpBanService(paths, NullLogger<IpBanService>.Instance);
            var passkeys = new PasskeyService(Store, NullLogger<PasskeyService>.Instance);
            var notices = new NotificationService(NullLogger<NotificationService>.Instance);
            var observer = new SignInObserver(
                new SuspiciousLoginDetector(Store, _geo, notices, NullLogger<SuspiciousLoginDetector>.Instance),
                new ImpossibleTravelDetector(Store, notices, NullLogger<ImpossibleTravelDetector>.Instance),
                NullLogger<SignInObserver>.Instance);
            Controller = new TwoFactorAuthController(
                store: Store,
                challengeStore: Challenges,
                totpService: null!,
                emailOtpService: null!,
                deviceTokenService: new DeviceTokenService(),
                devicePairingService: null!,
                notificationService: null!,
                sessionManager: null!,
                userManager: null!,
                cookieSigner: null!,
                rateLimiter: Limiter,
                recoveryCodes: new RecoveryCodeService(),
                appPasswords: null!,
                pendingPairings: _pairings,
                deviceManager: null!,
                sessionTerm: null!,
                passkeys: passkeys,
                passkeyChallenges: _ceremonies,
                diagnostics: null!,
                stats: null!,
                userExport: null!,
                recoveryPdf: null!,
                ipBans: _bans,
                allowlist: new IpAllowlistService(Store, NullLogger<IpAllowlistService>.Instance),
                stepUp: null!,
                scoreService: null!,
                configExport: null!,
                onboardingProofs: null!,
                externalUrls: null!,
                signInObserver: observer,
                logger: NullLogger<TwoFactorAuthController>.Instance)
            {
                ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
            };
            Controller.Request.Scheme = "https";
            Controller.Request.Host = new HostString("localhost");
            Controller.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse(Address);
        }

        public Task RegisterKey(ECDsa key)
        {
            var point = key.ExportParameters(false).Q;
            var cose = new byte[] { 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 }
                .Concat(point.X!).Concat(new byte[] { 0x22, 0x58, 0x20 }).Concat(point.Y!).ToArray();
            return Store.MutateAsync(UserId, data => data.Passkeys.Add(new PasskeyCredential
            {
                CredentialId = B64(_credential), PublicKeyCose = Convert.ToBase64String(cose),
            }));
        }

        public ChallengeData Challenge(string? device = "browser", string? name = "Test browser")
        {
            var challenge = Challenges.CreateChallenge(UserId, "alice", new() { "passkey", "recovery" }, device, name, Address);
            challenge.PendingAuthResponse = "{\"AccessToken\":\"test-session\"}";
            return challenge;
        }

        public void Fill(string key, int count)
        {
            for (var i = 0; i < count; i++)
                Assert.True(Limiter.CheckAndRecord(key, 100, TimeSpan.FromMinutes(15)).allowed);
        }

        public async Task<IActionResult> Finish(ChallengeData challenge, ECDsa key, bool remember, bool corrupt = false)
        {
            var begin = Assert.IsType<ContentResult>(await Controller.PasskeyAssertBegin(
                new TwoFactorAuthController.PasskeyAssertBeginRequest { ChallengeToken = challenge.Token }));
            using var payload = JsonDocument.Parse(begin.Content!);
            var clientData = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get", challenge = payload.RootElement.GetProperty("options").GetProperty("challenge").GetString(),
                origin = "https://localhost", crossOrigin = false,
            });
            var counter = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(counter, 1);
            var authData = SHA256.HashData(Encoding.UTF8.GetBytes("localhost")).Concat(new byte[] { 0x05 }).Concat(counter).ToArray();
            var signature = key.SignData(authData.Concat(SHA256.HashData(clientData)).ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (corrupt) signature[^1] ^= 0xFF;
            var assertion = JsonSerializer.Serialize(new
            {
                id = B64(_credential), rawId = B64(_credential), type = "public-key",
                response = new
                {
                    authenticatorData = B64(authData), clientDataJSON = B64(clientData), signature = B64(signature),
                    userHandle = B64(UserId.ToByteArray()),
                },
            });
            // Deserialize the actual wire shape so the baseline also compiles
            // before the request model accepts the device choice.
            var request = JsonSerializer.Deserialize<TwoFactorAuthController.PasskeyAssertFinishRequest>(JsonSerializer.Serialize(new
            {
                challengeToken = challenge.Token, nonce = payload.RootElement.GetProperty("nonce").GetString(),
                response = assertion, trustDevice = remember,
            }), new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
            return await Controller.PasskeyAssertFinish(request);
        }

        public async Task AssertDeviceChoice(bool remember, string? device, string? name)
        {
            var data = await Store.GetUserDataAsync(UserId);
            if (!remember || string.IsNullOrEmpty(device))
            {
                Assert.Empty(data.TrustedDevices);
                Assert.False(Controller.Response.Headers.ContainsKey("X-TwoFactor-Device-Token"));
                return;
            }
            var record = Assert.Single(data.TrustedDevices);
            var token = Controller.Response.Headers["X-TwoFactor-Device-Token"].ToString();
            Assert.NotEmpty(token);
            Assert.Equal(device, record.DeviceId);
            Assert.Equal(name ?? device, record.DeviceName);
            Assert.False(record.IndefiniteTrust);
            Assert.Equal(DeviceTokenService.HashToken(token), record.TokenHash);
            Assert.NotEqual(token, record.TokenHash);
            Assert.True(new DeviceTokenService().ValidateToken(token, data.TrustedDevices, device, out _));
        }

        private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public void Dispose()
        {
            _geo.Dispose();
            _ceremonies.Dispose();
            _pairings.Dispose();
            _bans.Dispose();
            Challenges.Dispose();
            Store.Dispose();
            Directory.Delete(_root, recursive: true);
        }
    }
}

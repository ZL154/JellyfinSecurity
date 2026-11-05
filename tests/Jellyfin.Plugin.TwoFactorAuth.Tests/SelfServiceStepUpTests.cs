using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// The controller reads Plugin.Instance. Keep its temporary configuration away
// from every other collection and restore the singleton after each test.
[CollectionDefinition("Self-service step-up", DisableParallelization = true)]
public sealed class SelfServiceStepUpCollection;

[Collection("Self-service step-up")]
public sealed class SelfServiceStepUpTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Missing_code_requests_proof_without_changing_the_failure_count(string? code)
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);

        AssertProofRequired(await fixture.ChangeAsync(code));

        await fixture.AssertStateAsync(2);
    }

    [Fact]
    public async Task Five_handshakes_do_not_lock_the_user()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync();

        for (var i = 0; i < 5; i++)
            AssertProofRequired(await fixture.ChangeAsync());

        await fixture.AssertStateAsync(0);
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("foreign")]
    [InlineData("spent")]
    [InlineData("unknown")]
    public async Task An_unusable_token_without_a_code_requests_proof_without_counting_a_failure(string kind)
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);
        var token = fixture.Challenges.MintUserStepUpToken(kind == "foreign" ? Guid.NewGuid() : fixture.UserId);
        if (kind == "expired")
        {
            // Expire the real token deterministically without waiting for its TTL.
            var field = typeof(ChallengeStore).GetField("_userStepUpTokens", BindingFlags.Instance | BindingFlags.NonPublic)!;
            var tokens = (ConcurrentDictionary<string, (Guid UserId, DateTime ExpiresAt)>)field.GetValue(fixture.Challenges)!;
            tokens[token] = (fixture.UserId, DateTime.UtcNow.AddSeconds(-1));
        }
        else if (kind == "spent")
            Assert.True(fixture.Challenges.ConsumeUserStepUpToken(token, fixture.UserId));
        else if (kind == "unknown")
            token = "unknown-token";

        AssertProofRequired(await fixture.ChangeAsync(token: token));

        await fixture.AssertStateAsync(2);
    }

    [Fact]
    public async Task A_wrong_code_counts_as_one_failure()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);

        AssertProofRequired(await fixture.ChangeAsync("invalid"));

        await fixture.AssertStateAsync(3);
    }

    [Fact]
    public async Task A_stale_token_does_not_hide_a_wrong_code()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);

        AssertProofRequired(await fixture.ChangeAsync("invalid", "unknown-token"));

        await fixture.AssertStateAsync(3);
    }

    [Fact]
    public async Task A_valid_token_allows_one_change_without_resetting_failures()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);
        var token = fixture.Challenges.MintUserStepUpToken(fixture.UserId);

        Assert.IsType<OkObjectResult>(await fixture.ChangeAsync("invalid", token));
        Assert.True((await fixture.Store.GetUserDataAsync(fixture.UserId)).RequireStepUpForChanges);
        AssertProofRequired(await fixture.ChangeAsync(token: token));
        await fixture.AssertStateAsync(2, changed: true);
    }

    [Fact]
    public async Task A_correct_totp_allows_the_change_and_persists_the_replay_floor()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);
        var secret = KeyGeneration.GenerateRandomKey(20);
        await fixture.Store.MutateAsync(fixture.UserId, data =>
            data.EncryptedTotpSecret = fixture.Totp.EncryptSecret(Base32Encoding.ToString(secret), fixture.UserId));

        Assert.IsType<OkObjectResult>(await fixture.ChangeAsync(new Totp(secret).ComputeTotp()));

        var data = await fixture.Store.GetUserDataAsync(fixture.UserId);
        Assert.True(data.LastUsedTotpStep > 0);
        await fixture.AssertStateAsync(2, changed: true);
    }

    [Fact]
    public async Task A_correct_recovery_code_is_persisted_as_used_without_resetting_failures()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync(2);
        const string Code = "ABCDE-FGHIJ";
        await fixture.Store.MutateAsync(fixture.UserId, data => data.RecoveryCodes.Add(new RecoveryCode
        {
            Hash = RecoveryCodeService.HashCodeV2(RecoveryCodeService.NormalizeForCompare(Code)),
        }));

        Assert.IsType<OkObjectResult>(await fixture.ChangeAsync(Code));

        var used = Assert.Single((await fixture.Store.GetUserDataAsync(fixture.UserId)).RecoveryCodes);
        Assert.True(used.Used);
        Assert.NotNull(used.UsedAt);
        await fixture.AssertStateAsync(2, changed: true);
        AssertProofRequired(await fixture.ChangeAsync(Code));
        await fixture.AssertStateAsync(3, changed: true);
    }

    [Fact]
    public async Task Handshakes_do_not_spend_the_code_rate_limit()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync();

        for (var i = 0; i < 16; i++)
            AssertProofRequired(await fixture.ChangeAsync());

        AssertProofRequired(await fixture.ChangeAsync("invalid"));
        await fixture.AssertStateAsync(1);
    }

    [Fact]
    public async Task The_sixteenth_wrong_code_is_rate_limited_without_another_failure()
    {
        using var fixture = new Fixture();
        await fixture.EnrollAsync();

        for (var i = 0; i < 15; i++)
            AssertProofRequired(await fixture.ChangeAsync("invalid"));

        var result = Assert.IsType<ObjectResult>(await fixture.ChangeAsync("invalid"));
        Assert.Equal(StatusCodes.Status429TooManyRequests, result.StatusCode);
        var body = JsonSerializer.SerializeToElement(result.Value);
        Assert.True(body.GetProperty("stepUpRequired").GetBoolean());
        Assert.StartsWith("Too many verification attempts. Try again in ", body.GetProperty("message").GetString());
        var data = await fixture.Store.GetUserDataAsync(fixture.UserId);
        Assert.Equal(15, data.FailedAttemptCount);
        Assert.True(await fixture.Store.IsLockedOutAsync(fixture.UserId));
    }

    private static void AssertProofRequired(IActionResult response)
    {
        var result = Assert.IsType<ObjectResult>(response);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        var body = JsonSerializer.SerializeToElement(result.Value);
        Assert.True(body.GetProperty("stepUpRequired").GetBoolean());
        Assert.True(body.GetProperty("twoFactorRequired").GetBoolean());
        Assert.Equal("A current authenticator or recovery code is required to modify two-factor settings.", body.GetProperty("message").GetString());
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _sandbox;
        private readonly Plugin? _previous = Plugin.Instance;
        private readonly TwoFactorAuthController _controller;

        public Guid UserId { get; } = Guid.NewGuid();
        public UserTwoFactorStore Store { get; }
        public ChallengeStore Challenges { get; } = new();
        public TotpService Totp { get; }

        public Fixture()
        {
            var paths = TestApplicationPaths.Create(out _sandbox);
            var serializer = Substitute.For<IXmlSerializer>();
            serializer.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
            var plugin = new Plugin(paths, serializer, Substitute.For<IApplicationHost>(), Substitute.For<ILogger<Plugin>>());
            plugin.Configuration.SelfServiceStepUpMode = SelfServiceStepUpMode.Forced;
            plugin.Configuration.ExemptAdministratorsFromLockout = false;
            plugin.Configuration.MaxFailedAttempts = 5;
            plugin.Configuration.LockoutDurationMinutes = 15;
            Store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
            Totp = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
            _controller = new TwoFactorAuthController(
                store: Store, challengeStore: Challenges, totpService: Totp,
                emailOtpService: new EmailOtpService(Substitute.For<ILogger<EmailOtpService>>(), () => plugin.Configuration),
                deviceTokenService: null!, devicePairingService: null!, notificationService: null!,
                sessionManager: null!, userManager: null!, cookieSigner: null!, rateLimiter: new RateLimiter(),
                recoveryCodes: null!, appPasswords: null!, pendingPairings: null!, deviceManager: null!,
                sessionTerm: null!, passkeys: null!, passkeyChallenges: null!, diagnostics: null!, stats: null!,
                userExport: null!, recoveryPdf: null!, ipBans: null!, allowlist: null!,
                stepUp: new StepUpService(Totp, Challenges, Substitute.For<ILogger<StepUpService>>()),
                scoreService: null!, configExport: null!, onboardingProofs: null!, externalUrls: null!,
                signInObserver: null!, logger: Substitute.For<ILogger<TwoFactorAuthController>>())
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext
                    {
                        User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("Jellyfin-UserId", UserId.ToString()) }, "test")),
                    },
                },
            };
        }

        public Task EnrollAsync(int failures = 0) => Store.MutateAsync(UserId, data =>
        {
            data.TotpEnabled = true;
            data.TotpVerified = true;
            data.FailedAttemptCount = failures;
        });

        public Task<IActionResult> ChangeAsync(string? code = null, string? token = null)
            => _controller.SetMyStepUpPreference(new TwoFactorAuthController.StepUpPrefRequest
            {
                Enabled = true,
                Code = code,
                StepUpToken = token,
            });

        public async Task AssertStateAsync(int failures, bool changed = false)
        {
            var data = await Store.GetUserDataAsync(UserId);
            Assert.Equal(failures, data.FailedAttemptCount);
            Assert.Null(data.LockoutEnd);
            Assert.False(await Store.IsLockedOutAsync(UserId));
            Assert.Equal(changed, data.RequireStepUpForChanges);
        }

        public void Dispose()
        {
            Store.Dispose();
            Challenges.Dispose();
            typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
            Directory.Delete(_sandbox, recursive: true);
        }
    }
}

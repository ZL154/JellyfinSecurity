using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[Collection("SignInPolicy")]
public class PasskeysDisabledIntegrationTests
{
    public static IEnumerable<object[]> Routes()
    {
        yield return new object[] { "Passkeys/RegisterBegin" };
        yield return new object[] { "Passkeys/RegisterFinish" };
        yield return new object[] { "Passkey/LoginBegin" };
        yield return new object[] { "Passkey/LoginComplete" };
        yield return new object[] { "Verify/Passkey/Begin" };
        yield return new object[] { "Verify/Passkey/Finish" };
        yield return new object[] { "StepUp/UserPasskeyBegin" };
        yield return new object[] { "StepUp/UserPasskeyVerify" };
    }

    [Theory]
    [MemberData(nameof(Routes))]
    public async Task Refused_ceremonies_leave_challenges_counters_and_credentials_untouched(string route)
    {
        using var api = new DisabledPasskeyApi();
        await api.SeedAsync();
        var before = JsonSerializer.Serialize(await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id));
        var challenge = api.Fixture.Challenges.CreateChallenge(api.Fixture.User.Id, "local-user", new() { "passkey" }, null, null, null);
        var nonce = api.Ceremonies.Begin("saved-options", api.Fixture.User.Id);
        for (var i = 0; i < 22; i++)
        {
            using var response = await api.Client.PostAsJsonAsync("/TwoFactorAuth/" + route,
                new { username = "local-user", nonce, response = "invalid-assertion", challengeToken = challenge.Token });
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("Passkeys are disabled on this server.", body.RootElement.GetProperty("message").GetString());
            Assert.False(response.Headers.Contains("Retry-After"));
        }
        Assert.Equal(before, JsonSerializer.Serialize(await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id)));
        Assert.Empty(await api.Fixture.Store.GetAuditLogAsync());
        Assert.NotNull(api.Fixture.Challenges.GetChallenge(challenge.Token));
        Assert.Equal("saved-options", api.Ceremonies.Consume(nonce).OptionsJson);
        foreach (var bucket in new[] { "passkey_login:", "passkey_complete:", "pk_assert:" })
            for (var i = 0; i < 20; i++)
                Assert.True(api.Limiter.CheckAndRecord(bucket + "127.0.0.1", 20, TimeSpan.FromMinutes(5)).allowed);
    }

    [Theory]
    [InlineData(false, false, false, "enroll")]
    [InlineData(true, false, false, "enroll")]
    [InlineData(false, true, false, "enroll")]
    [InlineData(true, true, false, "email")]
    [InlineData(false, false, true, "recovery")]
    public async Task Required_enrollment_uses_the_methods_that_can_actually_answer(
        bool deliveryEnabled, bool address, bool recovery, string expected)
    {
        using var fixture = new SignInPolicyFixture();
        fixture.Config.PasskeysEnabled = false;
        fixture.Config.EnforcementScope = EnforcementScope.All;
        fixture.Config.EmailOtpEnabled = deliveryEnabled;
        if (address) fixture.Config.SetUserEmail(fixture.User.Id.ToString("N"), "person@example.test");
        var data = new UserTwoFactorData { UserId = fixture.User.Id, Passkeys = { new PasskeyCredential { Id = "saved" } } };
        if (recovery) data.RecoveryCodes.Add(new RecoveryCode { Hash = "saved-recovery" });
        await fixture.Store.SaveUserDataAsync(data);
        var (status, body) = await fixture.SignInAsync();
        Assert.Equal(401, status);
        using var result = JsonDocument.Parse(body);
        Assert.Equal(new[] { expected }, result.RootElement.GetProperty("Methods").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(expected == "enroll", result.RootElement.GetProperty("EnrollmentRequired").GetBoolean());
    }

    [Fact]
    public async Task Saved_passkeys_remain_listed_removable_and_the_preference_stays_writable()
    {
        using var api = new DisabledPasskeyApi();
        await api.SeedAsync();
        using var listed = await api.Client.GetAsync("/TwoFactorAuth/Passkeys");
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        using var items = JsonDocument.Parse(await listed.Content.ReadAsStringAsync());
        Assert.Single(items.RootElement.EnumerateArray());
        using var preference = await api.Client.PostAsJsonAsync("/TwoFactorAuth/MyPasskeySecondFactorPreference", new { enabled = true });
        Assert.Equal(HttpStatusCode.OK, preference.StatusCode);
        using var deleted = await api.Client.DeleteAsync("/TwoFactorAuth/Passkeys/saved-key");
        Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);
        Assert.Empty((await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id)).Passkeys);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_verified_app_is_offered_without_a_disabled_passkey(bool enabled)
    {
        using var fixture = new SignInPolicyFixture();
        fixture.Config.PasskeysEnabled = enabled;
        await fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = fixture.User.Id,
            TotpEnabled = true,
            TotpVerified = true,
            Passkeys = { new PasskeyCredential { Id = "saved-key" } },
        });
        var (status, body) = await fixture.SignInAsync();
        Assert.Equal(401, status);
        using var result = JsonDocument.Parse(body);
        var methods = result.RootElement.GetProperty("Methods").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Contains("totp", methods);
        Assert.Equal(enabled, methods.Contains("passkey"));
        await fixture.ProcessSessionAsync();
        Assert.True(fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
    }

    [Fact]
    public async Task Status_and_coverage_count_only_enabled_factors_but_report_stored_credentials()
    {
        using var api = new DisabledPasskeyApi();
        await api.SeedAsync();
        using var response = await api.Client.GetAsync("/TwoFactorAuth/MyStatus");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(1, body.RootElement.GetProperty("PasskeyCount").GetInt32());
        Assert.False(body.RootElement.GetProperty("CanCreateAppPasswords").GetBoolean());
        Assert.Equal("none", body.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
        Assert.Equal(0, (await api.Stats.ComputeAsync()).EnrolledCount);
        var score = await api.Score.ComputeAsync();
        Assert.Equal(0, Assert.Single(score.Factors, x => x.Id == "coverage").Earned);
        api.Fixture.Config.PasskeysEnabled = true;
        Assert.Equal(1, (await api.Stats.ComputeAsync()).EnrolledCount);
        Assert.Equal(30, Assert.Single((await api.Score.ComputeAsync()).Factors, x => x.Id == "coverage").Earned);
        Assert.False((await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id)).PasskeyRequiresSecondFactor);
    }

    [Theory]
    [InlineData("passkey", false)]
    [InlineData("oidc-provider", true)]
    public async Task Previously_issued_bridge_tokens_honor_the_current_switch(string source, bool accepted)
    {
        using var api = new DisabledPasskeyApi();
        var app = Substitute.For<IApplicationHost>();
        app.Resolve<MediaBrowser.Controller.Library.IUserManager>().Returns(api.Fixture.Users);
        var provider = new TwoFactorAuthProvider(app, api.Fixture.Store, api.Fixture.Challenges,
            new BypassEvaluator(NullLogger<BypassEvaluator>.Instance), null!, null!, null!, api.Limiter, api.Bridge,
            api.Bans, new IpAllowlistService(api.Fixture.Store, NullLogger<IpAllowlistService>.Instance),
            new Microsoft.AspNetCore.Http.HttpContextAccessor(), NullLogger<TwoFactorAuthProvider>.Instance);
        var token = api.Bridge.Mint(api.Fixture.User.Id, api.Fixture.User.Username, source);
        if (accepted)
            Assert.Equal(api.Fixture.User.Username, (await provider.Authenticate(api.Fixture.User.Username, token)).Username);
        else
        {
            var error = await Assert.ThrowsAsync<AuthenticationException>(() => provider.Authenticate(api.Fixture.User.Username, token));
            Assert.Equal("Passkeys are disabled on this server.", error.Message);
            Assert.Empty(await api.Fixture.Store.GetAuditLogAsync());
        }
    }
}

internal sealed class DisabledPasskeyApi : IDisposable
{
    private readonly TestServer _server;
    internal SignInPolicyFixture Fixture { get; } = new();
    internal PasskeyChallengeStore Ceremonies { get; } = new();
    internal OidcLoginTokenStore Bridge { get; } = new();
    internal RateLimiter Limiter { get; } = new();
    internal IpBanService Bans { get; }
    internal StatsService Stats { get; }
    internal SecurityScoreService Score { get; }
    internal HttpClient Client { get; }

    internal DisabledPasskeyApi()
    {
        Fixture.Config.PasskeysEnabled = false;
        var paths = TestApplicationPaths.Create();
        var totp = new TotpService(paths, NullLogger<TotpService>.Instance);
        var codes = new EmailOtpService(NullLogger<EmailOtpService>.Instance, Fixture.Store);
        var stepUp = new StepUpService(totp, Fixture.Challenges, NullLogger<StepUpService>.Instance);
        var notices = new NotificationService(NullLogger<NotificationService>.Instance);
        var passkeys = new PasskeyService(Fixture.Store, NullLogger<PasskeyService>.Instance);
        var allowlist = new IpAllowlistService(Fixture.Store, NullLogger<IpAllowlistService>.Instance);
        Bans = new IpBanService(paths, NullLogger<IpBanService>.Instance);
        Stats = new StatsService(Fixture.Store, Fixture.Users);
        Score = new SecurityScoreService(Fixture.Store, Stats, paths, NullLogger<SecurityScoreService>.Instance, () => Fixture.Config);
        _server = new TestServer(new WebHostBuilder().ConfigureServices(services =>
        {
            services.AddAuthentication("test").AddScheme<AuthenticationSchemeOptions, PreferenceTestAuth>("test", _ => { });
            services.AddAuthorization(options => options.AddPolicy("RequiresElevation", p => p.RequireAuthenticatedUser()));
            services.AddControllers().AddApplicationPart(typeof(TwoFactorAuthController).Assembly)
                .AddJsonOptions(options => options.JsonSerializerOptions.PropertyNamingPolicy = null).AddControllersAsServices();
            services.AddTransient(_ => new TwoFactorAuthController(
                store: Fixture.Store, challengeStore: Fixture.Challenges, totpService: totp, emailOtpService: codes,
                deviceTokenService: new DeviceTokenService(), devicePairingService: null!, notificationService: notices,
                sessionManager: Fixture.Sessions, userManager: Fixture.Users, cookieSigner: null!, rateLimiter: Limiter,
                recoveryCodes: null!, appPasswords: null!, pendingPairings: null!, deviceManager: Fixture.Devices,
                sessionTerm: null!, passkeys: passkeys, passkeyChallenges: Ceremonies, diagnostics: null!, stats: Stats,
                userExport: null!, recoveryPdf: null!, ipBans: Bans, allowlist: allowlist, stepUp: stepUp, scoreService: Score,
                configExport: null!, onboardingProofs: null!, externalUrls: null!, signInObserver: null!,
                logger: NullLogger<TwoFactorAuthController>.Instance));
            services.AddTransient(_ => new SecurityController(null!, Bridge, Bans, allowlist, Fixture.Store, passkeys,
                Ceremonies, Fixture.Users, Limiter, stepUp, Fixture.Challenges, null!, Fixture.Sessions, null!, NullLogger<SecurityController>.Instance));
        }).Configure(app => { app.Use((context, next) => { context.Connection.RemoteIpAddress = IPAddress.Loopback; return next(context); }); app.UseRouting(); app.UseAuthentication(); app.UseAuthorization(); app.UseEndpoints(e => e.MapControllers()); }));
        Client = _server.CreateClient();
        Client.DefaultRequestHeaders.Add("X-Test-User", Fixture.User.Id.ToString());
    }

    internal Task SeedAsync() => Fixture.Store.SaveUserDataAsync(new UserTwoFactorData
    {
        UserId = Fixture.User.Id,
        PasskeyRequiresSecondFactor = false,
        Passkeys = { new PasskeyCredential { Id = "saved-key", CredentialId = "credential" } },
    });

    public void Dispose()
    {
        Client.Dispose(); _server.Dispose(); Score.Dispose(); Bans.Dispose(); Bridge.Dispose(); Ceremonies.Dispose(); Fixture.Dispose();
    }
}

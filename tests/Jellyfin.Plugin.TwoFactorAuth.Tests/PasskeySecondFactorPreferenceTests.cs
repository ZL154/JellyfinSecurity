using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[Collection("SignInPolicy")]
public class PasskeySecondFactorPreferenceTests
{
    private const string Route = "/TwoFactorAuth/MyPasskeySecondFactorPreference";

    [Fact]
    public async Task Enabling_needs_no_proof_and_updates_only_the_caller_with_fixed_audit_names()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(false);
        var other = Guid.NewGuid();
        await api.Fixture.Store.SaveUserDataAsync(new UserTwoFactorData { UserId = other, PasskeyRequiresSecondFactor = false });
        using var response = await api.Client.PostAsJsonAsync(Route, new { enabled = true, userId = other });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.GetProperty("PasskeyRequiresSecondFactor").GetBoolean());
        Assert.True(json.RootElement.GetProperty("PasswordSignInRequiresSecondFactor").GetBoolean());
        Assert.Equal("passkey", json.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
        Assert.False((await api.Fixture.Store.GetUserDataAsync(other)).PasskeyRequiresSecondFactor);
        var entry = Assert.Single(await api.Fixture.Store.GetAuditLogAsync());
        Assert.Equal(api.Fixture.User.Id, entry.UserId);
        Assert.Equal(AuditResult.ConfigChanged, entry.Result);
        Assert.Equal("passkey_second_factor_on", entry.Method);
    }

    [Theory]
    [InlineData(SelfServiceStepUpMode.Off)]
    [InlineData(SelfServiceStepUpMode.UserChoice)]
    [InlineData(SelfServiceStepUpMode.Forced)]
    public async Task Disabling_always_needs_fresh_owner_bound_proof(SelfServiceStepUpMode mode)
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(true);
        api.Fixture.Config.SelfServiceStepUpMode = mode;
        using var denied = await api.Client.PostAsJsonAsync(Route, new { enabled = false });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var denial = JsonDocument.Parse(await denied.Content.ReadAsStringAsync());
        Assert.True(denial.RootElement.GetProperty("stepUpRequired").GetBoolean());
        Assert.True((await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id)).PasskeyRequiresSecondFactor);
        Assert.Empty(await api.Fixture.Store.GetAuditLogAsync());

        var foreign = api.Fixture.Challenges.MintUserStepUpToken(Guid.NewGuid());
        using var wrongOwner = await api.Client.PostAsJsonAsync(Route, new { enabled = false, stepUpToken = foreign });
        Assert.Equal(HttpStatusCode.Forbidden, wrongOwner.StatusCode);
        var proof = api.Fixture.Challenges.MintUserStepUpToken(api.Fixture.User.Id);
        using var accepted = await api.Client.PostAsJsonAsync(Route, new { enabled = false, stepUpToken = proof });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        using var state = JsonDocument.Parse(await accepted.Content.ReadAsStringAsync());
        Assert.False(state.RootElement.GetProperty("PasswordSignInRequiresSecondFactor").GetBoolean());
        Assert.Equal("none", state.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
        using var replay = await api.Client.PostAsJsonAsync(Route, new { enabled = false, stepUpToken = proof });
        Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
        var entry = Assert.Single(await api.Fixture.Store.GetAuditLogAsync(), e => e.Result == AuditResult.ConfigChanged);
        Assert.Equal("passkey_second_factor_off", entry.Method);
    }

    [Fact]
    public async Task Read_reports_stored_preference_separately_from_scope_and_authenticator_enforcement()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(false);
        api.Fixture.Config.EnforcementScope = EnforcementScope.All;
        using var scoped = await api.Client.GetAsync("/TwoFactorAuth/MyStatus");
        using var scope = JsonDocument.Parse(await scoped.Content.ReadAsStringAsync());
        Assert.False(scope.RootElement.GetProperty("PasskeyRequiresSecondFactor").GetBoolean());
        Assert.True(scope.RootElement.GetProperty("PasswordSignInRequiresSecondFactor").GetBoolean());
        Assert.Equal("scope", scope.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
        api.Fixture.Config.EnforcementScope = EnforcementScope.Optional;
        await api.Fixture.Store.MutateAsync(api.Fixture.User.Id, data => { data.TotpEnabled = true; data.TotpVerified = true; });
        using var appResponse = await api.Client.GetAsync("/TwoFactorAuth/MyStatus");
        using var app = JsonDocument.Parse(await appResponse.Content.ReadAsStringAsync());
        Assert.Equal("authenticator", app.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Without_a_passkey_the_preference_cannot_be_set(bool enabled)
    {
        using var api = new PreferenceApi();
        using var response = await api.Client.PostAsJsonAsync(Route, new { enabled });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("passkey", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await api.Fixture.Store.GetAuditLogAsync());
    }

    [Fact]
    public async Task Missing_choice_is_rejected_and_a_no_op_does_not_add_an_audit_entry()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(true);
        using var missing = await api.Client.PostAsJsonAsync(Route, new { });
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        using var same = await api.Client.PostAsJsonAsync(Route, new { enabled = true });
        Assert.Equal(HttpStatusCode.OK, same.StatusCode);
        Assert.Empty(await api.Fixture.Store.GetAuditLogAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_current_code_can_be_submitted_directly_or_exchanged_for_a_single_use_token(bool exchange)
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(true);
        var secret = KeyGeneration.GenerateRandomKey(20);
        await api.Fixture.Store.MutateAsync(api.Fixture.User.Id, data =>
        {
            data.TotpEnabled = true;
            data.TotpVerified = true;
            data.EncryptedTotpSecret = api.Totp.EncryptSecret(Base32Encoding.ToString(secret), data.UserId);
        });
        var code = new Totp(secret).ComputeTotp();
        string? proof = null;
        if (exchange)
        {
            using var verification = await api.Client.PostAsJsonAsync("/TwoFactorAuth/StepUp/UserCodeVerify", new { code });
            Assert.Equal(HttpStatusCode.OK, verification.StatusCode);
            using var token = JsonDocument.Parse(await verification.Content.ReadAsStringAsync());
            proof = token.RootElement.GetProperty("stepUpToken").GetString();
        }
        using var response = await api.Client.PostAsJsonAsync(Route, new { enabled = false, code = exchange ? null : code, stepUpToken = proof });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var state = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(state.RootElement.GetProperty("PasskeyRequiresSecondFactor").GetBoolean());
        Assert.True(state.RootElement.GetProperty("PasswordSignInRequiresSecondFactor").GetBoolean());
        Assert.Equal("authenticator", state.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
        Assert.True((await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id)).LastUsedTotpStep > 0);
    }

    [Fact]
    public async Task Invalid_codes_are_throttled_by_the_existing_step_up_limiter()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(true);
        api.Fixture.Config.SelfServiceStepUpMode = SelfServiceStepUpMode.Off;
        for (var attempt = 0; attempt < 15; attempt++)
        {
            using var denied = await api.Client.PostAsJsonAsync(Route, new { enabled = false, code = "invalid" });
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }
        using var limited = await api.Client.PostAsJsonAsync(Route, new { enabled = false, code = "invalid" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True((await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id)).PasskeyRequiresSecondFactor);
    }

    [Fact]
    public async Task Mandatory_scope_stays_effective_after_a_stored_opt_out_and_in_the_export()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(true);
        api.Fixture.Config.EnforcementScope = EnforcementScope.All;
        var proof = api.Fixture.Challenges.MintUserStepUpToken(api.Fixture.User.Id);
        using var response = await api.Client.PostAsJsonAsync(Route, new { enabled = false, stepUpToken = proof });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var state = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(state.RootElement.GetProperty("PasskeyRequiresSecondFactor").GetBoolean());
        Assert.True(state.RootElement.GetProperty("PasswordSignInRequiresSecondFactor").GetBoolean());
        Assert.Equal("scope", state.RootElement.GetProperty("PasswordSignInSecondFactorReason").GetString());
        var export = new UserExportService(api.Fixture.Store, api.Fixture.Users);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(await export.BuildExportAsync(api.Fixture.User.Id)));
        var factors = json.RootElement.GetProperty("twoFactor");
        Assert.False(factors.GetProperty("passkeyRequiresSecondFactor").GetBoolean());
        Assert.True(factors.GetProperty("passwordSignInRequiresSecondFactor").GetBoolean());
        Assert.Equal("scope", factors.GetProperty("passwordSignInSecondFactorReason").GetString());
    }

    [Fact]
    public async Task Changing_the_preference_preserves_lockout_and_other_restrictions()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(true);
        var until = DateTime.UtcNow.AddMinutes(10);
        await api.Fixture.Store.MutateAsync(api.Fixture.User.Id, data =>
        {
            data.FailedAttemptCount = 3;
            data.LockoutEnd = until;
            data.IpAllowlistCidrs.Add("192.0.2.0/24");
            data.RequirePasskeyOnly = true;
        });
        api.Fixture.Config.DisablePasswordLogin = true;
        var proof = api.Fixture.Challenges.MintUserStepUpToken(api.Fixture.User.Id);
        using var response = await api.Client.PostAsJsonAsync(Route, new { enabled = false, stepUpToken = proof });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var data = await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id);
        Assert.False(data.PasskeyRequiresSecondFactor);
        Assert.Equal(3, data.FailedAttemptCount);
        Assert.Equal(until, data.LockoutEnd);
        Assert.Equal("192.0.2.0/24", Assert.Single(data.IpAllowlistCidrs));
        Assert.True(data.RequirePasskeyOnly);
        Assert.True(api.Fixture.Config.DisablePasswordLogin);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Emergency_lockout_still_requires_recovery_after_an_opt_out(bool preference)
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(preference);
        using var emergency = await api.Client.PostAsJsonAsync("/TwoFactorAuth/Setup/EmergencyLockout", new { });
        Assert.Equal(HttpStatusCode.OK, emergency.StatusCode);
        var data = await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id);
        Assert.True(data.ForceRecoveryOnNextLogin);
        Assert.True(data.PasskeyRequiresSecondFactor);
        var audit = await api.Fixture.Store.GetAuditLogAsync();
        Assert.Single(audit, entry => entry.Method == "emergency_lockout");
        Assert.Equal(preference ? 0 : 1, audit.Count(entry => entry.Method == "passkey_second_factor_on"));
        var (status, body) = await api.Fixture.SignInAsync();
        Assert.Equal(401, status);
        using var challenge = JsonDocument.Parse(body);
        var methods = challenge.RootElement.GetProperty("Methods").EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Contains("recovery", methods);
        Assert.DoesNotContain("passkey", methods);
    }

    [Fact]
    public async Task Emergency_lockout_rearms_a_stored_passkey_while_passkeys_are_off()
    {
        using var api = new PreferenceApi();
        await api.EnrollAsync(false);
        api.Fixture.Config.PasskeysEnabled = false;
        using var emergency = await api.Client.PostAsJsonAsync("/TwoFactorAuth/Setup/EmergencyLockout", new { });
        Assert.Equal(HttpStatusCode.OK, emergency.StatusCode);
        var data = await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id);
        Assert.True(data.ForceRecoveryOnNextLogin);
        // [#345] The switch keeps the passkey out of sign-in, but turning it back
        // on must not bring back an opted-out passkey that skips the challenge.
        Assert.True(data.PasskeyRequiresSecondFactor);
        var audit = await api.Fixture.Store.GetAuditLogAsync();
        Assert.Single(audit, entry => entry.Method == "emergency_lockout");
        Assert.Single(audit, entry => entry.Method == "passkey_second_factor_on");
    }

    [Fact]
    public async Task Emergency_lockout_without_a_passkey_does_not_change_the_preference()
    {
        using var api = new PreferenceApi();
        await api.Fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = api.Fixture.User.Id,
            PasskeyRequiresSecondFactor = false,
        });
        using var response = await api.Client.PostAsJsonAsync("/TwoFactorAuth/Setup/EmergencyLockout", new { });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var data = await api.Fixture.Store.GetUserDataAsync(api.Fixture.User.Id);
        Assert.True(data.ForceRecoveryOnNextLogin);
        Assert.False(data.PasskeyRequiresSecondFactor);
        Assert.Equal("emergency_lockout", Assert.Single(await api.Fixture.Store.GetAuditLogAsync()).Method);
    }

    [Fact]
    public async Task Both_endpoints_require_an_authenticated_user()
    {
        using var api = new PreferenceApi();
        api.Client.DefaultRequestHeaders.Remove("X-Test-User");
        using var read = await api.Client.GetAsync("/TwoFactorAuth/MyStatus");
        using var write = await api.Client.PostAsJsonAsync(Route, new { enabled = false });
        Assert.Equal(HttpStatusCode.Unauthorized, read.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, write.StatusCode);
    }
}

internal sealed class PreferenceApi : IDisposable
{
    private readonly TestServer _server;
    internal SignInPolicyFixture Fixture { get; } = new();
    internal HttpClient Client { get; }
    internal TotpService Totp { get; }

    internal PreferenceApi()
    {
        var paths = TestApplicationPaths.Create();
        Totp = new TotpService(paths, NullLogger<TotpService>.Instance);
        var codes = new EmailOtpService(NullLogger<EmailOtpService>.Instance, Fixture.Store);
        var limiter = new RateLimiter();
        var stepUp = new StepUpService(Totp, Fixture.Challenges, NullLogger<StepUpService>.Instance);
        var termination = new SessionTerminationService(Fixture.Sessions, Fixture.Devices, Fixture.Challenges, NullLogger<SessionTerminationService>.Instance);
        var notifications = new NotificationService(NullLogger<NotificationService>.Instance);
        _server = new TestServer(new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddAuthentication("test").AddScheme<AuthenticationSchemeOptions, PreferenceTestAuth>("test", _ => { });
                services.AddAuthorization();
                services.AddControllers().AddApplicationPart(typeof(TwoFactorAuthController).Assembly)
                    .AddJsonOptions(options => options.JsonSerializerOptions.PropertyNamingPolicy = null).AddControllersAsServices();
                services.AddTransient(_ => new TwoFactorAuthController(
                    store: Fixture.Store, challengeStore: Fixture.Challenges, totpService: Totp, emailOtpService: codes,
                    deviceTokenService: new DeviceTokenService(), devicePairingService: null!, notificationService: notifications,
                    sessionManager: Fixture.Sessions, userManager: Fixture.Users, cookieSigner: null!, rateLimiter: limiter,
                    recoveryCodes: null!, appPasswords: null!, pendingPairings: null!, deviceManager: Fixture.Devices,
                    sessionTerm: termination, passkeys: null!, passkeyChallenges: null!, diagnostics: null!, stats: null!,
                    userExport: null!, recoveryPdf: null!, ipBans: null!, allowlist: null!, stepUp: stepUp, scoreService: null!,
                    configExport: null!, onboardingProofs: null!, externalUrls: null!, signInObserver: null!,
                    logger: NullLogger<TwoFactorAuthController>.Instance));
            })
            .Configure(app => { app.UseRouting(); app.UseAuthentication(); app.UseAuthorization(); app.UseEndpoints(endpoints => endpoints.MapControllers()); }));
        Client = _server.CreateClient();
        Client.DefaultRequestHeaders.Add("X-Test-User", Fixture.User.Id.ToString());
    }

    internal Task EnrollAsync(bool preference) => Fixture.Store.SaveUserDataAsync(new UserTwoFactorData
    {
        UserId = Fixture.User.Id,
        PasskeyRequiresSecondFactor = preference,
        Passkeys = { new PasskeyCredential { Id = "key" } },
    });

    public void Dispose()
    {
        Client.Dispose();
        _server.Dispose();
        Fixture.Dispose();
    }
}

internal sealed class PreferenceTestAuth : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public PreferenceTestAuth(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Guid.TryParse(Request.Headers["X-Test-User"], out var id)) return Task.FromResult(AuthenticateResult.NoResult());
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("Jellyfin-UserId", id.ToString()) }, Scheme.Name));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
    }
}

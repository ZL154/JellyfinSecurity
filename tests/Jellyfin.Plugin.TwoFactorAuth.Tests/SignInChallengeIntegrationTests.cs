using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Jellyfin.Data;
using Jellyfin.Data.Queries;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Entities.Security;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Querying;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[CollectionDefinition("SignInPolicy", DisableParallelization = true)]
public class SignInPolicyCollection;

[Collection("SignInPolicy")]
public class SignInChallengeIntegrationTests
{
    [Theory]
    [InlineData("oidc", false)]
    [InlineData(HeaderSignIn.BridgeProviderId, false)]
    [InlineData("passkey", true)]
    public async Task Accepted_bridges_apply_account_policy_without_granting_extra_proof(string origin, bool bypass)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        var ticket = fixture.Bridges.Mint(fixture.User.Id, fixture.User.Username, origin, bypassPluginTwoFa: bypass);
        var response = await fixture.SignInAsync(password: ticket, authenticate: async context =>
        {
            var result = await fixture.AuthenticateAsync(context, ticket);
            Assert.Equal(fixture.User.Username, result.Username);
            Assert.Equal(bypass, fixture.Challenges.IsDevicePreVerified(fixture.User.Id, SignInPolicyFixture.DeviceId));
            await fixture.ProcessSessionAsync();
        });
        Assert.Equal(200, response.Status);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.Equal(bypass, fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.DoesNotContain(await fixture.Store.GetAuditLogAsync(), e => e.Result == AuditResult.ChallengeIssued);
    }

    [Theory]
    [InlineData("eligible", 200)]
    [InlineData("recovery", 401)]
    [InlineData("scope", 401)]
    [InlineData("totp", 401)]
    [InlineData("password", 401)]
    [InlineData("missing", 401)]
    [InlineData("directory-error", 401)]
    public async Task Quick_connect_without_proof_uses_the_current_account_policy(string condition, int status)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        if (condition == "recovery") await fixture.Store.MutateAsync(fixture.User.Id, d => d.ForceRecoveryOnNextLogin = true);
        if (condition == "scope") fixture.Config.EnforcementScope = EnforcementScope.All;
        if (condition == "totp") await fixture.Store.MutateAsync(fixture.User.Id, d => d.TotpEnabled = d.TotpVerified = true);
        if (condition == "password") fixture.User.Password = "stored";
        if (condition == "missing") fixture.Users.GetUserById(fixture.User.Id).Returns((User?)null);
        if (condition == "directory-error") fixture.Users.GetUserById(fixture.User.Id).Returns(_ => throw new IOException("Directory unavailable."));
        await fixture.ProcessSessionAsync();
        var response = await fixture.SignInAsync("/media/Users/AuthenticateWithQuickConnect/");
        Assert.Equal(status, response.Status);
        Assert.Equal(status == 200 ? 200 : 403, await fixture.UseTokenAsync());
        Assert.False(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
    }

    [Theory]
    [InlineData(true, false, "DeviceId", true)]
    [InlineData(true, true, "deviceId", true)]
    [InlineData(false, false, "DeviceId", true)]
    [InlineData(false, true, "deviceId", false)]
    [InlineData(false, true, "DeviceId", false)]
    [InlineData(false, false, "deviceId", false)]
    public async Task Headerless_quick_connect_uses_response_casing_allowed_for_the_target(
        bool eligible, bool camelCase, string deviceProperty, bool accepted)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        if (!eligible) fixture.User.Password = "stored";
        var (credential, device) = new DeviceTokenService().CreateDeviceToken(SignInPolicyFixture.DeviceId, "Browser");
        await fixture.Store.MutateAsync(fixture.User.Id, data => data.TrustedDevices.Add(device));
        fixture.Challenges.BlockToken(SignInPolicyFixture.Token);
        var response = await fixture.SignInAsync("/media/Users/AuthenticateWithQuickConnect/", authenticate: context =>
        {
            context.Request.Headers.Remove("X-Emby-Device-Id");
            context.Request.Headers["X-TwoFactor-Token"] = credential;
            return Task.CompletedTask;
        }, camelCase: camelCase, sessionInfo: new Dictionary<string, string> { [deviceProperty] = SignInPolicyFixture.DeviceId });
        Assert.Equal(accepted ? 200 : 401, response.Status);
        Assert.Equal(accepted ? 200 : 403, await fixture.UseTokenAsync());
        Assert.Equal(accepted, fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        var audit = await fixture.Store.GetAuditLogAsync();
        if (accepted) Assert.Equal("trusted_device", Assert.Single(audit).Method);
        else Assert.DoesNotContain(audit, entry => entry.Method == "trusted_device");
    }

    [Theory]
    [InlineData(true, 401)]
    [InlineData(false, 200)]
    public async Task Only_a_newly_exempt_target_reconciles_a_prior_hold(bool activePreference, int expectedStatus)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        var credentialDevice = activePreference ? "other-device" : SignInPolicyFixture.DeviceId;
        var (credential, device) = new DeviceTokenService().CreateDeviceToken(credentialDevice, "Tablet");
        await fixture.Store.MutateAsync(fixture.User.Id, data =>
        {
            data.PasskeyRequiresSecondFactor = activePreference;
            data.TrustedDevices.Add(device);
        });
        fixture.Config.LanBypassEnabled = true;
        fixture.Config.LanBypassCidrs = ["203.0.113.10/32"];
        fixture.Challenges.BlockToken(SignInPolicyFixture.Token);
        var response = await fixture.SignInAsync("/Users/AuthenticateWithQuickConnect", authenticate: context =>
        {
            context.Request.Headers["X-Emby-Device-Id"] = credentialDevice;
            context.Request.Headers["X-TwoFactor-Token"] = credential;
            return Task.CompletedTask;
        });
        Assert.Equal(expectedStatus, response.Status);
        Assert.Equal(403, await fixture.UseTokenAsync());
        Assert.False(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
    }

    [Theory]
    [InlineData(false, false, 200)]
    [InlineData(false, true, 401)]
    [InlineData(true, false, 401)]
    [InlineData(false, null, 401)]
    [InlineData(true, null, 401)]
    public async Task Admin_scope_requires_both_roles_to_allow_a_native_exemption(bool directoryAdmin, bool? responseAdmin, int expectedStatus)
    {
        using var fixture = new SignInPolicyFixture(admin: directoryAdmin);
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        var policy = new Dictionary<string, bool>();
        if (responseAdmin.HasValue) policy.Add("IsAdministrator", responseAdmin.Value);
        var response = await fixture.SignInAsync("/Users/AuthenticateWithQuickConnect", responsePolicy: policy);
        Assert.Equal(expectedStatus, response.Status);
    }

    [Theory]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/Users/0123456789abcdef0123456789abcdef/Authenticate")]
    [InlineData("/Users/AuthenticateWithQuickConnect/other")]
    public async Task An_ambiguous_native_response_retains_the_challenge(string path)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        Assert.Equal(401, (await fixture.SignInAsync(path)).Status);
        fixture.Users.DidNotReceive().GetUserById(fixture.User.Id);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Network_restrictions_apply_before_the_eligible_native_response(bool banned)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        if (banned)
        {
            fixture.Config.IpBanEnabled = true;
            fixture.Bans.Ban("203.0.113.10", "manual", "test", 1);
        }
        else
        {
            await fixture.Store.MutateAsync(fixture.User.Id, data => data.IpAllowlistCidrs.Add("192.0.2.0/24"));
        }
        Assert.Equal(403, (await fixture.SignInAsync("/Users/AuthenticateWithQuickConnect")).Status);
        fixture.Users.DidNotReceive().GetUserById(fixture.User.Id);
    }

    [Fact]
    public async Task A_bridge_for_another_user_cannot_exempt_the_password_response()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        var other = new User("other-user", "provider", "reset");
        fixture.Users.GetUserById(other.Id).Returns(other);
        var ticket = fixture.Bridges.Mint(other.Id, other.Username, "oidc", bypassPluginTwoFa: false);
        var response = await fixture.SignInAsync(password: ticket,
            authenticate: context => fixture.AuthenticateAsync(context, ticket, other.Username));
        Assert.Equal(401, response.Status);
    }

    [Fact]
    public async Task A_successful_password_delegation_keeps_the_provider_and_response_challenges()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        const string password = "accepted-by-delegate";
        var delegated = Substitute.For<IAuthenticationProvider>();
        delegated.IsEnabled.Returns(true);
        delegated.Authenticate(fixture.User.Username, password).Returns(new ProviderAuthenticationResult { Username = fixture.User.Username });
        fixture.Host.GetExports<IAuthenticationProvider>(false).Returns(new[] { delegated });
        var response = await fixture.SignInAsync(password: password, authenticate: async context =>
        {
            Assert.Equal(fixture.User.Username, (await fixture.AuthenticateAsync(context, password)).Username);
            Assert.Contains(await fixture.Store.GetAuditLogAsync(), entry => entry.Result == AuditResult.ChallengeIssued);
        });
        Assert.Equal(401, response.Status);
        Assert.Equal(403, await fixture.UseTokenAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task The_provider_rejects_blank_credentials_before_delegation(string blank)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        await Assert.ThrowsAsync<AuthenticationException>(() => fixture.AuthenticateAsync(new DefaultHttpContext(), blank));
        fixture.Host.DidNotReceive().GetExports<IAuthenticationProvider>(false);
    }

    [Fact]
    public async Task A_matched_app_credential_retains_its_preverification_and_one_shot_allowance()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        var (password, hash) = new AppPasswordService().Generate();
        await fixture.Store.MutateAsync(fixture.User.Id, d => d.AppPasswords.Add(new AppPassword { PasswordHash = hash, Label = "TV" }));
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Emby-Device-Id"] = SignInPolicyFixture.DeviceId;
        context.Request.Headers["X-Emby-Client"] = "TV";
        Assert.Equal(fixture.User.Username, (await fixture.AuthenticateAsync(context, password)).Username);
        Assert.True(fixture.Challenges.IsDevicePreVerified(fixture.User.Id, SignInPolicyFixture.DeviceId));
        await fixture.ProcessSessionAsync();
        Assert.False(fixture.Challenges.ConsumeAppPasswordPending(fixture.User.Id));
        Assert.True(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    public async Task A_passkey_preference_controls_the_challenge_except_for_admin_scope(bool preference, bool admin, bool required)
    {
        using var fixture = new SignInPolicyFixture(admin);
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        await fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = fixture.User.Id,
            PasskeyRequiresSecondFactor = preference,
            Passkeys = { new PasskeyCredential { Id = "key" } },
        });

        var (status, body) = await fixture.SignInAsync();
        Assert.Equal(required ? 401 : 200, status);
        using var result = JsonDocument.Parse(body);
        if (required)
        {
            Assert.True(result.RootElement.GetProperty("TwoFactorRequired").GetBoolean());
            Assert.Contains(result.RootElement.GetProperty("Methods").EnumerateArray(), method => method.GetString() == "passkey");
        }
        else
        {
            Assert.Equal(SignInPolicyFixture.Token, result.RootElement.GetProperty("AccessToken").GetString());
        }

        await fixture.ProcessSessionAsync();
        Assert.Equal(required, fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
        Assert.Equal(required ? 403 : 200, await fixture.UseTokenAsync());
    }

    [Theory]
    [InlineData(true, null)]
    [InlineData(true, "not-a-trusted-credential")]
    [InlineData(false, null)]
    [InlineData(false, "not-a-trusted-credential")]
    public async Task Context_alone_leaves_restored_token_unverified(bool lan, string? credential)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.LanBypassEnabled = lan;
        fixture.Config.LanBypassCidrs = ["203.0.113.10/32"];
        fixture.Config.BareDeviceIdBypassEnabled = !lan;
        if (!lan)
        {
            await fixture.Store.MutateAsync(fixture.User.Id, u => u.PairedDevices.Add(
                new PairedDevice { DeviceId = SignInPolicyFixture.DeviceId }));
        }

        await fixture.ProcessSessionAsync(SignInPolicyFixture.Token, credential);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.False(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.False(fixture.Challenges.ConsumeTokenApproval(SignInPolicyFixture.Token, fixture.User.Id, SignInPolicyFixture.DeviceId));
        Assert.Empty(await fixture.Store.GetAuditLogAsync());
        Assert.Null(fixture.Observer.LastObservedAt);
        var data = await fixture.Store.GetUserDataAsync(fixture.User.Id);
        Assert.Empty(data.RegisteredDeviceIds);
        Assert.All(data.PairedDevices, p => Assert.Equal(string.Empty, p.LastIp));
    }

    [Fact]
    public async Task Existing_network_bypass_works_for_an_account_with_a_password()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.User.Password = "stored";
        fixture.Config.LanBypassEnabled = true;
        fixture.Config.LanBypassCidrs = ["203.0.113.10/32"];
        await fixture.ProcessSessionAsync(SignInPolicyFixture.Token);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.True(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.Equal("lan", Assert.Single(await fixture.Store.GetAuditLogAsync()).Method);
    }

    [Fact]
    public async Task Gate_off_does_not_resolve_an_optional_account()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.BlockEmptyPasswordLogin = false;
        await fixture.ProcessSessionAsync();
        Assert.Equal(403, await fixture.UseTokenAsync());
        fixture.Users.DidNotReceive().GetUserById(fixture.User.Id);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Unknown_role_alone_retains_admin_enforcement(bool throws)
    {
        using var fixture = new SignInPolicyFixture();
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        fixture.Users.GetUserById(fixture.User.Id).Returns(_ => throws ? throw new InvalidOperationException() : null);
        await fixture.ProcessSessionAsync();
        Assert.Equal(403, await fixture.UseTokenAsync());
    }

    [Fact]
    public async Task Legacy_all_user_enforcement_does_not_depend_on_a_role_lookup()
    {
        using var fixture = new SignInPolicyFixture();
        fixture.Config.RequireForAllUsers = true;
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        fixture.Users.GetUserById(fixture.User.Id).Returns(_ => throw new InvalidOperationException("Role lookup unavailable."));
        await fixture.ProcessSessionAsync();
        Assert.True(fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
    }

    [Theory]
    [InlineData(false, 200)]
    [InlineData(true, 401)]
    public async Task Only_a_verified_authenticator_app_triggers_an_optional_challenge(bool verified, int expected)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = fixture.User.Id,
            TotpEnabled = true,
            TotpVerified = verified,
            PasskeyRequiresSecondFactor = false,
        });
        Assert.Equal(expected, (await fixture.SignInAsync()).Status);
        await fixture.ProcessSessionAsync();
        Assert.Equal(verified, fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
    }

    [Fact]
    public async Task Restoring_a_token_without_proof_does_not_verify_it_and_a_new_password_restores_the_challenge()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        await fixture.ProcessSessionAsync(SignInPolicyFixture.Token);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.False(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.Empty(await fixture.Store.GetAuditLogAsync());
        Assert.Null(fixture.Observer.LastObservedAt);

        const string fresh = "fresh-unverified-token";
        fixture.User.Password = "stored-value";
        fixture.SetSessionToken(fresh);
        await fixture.ProcessSessionAsync(fresh);
        Assert.Equal(403, await fixture.UseTokenAsync(fresh));
        Assert.False(fixture.Challenges.IsTokenVerified(fresh));
    }

    [Theory]
    [InlineData("scope", 0)]
    [InlineData("authenticator", 0)]
    [InlineData("recovery", 1)]
    public async Task An_independent_requirement_still_blocks_an_eligible_session(string reason, int expectedLookups)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        if (reason == "scope") fixture.Config.EnforcementScope = EnforcementScope.All;
        await fixture.Store.MutateAsync(fixture.User.Id, data =>
        {
            data.TotpEnabled = data.TotpVerified = reason == "authenticator";
            data.ForceRecoveryOnNextLogin = reason == "recovery";
        });

        await fixture.ProcessSessionAsync();
        Assert.Equal(403, await fixture.UseTokenAsync());
        fixture.Users.Received(expectedLookups).GetUserById(fixture.User.Id);
    }

    [Theory]
    [InlineData(EnforcementScope.Admins, true)]
    [InlineData(EnforcementScope.Admins, false)]
    [InlineData(EnforcementScope.Optional, true)]
    [InlineData(EnforcementScope.Optional, false)]
    public async Task A_missing_user_or_failed_lookup_keeps_the_challenge(EnforcementScope scope, bool throws)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.EnforcementScope = scope;
        fixture.Users.GetUserById(fixture.User.Id).Returns(_ => throws ? throw new InvalidOperationException() : null);
        await fixture.ProcessSessionAsync();
        Assert.Equal(403, await fixture.UseTokenAsync());
        fixture.Users.Received(1).GetUserById(fixture.User.Id);
    }

    [Fact]
    public async Task Admin_scope_reuses_the_role_lookup_for_an_excluded_user()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        await fixture.ProcessSessionAsync();
        Assert.Equal(200, await fixture.UseTokenAsync());
        fixture.Users.Received(1).GetUserById(fixture.User.Id);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("unrecognized-device-token")]
    public async Task A_restored_token_on_a_known_device_does_not_gain_verification_without_proof(string? submittedToken)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.BareDeviceIdBypassEnabled = true;
        await fixture.Store.MutateAsync(fixture.User.Id, data => data.RegisteredDeviceIds.Add(SignInPolicyFixture.DeviceId));
        await fixture.ProcessSessionAsync(SignInPolicyFixture.Token, submittedToken);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.False(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.Empty(await fixture.Store.GetAuditLogAsync());
    }

    [Fact]
    public async Task A_current_trusted_device_token_still_verifies_and_observes_the_session()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        var (token, device) = new DeviceTokenService().CreateDeviceToken(SignInPolicyFixture.DeviceId, "Browser");
        await fixture.Store.MutateAsync(fixture.User.Id, data => data.TrustedDevices.Add(device));
        await fixture.ProcessSessionAsync(SignInPolicyFixture.Token, token);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.True(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.NotNull(fixture.Observer.LastObservedAt);
        Assert.Equal("trusted_device", Assert.Single(await fixture.Store.GetAuditLogAsync()).Method);
    }

    [Fact]
    public async Task An_existing_verified_token_keeps_its_reconnect_approval()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Challenges.MarkTokenVerified(SignInPolicyFixture.Token);
        await fixture.ProcessSessionAsync(SignInPolicyFixture.Token);
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.True(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.Equal("reconnect", Assert.Single(await fixture.Store.GetAuditLogAsync()).Method);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Quick_connect_pairs_and_observes_only_an_approved_sign_in(bool approval, bool remember)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Config.PairDeviceOnSecondScreenApproval = remember;
        const string approver = "approver-token";
        if (approval) fixture.Challenges.MarkTokenVerified(approver);
        Assert.Equal(200, await fixture.UseTokenAsync(approver, "/QuickConnect/Authorize"));

        await fixture.ProcessSessionAsync();
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.Equal(approval, fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.Equal(approval, fixture.Observer.LastObservedAt.HasValue);
        Assert.False(fixture.Challenges.ConsumeQuickConnectPending(fixture.User.Id));
        var data = await fixture.Store.GetUserDataAsync(fixture.User.Id);
        Assert.Equal(approval && remember, data.PairedDevices.Any(d => d.DeviceId == SignInPolicyFixture.DeviceId));
        var audit = await fixture.Store.GetAuditLogAsync();
        Assert.Equal(approval ? 1 : 0, audit.Count(e => e.Method == "quickconnect" && e.Result == AuditResult.Bypassed));
        Assert.Equal(approval && remember ? 1 : 0, audit.Count(e => e.Method == "device_paired_quickconnect"));
        if (!approval) Assert.Empty(audit);
    }

    [Theory]
    [InlineData(false, "app_password")]
    [InlineData(true, "totp")]
    public async Task An_app_password_allowance_is_consumed_even_if_the_device_was_preverified(bool preverified, string method)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        fixture.Challenges.MarkAppPasswordPending(fixture.User.Id);
        if (preverified) fixture.Challenges.MarkDevicePreVerified(fixture.User.Id, SignInPolicyFixture.DeviceId);
        await fixture.ProcessSessionAsync();
        Assert.Equal(200, await fixture.UseTokenAsync());
        Assert.True(fixture.Challenges.IsTokenVerified(SignInPolicyFixture.Token));
        Assert.False(fixture.Challenges.ConsumeAppPasswordPending(fixture.User.Id));
        Assert.NotNull(fixture.Observer.LastObservedAt);
        Assert.Equal(method, Assert.Single(await fixture.Store.GetAuditLogAsync()).Method);
    }

    [Fact]
    public async Task An_inactive_preference_keeps_the_original_early_return()
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.EnrollPasswordlessAsync();
        await fixture.Store.MutateAsync(fixture.User.Id, data => data.PasskeyRequiresSecondFactor = false);
        fixture.Challenges.MarkTokenVerified("approver-token");
        Assert.Equal(200, await fixture.UseTokenAsync("approver-token", "/QuickConnect/Authorize"));
        await fixture.ProcessSessionAsync();
        Assert.Equal(200, await fixture.UseTokenAsync());
        fixture.Users.DidNotReceive().GetUserById(fixture.User.Id);
        Assert.True(fixture.Challenges.ConsumeQuickConnectPending(fixture.User.Id));
        Assert.Null(fixture.Observer.LastObservedAt);
        Assert.Empty(await fixture.Store.GetAuditLogAsync());
    }
}

internal sealed class SignInPolicyFixture : IDisposable
{
    internal const string Token = "session-token";
    internal const string DeviceId = "browser-device";
    private readonly Plugin? _previous = Plugin.Instance;
    private readonly Plugin _plugin;
    private readonly HttpClient _http = new();
    private readonly GeoIpService _geo = new(NullLogger<GeoIpService>.Instance);
    internal SignInObserver Observer { get; }
    internal IpBanService Bans { get; }
    private readonly PendingPairingService _pending = new(NullLogger<PendingPairingService>.Instance);
    internal IApplicationHost Host { get; } = Substitute.For<IApplicationHost>();
    internal OidcLoginTokenStore Bridges { get; } = new();
    internal User User { get; } = new("local-user", "provider", "reset");
    internal IUserManager Users { get; } = Substitute.For<IUserManager>();
    internal ISessionManager Sessions { get; } = Substitute.For<ISessionManager>();
    internal IDeviceManager Devices { get; } = Substitute.For<IDeviceManager>();
    internal UserTwoFactorStore Store { get; }
    internal ChallengeStore Challenges { get; } = new();
    internal PluginConfiguration Config => _plugin.Configuration;

    internal SignInPolicyFixture(bool admin = false)
    {
        var paths = TestApplicationPaths.Create();
        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        Host.Resolve<IUserManager>().Returns(Users);
        Host.GetExportTypes<IAuthenticationProvider>().Returns(
            new[] { typeof(TwoFactorAuthProvider), HostProviderIdentityFixture.PasswordProvider });
        _plugin = new Plugin(paths, xml, Host, NullLogger<Plugin>.Instance);
        Config.Enabled = true;
        Config.RequireForAllUsers = false;
        Config.EnforcementScope = EnforcementScope.Optional;
        Config.EmailOtpEnabled = false;
        Config.LanBypassEnabled = false;
        Config.IpBanEnabled = false;
        Config.HibpEnabled = false;
        Config.SuspiciousLoginEnabled = false;
        Config.ImpossibleTravelEnabled = false;
        if (admin) User.SetPermission(PermissionKind.IsAdministrator, true);
        Users.GetUserById(User.Id).Returns(User);
        Users.GetUserByName(User.Username).Returns(User);
        var services = Substitute.For<IServiceProvider>();
        services.GetService(typeof(IUserManager)).Returns(Users);
        Store = new UserTwoFactorStore(paths, services);
        Bans = new IpBanService(paths, NullLogger<IpBanService>.Instance);
        var notifications = new NotificationService(NullLogger<NotificationService>.Instance);
        Observer = new SignInObserver(
            new SuspiciousLoginDetector(Store, _geo, notifications, NullLogger<SuspiciousLoginDetector>.Instance),
            new ImpossibleTravelDetector(Store, notifications, NullLogger<ImpossibleTravelDetector>.Instance),
            NullLogger<SignInObserver>.Instance);
        SetSessionToken(Token);
    }

    internal Task EnrollPasswordlessAsync()
    {
        Config.BlockEmptyPasswordLogin = true;
        User.AuthenticationProviderId = SignInProviderRestore.PluginProviderId;
        return Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = User.Id,
            PasskeyRequiresSecondFactor = true,
            Passkeys = { new PasskeyCredential { Id = "key" } },
        });
    }

    internal void SetSessionToken(string token)
    {
        Devices.GetDevices(Arg.Any<DeviceQuery>()).Returns(new QueryResult<Device>
        {
            Items = new[] { new Device(User.Id, "Web", "1.0", "Browser", DeviceId) { AccessToken = token, DateLastActivity = DateTime.UtcNow } },
        });
    }

    internal Task<ProviderAuthenticationResult> AuthenticateAsync(HttpContext context, string password, string? username = null)
    {
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var provider = new TwoFactorAuthProvider(Host, Store, Challenges, new BypassEvaluator(NullLogger<BypassEvaluator>.Instance),
            new NotificationService(NullLogger<NotificationService>.Instance), new AppPasswordService(), _pending, new RateLimiter(),
            Bridges, Bans, new IpAllowlistService(Store, NullLogger<IpAllowlistService>.Instance), accessor, NullLogger<TwoFactorAuthProvider>.Instance);
        return provider.Authenticate(username ?? User.Username, password);
    }

    internal async Task<(int Status, string Body)> SignInAsync(
        string path = "/Users/AuthenticateByName", string password = "sample-secret", Func<HttpContext, Task>? authenticate = null,
        object? responsePolicy = null, bool camelCase = false, object? sessionInfo = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = path;
        using var services = new ServiceCollection().AddSingleton(Users).BuildServiceProvider();
        context.RequestServices = services;
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10");
        context.Request.Headers["X-Emby-Device-Id"] = DeviceId;
        context.Request.ContentType = "application/json";
        using var submitted = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new { Username = User.Username, Pw = password }));
        context.Request.Body = submitted;
        context.Request.ContentLength = submitted.Length;
        using var response = new MemoryStream();
        context.Response.Body = response;
        var middleware = new TwoFactorEnforcementMiddleware(
            async ctx =>
            {
                if (authenticate is not null) await authenticate(ctx);
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    AccessToken = Token,
                    SessionInfo = sessionInfo ?? new { Id = "session", DeviceId },
                    User = new { Id = User.Id.ToString("N"), Name = User.Username, Policy = responsePolicy ?? new { IsAdministrator = User.HasPermission(PermissionKind.IsAdministrator) } },
                }, camelCase ? JsonSerializerOptions.Web : JsonSerializerOptions.Default));
            }, Store, Challenges, new BypassEvaluator(NullLogger<BypassEvaluator>.Instance), new AppPasswordService(), _pending,
            new RateLimiter(), Bans, new IpAllowlistService(Store, NullLogger<IpAllowlistService>.Instance),
            new HibpService(_http, NullLogger<HibpService>.Instance), AppSignInCodesForTests.Build(TestApplicationPaths.Create(), Store, Users, Substitute.For<IApplicationHost>(), Challenges, () => Config),
            NullLogger<TwoFactorEnforcementMiddleware>.Instance);
        await middleware.InvokeAsync(context);
        return (context.Response.StatusCode, Encoding.UTF8.GetString(response.ToArray()));
    }

    internal async Task ProcessSessionAsync(string? requestToken = null, string? trustedDeviceToken = null)
    {
        var handler = new AuthenticationEventHandler(Sessions, Store, new BypassEvaluator(NullLogger<BypassEvaluator>.Instance),
            Challenges, new NotificationService(NullLogger<NotificationService>.Instance), _pending, Devices, Users,
            new HttpContextAccessor(), Observer, NullLogger<AuthenticationEventHandler>.Instance);
        // Await the event's real async body so assertions cannot race its Task.Run hand-off.
        var process = typeof(AuthenticationEventHandler).GetMethod("HandleSessionAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var task = (Task)process.Invoke(handler, new object?[]
        {
            new SessionInfo(Sessions, NullLogger.Instance) { Id = "session", UserId = User.Id, UserName = User.Username, DeviceId = DeviceId, DeviceName = "Browser", RemoteEndPoint = "203.0.113.10" },
            null, trustedDeviceToken, requestToken, requestToken is null ? null : DeviceId, Guid.Empty, CodeAfterPasswordMiddleware.AuditMethod,
        })!;
        await task;
    }

    internal async Task<int> UseTokenAsync(string token = Token, string path = "/Items")
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Headers["X-Emby-Token"] = token;
        using var response = new MemoryStream();
        context.Response.Body = response;
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("Jellyfin-UserId", User.Id.ToString()), new Claim("Jellyfin-Token", token) }, "test"));
        var auth = Substitute.For<IAuthenticationService>();
        auth.AuthenticateAsync(Arg.Any<HttpContext>(), "CustomAuthentication")
            .Returns(AuthenticateResult.Success(new AuthenticationTicket(principal, "CustomAuthentication")));
        using var services = new ServiceCollection().AddSingleton(auth).BuildServiceProvider();
        context.RequestServices = services;
        var blocker = new RequestBlockerMiddleware(_ => Task.CompletedTask, Challenges, NullLogger<RequestBlockerMiddleware>.Instance);
        await blocker.InvokeAsync(context);
        return context.Response.StatusCode;
    }

    public void Dispose()
    {
        Bridges.Dispose();
        _geo.Dispose();
        _http.Dispose();
        Bans.Dispose();
        _pending.Dispose();
        Challenges.Dispose();
        Store.Dispose();
        typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
    }
}

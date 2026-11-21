using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class SignInChallengePolicyTests
{
    [Fact]
    public void An_explicit_opt_out_survives_json_serialization()
    {
        var data = JsonSerializer.Deserialize<UserTwoFactorData>("{\"PasskeyRequiresSecondFactor\":false}");
        using var saved = JsonDocument.Parse(JsonSerializer.Serialize(data));
        Assert.False(saved.RootElement.GetProperty("PasskeyRequiresSecondFactor").GetBoolean());
    }

    [Fact]
    public void A_legacy_record_requires_the_second_factor_by_default()
    {
        var data = JsonSerializer.Deserialize<UserTwoFactorData>("{}");
        Assert.True(data!.PasskeyRequiresSecondFactor);
        Assert.True(new UserTwoFactorData().PasskeyRequiresSecondFactor);
    }

    [Fact]
    public async Task Opt_out_survives_store_copies_targeted_updates_and_reload()
    {
        var paths = TestApplicationPaths.Create();
        var id = Guid.NewGuid();
        using (var store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>()))
        {
            await store.SaveUserDataAsync(new UserTwoFactorData { UserId = id, PasskeyRequiresSecondFactor = false });
            var copy = await store.GetUserDataAsync(id);
            Assert.False(copy.PasskeyRequiresSecondFactor);
            copy.PasskeyRequiresSecondFactor = true;
            await store.MutateAsync(id, data => UserDataUpdates.RaiseReplayFloor(data, 123));
            Assert.False((await store.GetUserDataAsync(id)).PasskeyRequiresSecondFactor);
        }

        using var restarted = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        var restored = await restarted.GetUserDataAsync(id);
        Assert.False(restored.PasskeyRequiresSecondFactor);
        Assert.Equal(123, restored.LastUsedTotpStep);
    }

    [Fact]
    public void An_unestablished_password_capability_keeps_the_passkey_challenge()
    {
        var config = new PluginConfiguration { EnforcementScope = EnforcementScope.Optional, RequireForAllUsers = false };
        var data = new UserTwoFactorData { Passkeys = { new PasskeyCredential() }, PasskeyRequiresSecondFactor = true };

        Assert.Equal("passkey", SignInChallengePolicy.GetReason(data, config, isAdmin: false, accountPasswordSignInUnavailable: false));
        Assert.True(SignInChallengePolicy.RequiresChallenge(data, config, isAdmin: false, accountPasswordSignInUnavailable: false));
    }

    [Fact]
    public void A_disabled_authenticator_with_a_stored_verification_does_not_require_a_challenge()
    {
        var config = new PluginConfiguration { EnforcementScope = EnforcementScope.Optional, RequireForAllUsers = false };
        var data = new UserTwoFactorData { TotpEnabled = false, TotpVerified = true };

        Assert.Equal("none", SignInChallengePolicy.GetReason(data, config, isAdmin: false, accountPasswordSignInUnavailable: true));
        Assert.False(SignInChallengePolicy.RequiresChallenge(data, config, isAdmin: false, accountPasswordSignInUnavailable: true));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_disabled_passkey_cannot_require_a_challenge_for_a_passwordless_account(bool recovery)
    {
        var config = new PluginConfiguration { EnforcementScope = EnforcementScope.Optional, PasskeysEnabled = false };
        var data = new UserTwoFactorData
        {
            Passkeys = { new PasskeyCredential() },
            PasskeyRequiresSecondFactor = true,
            ForceRecoveryOnNextLogin = recovery,
        };

        Assert.Equal("none", SignInChallengePolicy.GetReason(data, config, isAdmin: false, accountPasswordSignInUnavailable: true));
        Assert.False(SignInChallengePolicy.RequiresChallenge(data, config, isAdmin: false, accountPasswordSignInUnavailable: true));
        Assert.True(data.PasskeyRequiresSecondFactor);
    }

    public static IEnumerable<object[]> Matrix()
    {
        foreach (var scope in Enum.GetValues<EnforcementScope>())
        foreach (var admin in new[] { false, true })
        foreach (var legacy in new[] { false, true })
        foreach (var totp in new[] { "off", "unverified", "verified" })
        foreach (var passkey in new[] { false, true })
        foreach (var preference in new[] { false, true })
        foreach (var unavailable in new[] { false, true })
        foreach (var recovery in new[] { false, true })
        {
            string reason = (passkey, preference, unavailable, recovery) switch
            {
                (true, true, false, _) => "passkey",
                (true, true, true, true) => "recovery",
                _ => "none",
            };
            if (totp == "verified") reason = "authenticator";
            if (legacy || scope == EnforcementScope.All || (scope == EnforcementScope.Admins && admin)) reason = "scope";
            yield return new object[] { scope, admin, legacy, totp, passkey, preference, unavailable, recovery, reason };
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void The_policy_honors_scope_authenticator_passkey_and_emergency_recovery(
        EnforcementScope scope, bool admin, bool legacy, string totp, bool passkey,
        bool preference, bool unavailable, bool recovery, string reason)
    {
        var config = new PluginConfiguration { EnforcementScope = scope, RequireForAllUsers = legacy };
        var data = new UserTwoFactorData
        {
            TotpEnabled = totp != "off",
            TotpVerified = totp == "verified",
            PasskeyRequiresSecondFactor = preference,
            ForceRecoveryOnNextLogin = recovery,
        };
        if (passkey) data.Passkeys.Add(new PasskeyCredential());

        Assert.Equal(reason, SignInChallengePolicy.GetReason(data, config, admin, unavailable));
        Assert.Equal(reason != "none", SignInChallengePolicy.RequiresChallenge(data, config, admin, unavailable));
        Assert.Equal(preference, data.PasskeyRequiresSecondFactor);
    }
}

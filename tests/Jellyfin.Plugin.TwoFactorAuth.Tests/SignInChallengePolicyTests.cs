using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using NSubstitute;
using Jellyfin.Plugin.TwoFactorAuth.Models;
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

    public static IEnumerable<object[]> Matrix()
    {
        foreach (var scope in Enum.GetValues<EnforcementScope>())
        foreach (var admin in new[] { false, true })
        foreach (var legacy in new[] { false, true })
        foreach (var factor in new[] { "none", "passkey", "verified", "unverified", "both" })
        foreach (var preference in new[] { false, true })
        {
            var reason = legacy || scope == EnforcementScope.All || (scope == EnforcementScope.Admins && admin)
                ? "scope"
                : factor is "verified" or "both"
                    ? "authenticator"
                    : factor == "passkey" && preference ? "passkey" : "none";
            yield return new object[] { scope, admin, legacy, factor, preference, reason };
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void The_policy_honors_scope_verified_totp_and_the_preference(
        EnforcementScope scope, bool admin, bool legacy, string factor, bool preference, string reason)
    {
        var config = new PluginConfiguration { EnforcementScope = scope, RequireForAllUsers = legacy };
        var data = new UserTwoFactorData
        {
            TotpEnabled = factor is "verified" or "unverified" or "both",
            TotpVerified = factor is "verified" or "both",
            PasskeyRequiresSecondFactor = preference,
        };
        if (factor is "passkey" or "both") data.Passkeys.Add(new PasskeyCredential());

        Assert.Equal(reason, SignInChallengePolicy.GetReason(data, config, admin));
        Assert.Equal(reason != "none", SignInChallengePolicy.RequiresChallenge(data, config, admin));
    }
}

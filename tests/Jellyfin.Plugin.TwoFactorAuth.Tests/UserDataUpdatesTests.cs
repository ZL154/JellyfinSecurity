using System;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// The sign-in paths read the user's record, changed a field on that copy and
// saved the whole copy back, so whatever another request changed in between
// was written over. These pin the targeted updates that replace those saves.
public class UserDataUpdatesTests
{
    private static readonly DateTime Now = new(2026, 10, 10, 4, 0, 0, DateTimeKind.Utc);

    private static UserTwoFactorData WithRecoveryCodes(params string[] hashes) => new()
    {
        UserId = Guid.NewGuid(),
        RecoveryCodes = hashes.Select(h => new RecoveryCode { Hash = h }).ToList(),
    };

    private static TrustedDevice Trusted(string id, DateTime lastUsed) => new()
    {
        Id = id,
        DeviceId = "device-" + id,
        LastUsedAt = lastUsed,
    };

    [Fact]
    public void A_recovery_code_is_spent_once()
    {
        var data = WithRecoveryCodes("hash-a", "hash-b");

        Assert.True(UserDataUpdates.TryConsumeRecoveryCode(data, "hash-a", Now));
        Assert.False(UserDataUpdates.TryConsumeRecoveryCode(data, "hash-a", Now));

        Assert.True(data.RecoveryCodes[0].Used);
        Assert.Equal(Now, data.RecoveryCodes[0].UsedAt);
        Assert.False(data.RecoveryCodes[1].Used);
    }

    [Theory]
    [InlineData("hash-gone")]
    [InlineData("")]
    [InlineData(null)]
    public void A_recovery_code_the_record_does_not_hold_is_not_spent(string? hash)
    {
        // The codes were regenerated since the request read the record.
        var data = WithRecoveryCodes("hash-a");

        Assert.False(UserDataUpdates.TryConsumeRecoveryCode(data, hash, Now));
        Assert.False(data.RecoveryCodes[0].Used);
    }

    [Fact]
    public void A_secret_upgrade_lands_only_on_the_secret_it_was_made_from()
    {
        var data = new UserTwoFactorData { EncryptedTotpSecret = "v1-ciphertext" };
        UserDataUpdates.ApplySecretUpgrade(data, "v1-ciphertext", "v2:ciphertext");
        Assert.Equal("v2:ciphertext", data.EncryptedTotpSecret);

        // Replaced (a new enrolment) or wiped (a disable) in the meantime.
        var replaced = new UserTwoFactorData { EncryptedTotpSecret = "v2:another-secret" };
        UserDataUpdates.ApplySecretUpgrade(replaced, "v1-ciphertext", "v2:ciphertext");
        Assert.Equal("v2:another-secret", replaced.EncryptedTotpSecret);

        var wiped = new UserTwoFactorData { EncryptedTotpSecret = null };
        UserDataUpdates.ApplySecretUpgrade(wiped, "v1-ciphertext", "v2:ciphertext");
        Assert.Null(wiped.EncryptedTotpSecret);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void An_empty_upgrade_never_replaces_a_secret(string? upgraded)
    {
        var data = new UserTwoFactorData { EncryptedTotpSecret = "v1-ciphertext" };

        UserDataUpdates.ApplySecretUpgrade(data, "v1-ciphertext", upgraded);

        Assert.Equal("v1-ciphertext", data.EncryptedTotpSecret);
    }

    [Fact]
    public void The_replay_floor_only_moves_up()
    {
        var data = new UserTwoFactorData { LastUsedTotpStep = 100 };

        UserDataUpdates.RaiseReplayFloor(data, 120);
        Assert.Equal(120, data.LastUsedTotpStep);

        UserDataUpdates.RaiseReplayFloor(data, 110);
        Assert.Equal(120, data.LastUsedTotpStep);
    }

    [Fact]
    public void Adding_a_trusted_device_beyond_the_cap_drops_the_least_recently_used()
    {
        var data = new UserTwoFactorData();
        for (var i = 0; i < UserDataUpdates.MaxTrustedDevices; i++)
        {
            data.TrustedDevices.Add(Trusted("old-" + i, Now.AddDays(-100 + i)));
        }

        UserDataUpdates.AddTrustedDevice(data, Trusted("new", Now));

        Assert.Equal(UserDataUpdates.MaxTrustedDevices, data.TrustedDevices.Count);
        Assert.Contains(data.TrustedDevices, d => d.Id == "new");
        Assert.DoesNotContain(data.TrustedDevices, d => d.Id == "old-0");
    }

    [Fact]
    public void Touching_a_trusted_device_needs_its_record()
    {
        var data = new UserTwoFactorData();
        data.TrustedDevices.Add(Trusted("kept", Now.AddDays(-1)));

        Assert.True(UserDataUpdates.TouchTrustedDevice(data, "kept", Now));
        Assert.Equal(Now, data.TrustedDevices[0].LastUsedAt);

        // Revoked while the request was running: nothing to touch, nothing re-created.
        Assert.False(UserDataUpdates.TouchTrustedDevice(data, "revoked", Now));
        Assert.Single(data.TrustedDevices);
    }

    [Fact]
    public void Removing_a_paired_device_returns_it_once()
    {
        var data = new UserTwoFactorData();
        data.PairedDevices.Add(new PairedDevice { Id = "tv", DeviceId = "lg-tv" });

        var removed = UserDataUpdates.RemovePairedDevice(data, "tv");

        Assert.NotNull(removed);
        Assert.Equal("lg-tv", removed!.DeviceId);
        Assert.Empty(data.PairedDevices);
        Assert.Null(UserDataUpdates.RemovePairedDevice(data, "tv"));
    }
}

// The same race, on the real store: a request reads the record, another
// request changes it, then the first one writes. Writing the whole copy back
// undoes the other change; a targeted update inside MutateAsync keeps it.
public class StaleCopyWriteTests
{
    private static UserTwoFactorStore NewStore()
        => new(TestApplicationPaths.Create(), Substitute.For<IServiceProvider>());

    [Fact]
    public async Task Saving_a_whole_copy_read_earlier_undoes_a_change_made_in_between()
    {
        using var store = NewStore();
        var userId = Guid.NewGuid();
        await store.MutateAsync(userId, ud => ud.LastUsedTotpStep = 100);

        var copy = await store.GetUserDataAsync(userId);
        await store.MutateAsync(userId, ud => ud.Language = "de");
        copy.LastUsedTotpStep = 120;
        await store.SaveUserDataAsync(copy);

        var after = await store.GetUserDataAsync(userId);
        Assert.Equal(120, after.LastUsedTotpStep);
        Assert.Null(after.Language);
    }

    [Fact]
    public async Task A_targeted_update_keeps_a_change_made_in_between()
    {
        using var store = NewStore();
        var userId = Guid.NewGuid();
        await store.MutateAsync(userId, ud => ud.LastUsedTotpStep = 100);

        _ = await store.GetUserDataAsync(userId);
        await store.MutateAsync(userId, ud => ud.Language = "de");
        await store.MutateAsync(userId, ud => UserDataUpdates.RaiseReplayFloor(ud, 120));

        var after = await store.GetUserDataAsync(userId);
        Assert.Equal(120, after.LastUsedTotpStep);
        Assert.Equal("de", after.Language);
    }

    [Fact]
    public async Task A_device_revoked_during_a_sign_in_stays_revoked()
    {
        using var store = NewStore();
        var userId = Guid.NewGuid();
        await store.MutateAsync(userId, ud => ud.TrustedDevices.Add(new TrustedDevice { Id = "laptop", DeviceId = "laptop-1" }));

        // The sign-in has read the record and found the device...
        var copy = await store.GetUserDataAsync(userId);
        Assert.Single(copy.TrustedDevices);
        // ...the user revokes it...
        await store.MutateAsync(userId, ud => ud.TrustedDevices.RemoveAll(d => d.Id == "laptop"));
        // ...and the sign-in records the use.
        var touched = false;
        await store.MutateAsync(userId, ud => touched = UserDataUpdates.TouchTrustedDevice(ud, "laptop", DateTime.UtcNow));

        Assert.False(touched);
        Assert.Empty((await store.GetUserDataAsync(userId)).TrustedDevices);
    }
}

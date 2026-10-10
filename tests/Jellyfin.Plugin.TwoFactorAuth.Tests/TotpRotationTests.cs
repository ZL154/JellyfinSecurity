using System;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// Rotating the authenticator used to overwrite the secret and clear
// TotpVerified in one step, so until a confirmation that the Setup page never
// asked for, a password alone signed in. These pin that the active secret
// stays in charge until a code from the new one is confirmed, and that an
// abandoned or cancelled rotation changes nothing.
public class TotpRotationTests
{
    private static readonly DateTime Now = new(2026, 10, 9, 22, 0, 0, DateTimeKind.Utc);

    private static UserTwoFactorData Enrolled() => new()
    {
        UserId = Guid.NewGuid(),
        TotpEnabled = true,
        TotpVerified = true,
        EncryptedTotpSecret = "active-ciphertext",
        LastUsedTotpStep = 100,
    };

    [Fact]
    public void Starting_a_rotation_leaves_the_active_secret_in_charge()
    {
        var data = Enrolled();

        TotpRotation.Begin(data, "new-ciphertext", Now);

        Assert.Equal("active-ciphertext", data.EncryptedTotpSecret);
        Assert.True(data.TotpEnabled);
        Assert.True(data.TotpVerified);
        Assert.Equal("new-ciphertext", TotpRotation.PendingSecret(data, Now));
    }

    [Fact]
    public void An_abandoned_rotation_expires_without_touching_the_active_secret()
    {
        var data = Enrolled();
        TotpRotation.Begin(data, "new-ciphertext", Now);

        Assert.Equal("new-ciphertext", TotpRotation.PendingSecret(data, Now + TotpRotation.PendingLifetime));
        Assert.Null(TotpRotation.PendingSecret(data, Now + TotpRotation.PendingLifetime + TimeSpan.FromSeconds(1)));
        Assert.False(TotpRotation.TryComplete(data, "new-ciphertext", 200, Now + TimeSpan.FromMinutes(11)));
        Assert.Equal("active-ciphertext", data.EncryptedTotpSecret);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public void A_rotation_cannot_be_finished_once_totp_is_no_longer_active(bool enabled, bool verified)
    {
        // A disable, an admin reset or a fresh enrolment between the two steps.
        var data = Enrolled();
        TotpRotation.Begin(data, "new-ciphertext", Now);
        data.TotpEnabled = enabled;
        data.TotpVerified = verified;

        Assert.Null(TotpRotation.PendingSecret(data, Now));
        Assert.False(TotpRotation.TryComplete(data, "new-ciphertext", 200, Now));
    }

    [Fact]
    public void Confirming_makes_the_new_secret_active_and_raises_the_replay_floor()
    {
        var data = Enrolled();
        TotpRotation.Begin(data, "new-ciphertext", Now);

        Assert.True(TotpRotation.TryComplete(data, "new-ciphertext", 200, Now + TimeSpan.FromMinutes(1)));

        Assert.Equal("new-ciphertext", data.EncryptedTotpSecret);
        Assert.True(data.TotpEnabled);
        Assert.True(data.TotpVerified);
        Assert.Equal(200, data.LastUsedTotpStep);
        Assert.Null(data.PendingEncryptedTotpSecret);
        Assert.Null(data.PendingTotpSecretIssuedAt);
    }

    [Fact]
    public void Confirming_never_lowers_the_replay_floor()
    {
        var data = Enrolled();
        TotpRotation.Begin(data, "new-ciphertext", Now);

        Assert.True(TotpRotation.TryComplete(data, "new-ciphertext", 99, Now));

        Assert.Equal(100, data.LastUsedTotpStep);
    }

    [Fact]
    public void Only_the_latest_rotation_can_be_confirmed()
    {
        var data = Enrolled();
        TotpRotation.Begin(data, "first-ciphertext", Now);
        TotpRotation.Begin(data, "second-ciphertext", Now + TimeSpan.FromMinutes(1));

        Assert.False(TotpRotation.TryComplete(data, "first-ciphertext", 200, Now + TimeSpan.FromMinutes(2)));
        Assert.Equal("active-ciphertext", data.EncryptedTotpSecret);
        Assert.True(TotpRotation.TryComplete(data, "second-ciphertext", 200, Now + TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public void Clear_drops_the_pending_secret_and_keeps_the_active_one()
    {
        var data = Enrolled();
        TotpRotation.Begin(data, "new-ciphertext", Now);

        TotpRotation.Clear(data);

        Assert.Null(TotpRotation.PendingSecret(data, Now));
        Assert.Null(data.PendingTotpSecretIssuedAt);
        Assert.Equal("active-ciphertext", data.EncryptedTotpSecret);
    }

    [Fact]
    public void A_code_from_the_new_secret_in_the_rotation_window_is_not_taken_for_a_replay()
    {
        // The rotation request spends a code from the active secret, and the
        // replay cache tracks time steps, not secrets. Under the user's own
        // key, the first code from the new secret is refused whenever it falls
        // in that same 30 second window.
        var svc = new TotpService(TestApplicationPaths.Create(), Substitute.For<ILogger<TotpService>>());
        var userId = Guid.NewGuid();
        var active = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        var rotated = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        var at = DateTime.UtcNow;

        Assert.True(svc.ValidateCode(active, Code(active, at), userId.ToString("N"), persistedFloor: 0, out _));
        Assert.False(svc.ValidateCode(rotated, Code(rotated, at), userId.ToString("N"), persistedFloor: 0, out _));
        Assert.True(svc.ValidateCode(rotated, Code(rotated, at), TotpRotation.ReplayKey(userId), persistedFloor: 0, out _));
    }

    private static string Code(string base32Secret, DateTime at)
        => new Totp(Base32Encoding.ToBytes(base32Secret), step: 30, totpSize: 6).ComputeTotp(at);
}

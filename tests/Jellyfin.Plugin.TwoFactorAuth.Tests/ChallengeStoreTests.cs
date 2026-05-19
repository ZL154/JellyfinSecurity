using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Regression tests for v2.4 security fixes in ChallengeStore + ChallengeData.
/// </summary>
public class ChallengeStoreTests
{
    // ---- L2: atomic single-consume -----------------------------------------

    [Fact]
    public void TryConsume_returns_true_once_and_false_thereafter()
    {
        var data = new ChallengeData
        {
            Token = "any",
            UserId = Guid.NewGuid(),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        };

        Assert.True(data.TryConsume());
        Assert.False(data.TryConsume());
        Assert.False(data.TryConsume());
        Assert.True(data.IsConsumed);
    }

    [Fact]
    public async Task TryConsume_is_thread_safe_under_concurrent_callers()
    {
        // SEC v2.4 L2: previously two concurrent /Verify requests could both
        // pass the check-then-set guard and both succeed, minting two sessions
        // from one OTP code. TryConsume must succeed for exactly one caller
        // across N parallel attempts.
        for (var trial = 0; trial < 50; trial++)
        {
            var data = new ChallengeData
            {
                Token = "any",
                UserId = Guid.NewGuid(),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            };

            const int parallelism = 32;
            var tasks = new Task<bool>[parallelism];
            using var gate = new System.Threading.Barrier(parallelism);
            for (var i = 0; i < parallelism; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    gate.SignalAndWait();
                    return data.TryConsume();
                });
            }

            var results = await Task.WhenAll(tasks);
            var successCount = 0;
            foreach (var r in results) if (r) successCount++;
            Assert.Equal(1, successCount);
        }
    }

    [Fact]
    public void ConsumeChallenge_through_store_is_single_use()
    {
        using var store = new ChallengeStore();
        var c = store.CreateChallenge(
            Guid.NewGuid(),
            "alice",
            new List<string> { "totp" },
            "dev-1",
            "Living Room",
            "203.0.113.5");

        Assert.True(store.ConsumeChallenge(c.Token));
        Assert.False(store.ConsumeChallenge(c.Token));
        Assert.False(store.ConsumeChallenge(c.Token));
    }

    [Fact]
    public void ConsumeChallenge_rejects_expired()
    {
        using var store = new ChallengeStore();
        var c = store.CreateChallenge(
            Guid.NewGuid(),
            "alice",
            new List<string> { "totp" },
            "dev-1",
            "Living Room",
            "203.0.113.5");

        c.ExpiresAt = DateTime.UtcNow.AddSeconds(-1);
        Assert.False(store.ConsumeChallenge(c.Token));
    }

    [Fact]
    public void ConsumeChallenge_rejects_unknown_token()
    {
        using var store = new ChallengeStore();
        Assert.False(store.ConsumeChallenge("not-a-token"));
        Assert.False(store.ConsumeChallenge(string.Empty));
    }

    // ---- L7: deviceless / whitespace pre-verify guard ---------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData("   ")]
    public void MarkDevicePreVerified_ignores_empty_or_whitespace_deviceId(string? deviceId)
    {
        // SEC v2.4 L7: previously IsNullOrEmpty was used, so a single space or
        // tab deviceId would pass and grant a user-wide pre-verify bypass via
        // the "user:<id>" key.
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        store.MarkDevicePreVerified(userId, deviceId);

        Assert.False(store.IsDevicePreVerified(userId, deviceId));
        Assert.False(store.IsDevicePreVerified(userId, "device-1"));
    }

    [Fact]
    public void MarkDevicePreVerified_with_real_deviceId_records_correctly()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        store.MarkDevicePreVerified(userId, "device-real");

        Assert.True(store.IsDevicePreVerified(userId, "device-real"));
        Assert.False(store.IsDevicePreVerified(userId, "device-other"));
        Assert.False(store.IsDevicePreVerified(Guid.NewGuid(), "device-real"));
    }

    [Fact]
    public void ConsumeDevicePreVerified_is_single_use()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();
        store.MarkDevicePreVerified(userId, "device-1");

        Assert.True(store.IsDevicePreVerified(userId, "device-1"));
        store.ConsumeDevicePreVerified(userId, "device-1");
        Assert.False(store.IsDevicePreVerified(userId, "device-1"));
    }

    // ---- General correctness of challenge issuance ------------------------

    [Fact]
    public void CreateChallenge_generates_unique_tokens()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        var a = store.CreateChallenge(userId, "alice", new List<string> { "totp" }, "d1", "TV", "1.2.3.4");
        var b = store.CreateChallenge(userId, "alice", new List<string> { "totp" }, "d1", "TV", "1.2.3.4");

        Assert.NotEqual(a.Token, b.Token);
        Assert.False(string.IsNullOrEmpty(a.Token));
        Assert.DoesNotContain('=', a.Token);
        Assert.DoesNotContain('+', a.Token);
        Assert.DoesNotContain('/', a.Token);
    }

    [Fact]
    public void GetChallenge_returns_null_after_consumed()
    {
        using var store = new ChallengeStore();
        var c = store.CreateChallenge(Guid.NewGuid(), "alice", new List<string> { "totp" }, "d1", "TV", "1.2.3.4");

        Assert.NotNull(store.GetChallenge(c.Token));
        store.ConsumeChallenge(c.Token);
        Assert.Null(store.GetChallenge(c.Token));
    }

    // ---- Token / device blocking primitives -------------------------------

    [Fact]
    public void BlockToken_then_IsTokenBlocked_returns_true_until_unblocked()
    {
        using var store = new ChallengeStore();
        const string token = "abc123";

        Assert.False(store.IsTokenBlocked(token));
        store.BlockToken(token);
        Assert.True(store.IsTokenBlocked(token));
        store.UnblockToken(token);
        Assert.False(store.IsTokenBlocked(token));
    }

    [Fact]
    public void TryConsumePairToken_rejects_replay()
    {
        using var store = new ChallengeStore();
        Assert.True(store.TryConsumePairToken("sig-1"));
        Assert.False(store.TryConsumePairToken("sig-1"));
        Assert.True(store.TryConsumePairToken("sig-2"));
    }
}

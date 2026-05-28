using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class ChallengeStoreStepUpTests
{
    [Fact]
    public void StepUp_mark_then_verified_true()
    {
        using var store = new ChallengeStore();
        var user = Guid.NewGuid();
        Assert.False(store.IsStepUpVerified(user));
        store.MarkStepUpVerified(user);
        Assert.True(store.IsStepUpVerified(user));
    }

    [Fact]
    public void StepUp_is_scoped_per_user()
    {
        using var store = new ChallengeStore();
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        store.MarkStepUpVerified(a);
        Assert.True(store.IsStepUpVerified(a));
        Assert.False(store.IsStepUpVerified(b));
    }

    [Fact]
    public void StepUp_clear_removes_mark()
    {
        using var store = new ChallengeStore();
        var user = Guid.NewGuid();
        store.MarkStepUpVerified(user);
        store.ClearStepUp(user);
        Assert.False(store.IsStepUpVerified(user));
    }
}

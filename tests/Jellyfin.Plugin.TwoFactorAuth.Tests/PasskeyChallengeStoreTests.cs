using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class PasskeyChallengeStoreTests
{
    [Fact]
    public void Begin_returns_non_empty_url_safe_nonce()
    {
        using var store = new PasskeyChallengeStore();
        var nonce = store.Begin("{\"options\":\"json\"}", Guid.NewGuid());

        Assert.False(string.IsNullOrEmpty(nonce));
        Assert.DoesNotContain('+', nonce);
        Assert.DoesNotContain('/', nonce);
        Assert.DoesNotContain('=', nonce);
    }

    [Fact]
    public void Begin_produces_unique_nonces()
    {
        using var store = new PasskeyChallengeStore();
        var a = store.Begin("{}", Guid.NewGuid());
        var b = store.Begin("{}", Guid.NewGuid());
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Consume_returns_stored_options_and_user()
    {
        using var store = new PasskeyChallengeStore();
        var userId = Guid.NewGuid();
        const string json = "{\"challenge\":\"abc\"}";

        var nonce = store.Begin(json, userId);
        var (opts, returnedUser) = store.Consume(nonce);

        Assert.Equal(json, opts);
        Assert.Equal(userId, returnedUser);
    }

    [Fact]
    public void Consume_is_single_use()
    {
        using var store = new PasskeyChallengeStore();
        var nonce = store.Begin("{}", Guid.NewGuid());

        var first = store.Consume(nonce);
        Assert.NotNull(first.OptionsJson);

        var second = store.Consume(nonce);
        Assert.Null(second.OptionsJson);
        Assert.Null(second.UserId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unknown-nonce-value")]
    public void Consume_rejects_empty_or_unknown_nonce(string? nonce)
    {
        using var store = new PasskeyChallengeStore();
        var (opts, user) = store.Consume(nonce!);
        Assert.Null(opts);
        Assert.Null(user);
    }

    [Fact]
    public void Begin_accepts_null_user_for_assertion_ceremony()
    {
        // Passkey assertion (sign-in) doesn't know the user until the browser
        // submits the credential — userId is optional at Begin time.
        using var store = new PasskeyChallengeStore();
        var nonce = store.Begin("{}", null);
        var (opts, user) = store.Consume(nonce);
        Assert.Equal("{}", opts);
        Assert.Null(user);
    }

    [Fact]
    public void Dispose_does_not_throw_on_double_dispose()
    {
        var store = new PasskeyChallengeStore();
        store.Dispose();
        var ex = Record.Exception(() => store.Dispose());
        Assert.Null(ex);
    }
}

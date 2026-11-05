using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>The per-account lockout counts failed sign-ins: wrong passwords,
/// and wrong codes on the challenge. It also counted the challenge itself,
/// which only follows the right password, and a lockout that had run out left
/// its count behind, so the next failure locked the account again.</summary>
public sealed class SignInLockoutTests : IDisposable
{
    private readonly string _sandbox;
    private readonly UserTwoFactorStore _store;
    private readonly Guid _alice = Guid.NewGuid();

    public SignInLockoutTests()
    {
        _store = new UserTwoFactorStore(TestApplicationPaths.Create(out _sandbox), Substitute.For<IServiceProvider>());
    }

    public void Dispose()
    {
        _store.Dispose();
        Directory.Delete(_sandbox, recursive: true);
    }

    // ---- The count ----------------------------------------------------------

    [Fact]
    public async Task Five_failed_sign_ins_lock_the_account()
    {
        for (var i = 0; i < 5; i++)
        {
            Assert.False(await _store.IsLockedOutAsync(_alice));
            await _store.RecordFailedAttemptAsync(_alice);
        }

        Assert.True(await _store.IsLockedOutAsync(_alice));
    }

    [Fact]
    public async Task A_lockout_that_ran_out_starts_a_new_count()
    {
        await _store.MutateAsync(_alice, d =>
        {
            d.FailedAttemptCount = 5;
            d.LockoutEnd = DateTime.UtcNow.AddMinutes(-1);
        });
        Assert.False(await _store.IsLockedOutAsync(_alice));

        await _store.RecordFailedAttemptAsync(_alice);

        Assert.False(await _store.IsLockedOutAsync(_alice));
        var data = await _store.GetUserDataAsync(_alice);
        Assert.Equal(1, data.FailedAttemptCount);
        Assert.Null(data.LockoutEnd);
    }

    [Fact]
    public async Task A_failure_during_a_lockout_keeps_the_account_locked()
    {
        await _store.MutateAsync(_alice, d =>
        {
            d.FailedAttemptCount = 5;
            d.LockoutEnd = DateTime.UtcNow.AddMinutes(10);
        });

        await _store.RecordFailedAttemptAsync(_alice);

        Assert.True(await _store.IsLockedOutAsync(_alice));
        Assert.Equal(6, (await _store.GetUserDataAsync(_alice)).FailedAttemptCount);
    }

    // ---- What counts ----------------------------------------------------------

    private static DefaultHttpContext Answered(int status, bool challenge = false)
    {
        var context = new DefaultHttpContext();
        context.Response.StatusCode = status;
        if (challenge)
        {
            context.Items[TwoFactorEnforcementMiddleware.ChallengeIssuedItemKey] = true;
        }

        return context;
    }

    [Fact]
    public void A_refused_sign_in_counts_as_a_failure()
        => Assert.True(LockoutMessageMiddleware.IsFailedSignIn(Answered(StatusCodes.Status401Unauthorized)));

    [Fact]
    public void The_challenge_after_the_right_password_is_not_a_failure()
        => Assert.False(LockoutMessageMiddleware.IsFailedSignIn(Answered(StatusCodes.Status401Unauthorized, challenge: true)));

    [Theory]
    [InlineData(StatusCodes.Status200OK)]
    [InlineData(StatusCodes.Status403Forbidden)]
    [InlineData(StatusCodes.Status503ServiceUnavailable)]
    public void Only_a_refusal_is_a_failure(int status)
        => Assert.False(LockoutMessageMiddleware.IsFailedSignIn(Answered(status)));

    // ---- The wiring -------------------------------------------------------------

    [Fact]
    public void The_lockout_counts_a_401_only_through_IsFailedSignIn()
    {
        // Both middlewares need Plugin.Instance, so their wiring is pinned in
        // the source.
        var source = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/LockoutMessageMiddleware.cs");
        var invoke = source[source.IndexOf("public async Task InvokeAsync(HttpContext context)", StringComparison.Ordinal)..];

        Assert.Contains("else if (IsFailedSignIn(context))", invoke, StringComparison.Ordinal);
        Assert.DoesNotContain("status == StatusCodes.Status401Unauthorized", invoke, StringComparison.Ordinal);
    }

    [Fact]
    public void The_challenge_is_marked_before_it_is_answered()
    {
        const string Answer = "context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;";
        var source = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorEnforcementMiddleware.cs");

        var mark = source.IndexOf("context.Items[ChallengeIssuedItemKey] = true;", StringComparison.Ordinal);
        var answer = source.IndexOf(Answer, StringComparison.Ordinal);
        Assert.True(mark >= 0 && mark < answer);

        // The challenge is the only 401 this middleware writes; another one
        // would need its own answer to whether it counts.
        Assert.Equal(answer, source.LastIndexOf(Answer, StringComparison.Ordinal));
    }

    private static string SourceFile(string repoRelativePath)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, repoRelativePath);
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new FileNotFoundException(
            $"Could not find {repoRelativePath} walking up from {AppContext.BaseDirectory}");
    }
}

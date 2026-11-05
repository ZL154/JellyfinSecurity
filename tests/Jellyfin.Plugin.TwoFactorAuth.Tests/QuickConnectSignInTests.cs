using System.Text.RegularExpressions;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// #304: Quick Connect mints the device's access token inside the approver's
/// /QuickConnect/Authorize request, and the device fetches it afterwards with
/// /Users/AuthenticateWithQuickConnect. The SessionStarted handler judges the
/// session in the first request and the response middleware in the second, so
/// the token's state is the only thing that carries one verdict to the other.
/// The middleware cannot be built here without Plugin.Instance, so its wiring
/// is pinned in the source, as for the handler.
/// </summary>
public class QuickConnectSignInTests
{
    [Theory]
    [InlineData("/Users/AuthenticateWithQuickConnect", true)]
    [InlineData("/jellyfin/Users/AuthenticateWithQuickConnect", true)]
    [InlineData("/users/authenticatewithquickconnect/", true)]
    [InlineData("/Users/AuthenticateByName", false)]
    [InlineData("/Users/4974b86245bb4ae093ebc85484b74503/Authenticate", false)]
    [InlineData("/QuickConnect/Authorize", false)]
    [InlineData("/Users/AuthenticateWithQuickConnectAgain", false)]
    public void Only_the_request_that_fetches_a_Quick_Connect_token_is_a_Quick_Connect_sign_in(string path, bool quickConnect)
    {
        Assert.Equal(quickConnect, TwoFactorEnforcementMiddleware.IsQuickConnectSignIn(path));
    }

    [Fact]
    public void A_Quick_Connect_token_the_handler_let_through_is_handed_on()
    {
        // The handler's approval flag lasts 30 seconds and one read, and Jellyfin
        // keeps the Quick Connect secret for ten minutes. A device that fetched
        // its token later, or fetched it again, met the challenge for a token the
        // handler had already let through, and the challenge blocked that token.
        var approval = CallBlock(SourceFile(MiddlewarePath), "var approved = ");

        Assert.Matches(
            @"^var approved = \(quickConnect && _challengeStore\.IsTokenVerified\(authResult\.AccessToken\)\)\s*\|\|\s*await _challengeStore\s*\.WaitForApprovalAsync\(",
            approval);
    }

    [Theory]
    [InlineData("if (bypass.IsBypassed)")]
    [InlineData("if (paired is not null)")]
    public void A_bypass_on_the_devices_own_request_lifts_the_handlers_block(string branch)
    {
        // The report: with an API key approving, no verified session marks the
        // sign-in, and the handler, without the device's address in the
        // approving request, blocked the token. The device's own request then
        // matched the LAN bypass here, and the response carried a token every
        // later request was refused with.
        var middleware = SourceFile(MiddlewarePath);

        Assert.Matches(
            @"if \(quickConnect\)\s*\{\s*ReleaseQuickConnectToken\(authResult\.AccessToken, userGuid, deviceId\);\s*\}",
            Region(middleware, branch, "return;"));
    }

    [Fact]
    public void Releasing_a_Quick_Connect_token_does_what_the_handlers_own_bypass_does()
    {
        // The handler's bypass branch leaves the token verified and drops the
        // device from the pending pairings. Here the block comes off as well,
        // because the handler put it there.
        var release = Region(SourceFile(MiddlewarePath), "private void ReleaseQuickConnectToken(", "\n    }\n");

        Assert.Contains("_challengeStore.UnblockToken(token);", release, StringComparison.Ordinal);
        Assert.Contains("_challengeStore.MarkTokenVerified(token);", release, StringComparison.Ordinal);
        Assert.Contains("_pendingPairings.Remove(userId, deviceId);", release, StringComparison.Ordinal);
    }

    [Fact]
    public void Other_sign_ins_keep_the_handlers_block()
    {
        // On every other sign-in the handler judges the same request the
        // middleware answers, and its block stands when the two disagree (#273
        // aligned their inputs instead). Only the Quick Connect path releases.
        var middleware = SourceFile(MiddlewarePath);
        var calls = Regex.Matches(middleware, @"ReleaseQuickConnectToken\(authResult\.AccessToken");
        var guarded = Regex.Matches(
            middleware,
            @"if \(quickConnect\)\s*\{\s*ReleaseQuickConnectToken\(authResult\.AccessToken, userGuid, deviceId\);\s*\}");

        Assert.Equal(2, calls.Count);
        Assert.Equal(calls.Count, guarded.Count);
    }

    private const string MiddlewarePath = "src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorEnforcementMiddleware.cs";

    private static string Region(string source, string from, string to)
    {
        var start = source.IndexOf(from, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{from} should still be in the middleware");
        var end = source.IndexOf(to, start + from.Length, StringComparison.Ordinal);
        Assert.True(end > start, $"{to} should still follow {from}");
        return source[start..end];
    }

    private static string CallBlock(string source, string call)
    {
        var start = source.IndexOf(call, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{call} should still be in the middleware");
        var end = source.IndexOf(");", start, StringComparison.Ordinal);
        return source.Substring(start, end - start);
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

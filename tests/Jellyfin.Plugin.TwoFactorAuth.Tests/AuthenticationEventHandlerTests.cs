using System.Text.RegularExpressions;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class AuthenticationEventHandlerTests
{
    [Fact]
    public void SelectMostRecentAccessToken_uses_freshest_matching_device_record()
    {
        var now = DateTime.UtcNow;
        var candidates = new[]
        {
            (DeviceId: "living-room", AccessToken: "stale", DateLastActivity: now.AddHours(-2)),
            (DeviceId: "other", AccessToken: "wrong-device", DateLastActivity: now),
            (DeviceId: "living-room", AccessToken: "current", DateLastActivity: now.AddMinutes(-1)),
        };

        var selected = AuthenticationEventHandler.SelectMostRecentAccessToken(
            "living-room",
            candidates);

        Assert.Equal("current", selected);
    }

    [Fact]
    public void SelectMostRecentAccessToken_rejects_missing_or_blank_device_identity()
    {
        var candidates = new[]
        {
            (DeviceId: "device", AccessToken: "token", DateLastActivity: DateTime.UtcNow),
        };

        Assert.Null(AuthenticationEventHandler.SelectMostRecentAccessToken(null, candidates));
        Assert.Null(AuthenticationEventHandler.SelectMostRecentAccessToken(" ", candidates));
    }

    [Fact]
    public void Every_record_the_session_handler_writes_carries_the_resolved_address()
    {
        // #228: behind a trusted proxy the bypass is decided on the forwarded
        // address, but these records carried the proxy's own address, so a
        // LAN bypass granted on a forwarded (and possibly forged) address was
        // logged as coming from the proxy. The handler cannot be built here
        // without Plugin.Instance, so the wiring is pinned in the source.
        var handler = SourceFile(HandlerPath);

        var auditAddresses = Regex.Matches(handler, @"RemoteIp = [^\r\n]*");
        Assert.Equal(7, auditAddresses.Count);
        Assert.All(auditAddresses, m => Assert.Equal("RemoteIp = observedIp ?? string.Empty,", m.Value));

        Assert.Contains("p.LastIp = observedIp ?? string.Empty;", handler, StringComparison.Ordinal);
        Assert.Contains("info.UserName, observedIp, bypass.Reason);", handler, StringComparison.Ordinal);
        Assert.Contains("observedIp ?? \"unknown\",", handler, StringComparison.Ordinal);
        Assert.EndsWith("observedIp ?? string.Empty", CallBlock(handler, "_pendingPairings.Record("), StringComparison.Ordinal);

        var secondScreen = CallBlock(handler, "SecondScreenPairing.RecordAsync(");
        Assert.Contains("observedIp,", secondScreen, StringComparison.Ordinal);
        Assert.DoesNotContain("RemoteEndPoint", secondScreen, StringComparison.Ordinal);
    }

    [Fact]
    public void The_bypass_decision_still_gets_the_raw_peer_and_the_header()
    {
        // The evaluator walks X-Forwarded-For itself and refuses the LAN bypass
        // when the peer is a trusted proxy with no resolvable client. Handing it
        // the already-resolved address would resolve twice and defeat that guard.
        var decision = CallBlock(SourceFile(HandlerPath), "_bypassEvaluator.Evaluate(");

        Assert.Matches(@"^_bypassEvaluator\.Evaluate\(\s*info\.RemoteEndPoint,\s*forwardedFor,", decision);
    }

    [Fact]
    public void The_bypass_decision_gets_the_trusted_device_token()
    {
        // #273: the device token went in as null, so a trusted device could
        // never match here. The handler blocked the new access token while the
        // response middleware, which does read X-TwoFactor-Token, let the
        // sign-in through, and the client got a 200 whose token every later
        // request was refused with.
        var decision = CallBlock(SourceFile(HandlerPath), "_bypassEvaluator.Evaluate(");

        Assert.Matches(
            @"^_bypassEvaluator\.Evaluate\(\s*info\.RemoteEndPoint,\s*forwardedFor,\s*twoFactorToken,\s*info\.DeviceId,",
            decision);
    }

    [Fact]
    public void The_trusted_device_token_is_read_before_the_request_ends()
    {
        // HandleSessionAsync runs on Task.Run and can outlive the request, and
        // with it HttpContext; the X-Forwarded-For snapshot exists for the same
        // reason. Read there, the header would reach the evaluator as null, and
        // so would a snapshot the hand-off does not pass on.
        var handler = SourceFile(HandlerPath);
        var start = handler.IndexOf("private void OnSessionStarted(", StringComparison.Ordinal);
        Assert.True(start >= 0, "OnSessionStarted should still be in the handler");
        var handOff = handler.IndexOf("Task.Run(", start, StringComparison.Ordinal);
        Assert.True(handOff > start, "OnSessionStarted should still hand the work to Task.Run");
        var end = handler.IndexOf("private async Task HandleSessionAsync(", handOff, StringComparison.Ordinal);
        Assert.True(end > handOff, "HandleSessionAsync should still follow OnSessionStarted");

        Assert.Contains("Headers[\"X-TwoFactor-Token\"]", handler[start..handOff], StringComparison.Ordinal);
        Assert.Matches(@"HandleSessionAsync\(info, forwardedFor, twoFactorToken[,)]", handler[handOff..end]);
    }

    [Fact]
    public void The_session_token_is_the_one_the_request_carries_when_the_DeviceId_changed()
    {
        // A Jellyfin device record keeps the DeviceId its token was created
        // with, and some native clients send another one later (Jellyfin
        // Android TV 0.19.10 on a Fire TV did, in production). Looked up by the
        // session's DeviceId, the token in use was not found, so a reconnect of
        // a verified token could not be told from a new sign-in.
        var now = DateTime.UtcNow;
        var candidates = new[]
        {
            (DeviceId: "tv-auth-A", AccessToken: "tv-token", DateLastActivity: now),
            (DeviceId: "phone", AccessToken: "phone-token", DateLastActivity: now.AddMinutes(-5)),
        };

        Assert.Equal("tv-token", AuthenticationEventHandler.SelectSessionAccessToken("tv-token", "tv-session-B", "tv-session-B", candidates));
    }

    [Fact]
    public void A_sign_in_without_a_request_token_keeps_the_DeviceId_lookup()
    {
        // The token a sign-in mints is only in Jellyfin's device record: the
        // request carries none, so the newest record for the DeviceId wins.
        var now = DateTime.UtcNow;
        var candidates = new[]
        {
            (DeviceId: "tv", AccessToken: "old", DateLastActivity: now.AddDays(-3)),
            (DeviceId: "tv", AccessToken: "new", DateLastActivity: now),
        };

        Assert.Equal("new", AuthenticationEventHandler.SelectSessionAccessToken(null, null, "tv", candidates));
    }

    [Fact]
    public void A_request_token_the_users_devices_do_not_hold_is_not_judged()
    {
        // The handler approves, verifies or blocks only this user's device
        // tokens. Anything else (an API key, for one) leaves the lookup as it was.
        var candidates = new[] { (DeviceId: "tv", AccessToken: "mine", DateLastActivity: DateTime.UtcNow) };

        Assert.Equal("mine", AuthenticationEventHandler.SelectSessionAccessToken("not-a-device-token", "tv", "tv", candidates));
        Assert.Null(AuthenticationEventHandler.SelectSessionAccessToken("not-a-device-token", "other-device", "other-device", candidates));
    }

    [Fact]
    public void A_token_from_another_devices_request_is_not_the_sessions()
    {
        // Quick Connect opens the TV's session inside the phone's Authorize
        // request, so the token that request carries is the phone's. Taken as
        // the TV's, it was approved in place of the TV's new token and the TV
        // was challenged. Only a request from the session's own DeviceId names
        // the session's token.
        var now = DateTime.UtcNow;
        var candidates = new[]
        {
            (DeviceId: "phone", AccessToken: "phone-token", DateLastActivity: now.AddMinutes(-1)),
            (DeviceId: "tv2-auth", AccessToken: "tv2-token", DateLastActivity: now),
        };

        Assert.Equal("tv2-token", AuthenticationEventHandler.SelectSessionAccessToken("phone-token", "phone", "tv2-auth", candidates));
    }

    [Fact]
    public void A_percent_encoded_request_DeviceId_still_names_its_session()
    {
        // The session carries the DeviceId as Jellyfin decoded it from the
        // header, and clients may send it percent-encoded.
        var candidates = new[] { (DeviceId: "old-id", AccessToken: "web-token", DateLastActivity: DateTime.UtcNow) };

        Assert.Equal(
            "web-token",
            AuthenticationEventHandler.SelectSessionAccessToken("web-token", "TW96aWxsYQ%3D%3D", "TW96aWxsYQ==", candidates));
    }

    [Fact]
    public void The_request_token_is_snapshotted_except_on_sign_in_requests()
    {
        // Read while the request is alive, like the two headers above it. A
        // sign-in request carries no token, or an old one, so it keeps the
        // DeviceId lookup; and the token read is the one RequestBlockerMiddleware
        // reads, so the handler blocks exactly what the blocker will refuse.
        var handler = SourceFile(HandlerPath);
        var snapshot = Region(handler, "private void OnSessionStarted(", "Task.Run(");

        Assert.Contains("TwoFactorEnforcementMiddleware.IsAuthPath(", snapshot, StringComparison.Ordinal);
        Assert.Contains("RequestBlockerMiddleware.GetAccessToken(httpContext)", snapshot, StringComparison.Ordinal);
        Assert.Contains("TwoFactorAuthProvider.ResolveDeviceHeaderValue(", snapshot, StringComparison.Ordinal);
        Assert.Contains(
            "HandleSessionAsync(info, forwardedFor, twoFactorToken, requestToken, requestDeviceId)",
            Region(handler, "Task.Run(", "private async Task HandleSessionAsync("),
            StringComparison.Ordinal);
        Assert.Matches(
            @"^approvedToken = SelectSessionAccessToken\(\s*requestToken,\s*requestDeviceId,\s*info\.DeviceId,",
            CallBlock(handler, "approvedToken = SelectSessionAccessToken("));
    }

    [Fact]
    public void A_verified_reconnect_renews_the_verification()
    {
        // The verified mark lasts 30 days from when it was set and this branch
        // left it alone, so a TV in daily use met the challenge again (blocked,
        // then logged out) a month after its sign-in. Renewed here, the 30 days
        // run from the last use, which is what VerifiedTokenPersistence's TTL
        // is there for: long-abandoned sessions.
        var reconnect = Region(
            SourceFile(HandlerPath),
            "&& _challengeStore.IsTokenVerified(approvedToken))",
            "return;");

        Assert.Contains("_challengeStore.MarkTokenVerified(approvedToken);", reconnect, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Authorization", "MediaBrowser Client=\"Jellyfin Android TV\", Device=\"Fire TV\", DeviceId=\"tv-session-B\", Version=\"0.19.10\", Token=\"tv-token\"")]
    [InlineData("X-Emby-Authorization", "MediaBrowser Client=\"Jellyfin Web\", Device=\"Chrome\", DeviceId=\"web\", Version=\"12.2.0\", Token=\"tv-token\"")]
    [InlineData("X-Emby-Token", "tv-token")]
    public void The_request_token_is_read_from_every_header_shape_clients_send(string header, string value)
    {
        // The handler now judges the token these return. Losing a shape would
        // send that client back to the DeviceId lookup, and its reconnects
        // back to the challenge path.
        var context = new DefaultHttpContext();
        context.Request.Headers[header] = value;

        Assert.Equal("tv-token", RequestBlockerMiddleware.GetAccessToken(context));
    }

    [Theory]
    [InlineData("/Users/AuthenticateByName", true)]
    [InlineData("/Users/AuthenticateWithQuickConnect", true)]
    [InlineData("/Users/4974b86245bb4ae093ebc85484b74503/Authenticate", true)]
    [InlineData("/Sessions/Capabilities/Full", false)]
    [InlineData("/Sessions/Playing", false)]
    public void Sign_in_requests_are_told_apart_from_the_requests_that_reopen_a_session(string path, bool signIn)
    {
        // A sign-in keeps the DeviceId lookup; anything else that raises
        // SessionStarted is judged on the token it carries.
        Assert.Equal(signIn, TwoFactorEnforcementMiddleware.IsAuthPath(path));
    }

    private const string HandlerPath = "src/Jellyfin.Plugin.TwoFactorAuth/Services/AuthenticationEventHandler.cs";

    private static string Region(string source, string from, string to)
    {
        var start = source.IndexOf(from, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{from} should still be in the handler");
        var end = source.IndexOf(to, start + from.Length, StringComparison.Ordinal);
        Assert.True(end > start, $"{to} should still follow {from}");
        return source[start..end];
    }

    private static string CallBlock(string source, string call)
    {
        var start = source.IndexOf(call, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{call} should still be in the handler");
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

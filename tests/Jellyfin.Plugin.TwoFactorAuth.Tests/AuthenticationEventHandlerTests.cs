using System.Text.RegularExpressions;
using Jellyfin.Plugin.TwoFactorAuth.Services;
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

    private const string HandlerPath = "src/Jellyfin.Plugin.TwoFactorAuth/Services/AuthenticationEventHandler.cs";

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

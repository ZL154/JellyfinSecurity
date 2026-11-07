using System.Net;
using System.Net.Http.Json;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[Collection("SignInPolicy")]
public class PasskeysEnabledEntryPointTests
{
    [Fact]
    public async Task Diagnostic_routes_and_existing_generic_step_up_tokens_keep_their_contract()
    {
        using var api = new DisabledPasskeyApi();
        using var diagnosis = await api.Client.GetAsync("/TwoFactorAuth/Passkeys/Diagnose");
        Assert.Equal(HttpStatusCode.OK, diagnosis.StatusCode);
        using var diagnostic = await api.Client.PostAsJsonAsync("/TwoFactorAuth/Passkeys/ClientLog", new { phase = "test" });
        Assert.Equal(HttpStatusCode.OK, diagnostic.StatusCode);
        var proof = api.Fixture.Challenges.MintUserStepUpToken(api.Fixture.User.Id);
        using var accepted = await api.Client.PostAsJsonAsync("/TwoFactorAuth/StepUp/Verify", new { stepUpToken = proof });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.True(api.Fixture.Challenges.IsStepUpVerified(api.Fixture.User.Id));
        using var replay = await api.Client.PostAsJsonAsync("/TwoFactorAuth/StepUp/Verify", new { stepUpToken = proof });
        Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_authentication_provider_issues_the_same_effective_method_inventory(bool enabled)
    {
        using var api = new DisabledPasskeyApi();
        api.Fixture.Config.PasskeysEnabled = enabled;
        await api.Fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = api.Fixture.User.Id, TotpEnabled = true, TotpVerified = true,
            Passkeys = { new PasskeyCredential { Id = "saved-key" } },
        });
        var app = Substitute.For<IApplicationHost>();
        app.Resolve<IUserManager>().Returns(api.Fixture.Users);
        var primary = Substitute.For<IAuthenticationProvider>();
        primary.IsEnabled.Returns(true);
        primary.Authenticate("local-user", "sample-secret").Returns(new ProviderAuthenticationResult { Username = "local-user" });
        app.GetExports<IAuthenticationProvider>(false).Returns(new[] { primary });
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.25");
        context.Request.Headers["X-Emby-Device-Id"] = "test-browser";
        using var pairings = new PendingPairingService(NullLogger<PendingPairingService>.Instance);
        var provider = new TwoFactorAuthProvider(app, api.Fixture.Store, api.Fixture.Challenges,
            new BypassEvaluator(NullLogger<BypassEvaluator>.Instance), new NotificationService(NullLogger<NotificationService>.Instance),
            new AppPasswordService(), pairings, api.Limiter, api.Bridge, api.Bans,
            new IpAllowlistService(api.Fixture.Store, NullLogger<IpAllowlistService>.Instance),
            new HttpContextAccessor { HttpContext = context }, NullLogger<TwoFactorAuthProvider>.Instance);

        Assert.Equal("local-user", (await provider.Authenticate("local-user", "sample-secret")).Username);
        var entry = Assert.Single(await api.Fixture.Store.GetAuditLogAsync(), e => e.Result == AuditResult.ChallengeIssued);
        Assert.Equal(enabled ? "totp,passkey" : "totp", entry.Method);
    }
}

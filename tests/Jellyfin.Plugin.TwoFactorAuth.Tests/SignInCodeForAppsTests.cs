using System.Net;
using System.Text;
using System.Text.Json;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Jellyfin.Server.Implementations.Users;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#313] An app that can't show the challenge, for an account whose
/// codes come by email or Telegram: the first sign-in with the right password
/// gets the challenge and a sent code; the second one carries the code after
/// the password or, where the admin allows it, alone.</summary>
public sealed class SignInCodeForAppsTests : IDisposable
{
    private const string Password = "MyPassword";
    private const string Code = "24681357";
    private const string AppAddress = "198.51.100.7";
    private const string Header = "MediaBrowser Client=\"Infuse\", Device=\"iPhone\", DeviceId=\"infuse-1\", Version=\"8.1\"";

    private readonly string _sandbox;
    private readonly IApplicationPaths _paths;
    private readonly UserTwoFactorStore _store;
    private readonly TotpService _totp;
    private readonly ChallengeStore _challenges = new();
    private readonly DefaultAuthenticationProvider _passwords = new();
    private readonly IApplicationHost _host = Substitute.For<IApplicationHost>();
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly PluginConfiguration _cfg = new() { SendSignInCodeToApps = true };
    private readonly AppSignInCodeService _codes;
    private readonly CodeAfterPasswordMiddleware _middleware;
    private readonly User _alice = new("alice", SignInProviderRestore.JellyfinDefaultProviderId, "reset") { Password = "stored-hash-1" };

    public SignInCodeForAppsTests()
    {
        _paths = TestApplicationPaths.Create(out _sandbox);
        _store = new UserTwoFactorStore(_paths, Substitute.For<IServiceProvider>());
        _totp = new TotpService(_paths, NullLogger<TotpService>.Instance);
        _passwords.SetPassword(_alice, Password);
        _users.GetUserByName("alice").Returns(_alice);
        _users.GetUserById(_alice.Id).Returns(_alice);
        _host.GetExports<IAuthenticationProvider>(false).Returns(new IAuthenticationProvider[] { _passwords });
        _cfg.SetUserEmail(_alice.Id.ToString("N"), "alice@example.test");

        _codes = AppSignInCodesForTests.Build(_paths, _store, _users, _host, _challenges, () => _cfg);
        _codes.NewCode = () => Code;
        _middleware = new CodeAfterPasswordMiddleware(
            _ => Task.CompletedTask,
            _store,
            _users,
            _host,
            _totp,
            new RateLimiter(),
            new IpBanService(_paths, NullLogger<IpBanService>.Instance),
            _codes,
            NullLogger<CodeAfterPasswordMiddleware>.Instance);
    }

    public void Dispose()
    {
        _challenges.Dispose();
        _store.Dispose();
        Directory.Delete(_sandbox, recursive: true);
    }

    [Fact]
    public void Both_settings_are_off_until_an_admin_turns_them_on()
    {
        Assert.False(new PluginConfiguration().SendSignInCodeToApps);
        Assert.False(new PluginConfiguration().AcceptSignInCodeAlone);
    }

    // ---- The client's own address -------------------------------------------

    [Fact]
    public void A_request_without_a_forwarding_header_comes_from_the_client()
    {
        Assert.Equal(("203.0.113.5", true), AppSignInCodeService.ClientAddress(new PluginConfiguration(), "203.0.113.5", new HeaderDictionary()));
    }

    [Theory]
    [InlineData("X-Forwarded-For")]
    [InlineData("X-Real-IP")]
    [InlineData("Forwarded")]
    public void Behind_a_proxy_the_plugin_does_not_trust_the_address_is_unknown(string header)
    {
        var headers = new HeaderDictionary { [header] = "198.51.100.9" };

        Assert.False(AppSignInCodeService.ClientAddress(new PluginConfiguration(), "10.0.0.2", headers).Known);
    }

    [Fact]
    public void Behind_a_trusted_proxy_the_address_is_the_client_it_names()
    {
        var cfg = new PluginConfiguration { TrustForwardedFor = true, TrustedProxyCidrs = new[] { "10.0.0.2/32" } };
        var headers = new HeaderDictionary { ["X-Forwarded-For"] = "198.51.100.9" };

        Assert.Equal(("198.51.100.9", true), AppSignInCodeService.ClientAddress(cfg, "10.0.0.2", headers));
    }

    [Fact]
    public void A_chain_of_trusted_proxies_alone_names_no_client()
    {
        var cfg = new PluginConfiguration { TrustForwardedFor = true, TrustedProxyCidrs = new[] { "10.0.0.0/24" } };
        var headers = new HeaderDictionary { ["X-Forwarded-For"] = "10.0.0.3" };

        Assert.False(AppSignInCodeService.ClientAddress(cfg, "10.0.0.2", headers).Known);
        Assert.False(AppSignInCodeService.ClientAddress(cfg, null, new HeaderDictionary()).Known);
    }

    [Fact]
    public void The_first_attempt_is_read_from_its_request()
    {
        var context = SignIn(Password);

        var attempt = AppSignInCodeService.Capture(context, _cfg, _alice.Id, "alice", "challenge-1");

        Assert.Equal("infuse-1", attempt.DeviceId);
        Assert.Equal("Infuse", attempt.Client);
        Assert.Equal("iPhone", attempt.DeviceName);
        Assert.Equal(AppAddress, attempt.ClientIp);
        Assert.True(attempt.ClientIpKnown);
        Assert.Equal("challenge-1", attempt.ChallengeToken);
    }

    // ---- Who gets a code ------------------------------------------------------

    [Fact]
    public async Task An_app_signing_in_with_the_right_password_gets_a_code()
    {
        Assert.True(await _codes.SendAsync(Attempt(), enrollmentRequired: false));

        Assert.True(_codes.HasPending(_alice.Id, "infuse-1", "Infuse"));
        Assert.False(_codes.HasPending(_alice.Id, "infuse-1", "Swiftfin"));
        Assert.False(_codes.HasPending(_alice.Id, "other-device", "Infuse"));
    }

    [Fact]
    public async Task A_linked_Telegram_chat_is_enough_without_an_email_address()
    {
        _cfg.SetUserEmail(_alice.Id.ToString("N"), null);
        await _store.MutateAsync(_alice.Id, d => d.TelegramChatId = "123456");

        Assert.True(await _codes.SendAsync(Attempt(), enrollmentRequired: false));
    }

    [Theory]
    [InlineData("Jellyfin Web")]
    [InlineData("jellyfin web")]
    [InlineData("Jellyfin for Android")]
    public async Task Clients_that_show_the_challenge_get_none(string client)
    {
        // The web interface always, and what the admin lists (#244).
        _cfg.AppPasswordRefusedClients = new[] { "Jellyfin for Android" };

        Assert.False(await _codes.SendAsync(Attempt() with { Client = client }, enrollmentRequired: false));
    }

    [Fact]
    public async Task Nothing_goes_out_while_the_setting_or_email_OTP_is_off()
    {
        _cfg.SendSignInCodeToApps = false;
        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: false));

        _cfg.SendSignInCodeToApps = true;
        _cfg.EmailOtpEnabled = false;
        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: false));
    }

    [Fact]
    public async Task Nothing_goes_out_without_a_device_a_channel_or_a_password()
    {
        Assert.False(await _codes.SendAsync(Attempt() with { DeviceId = null }, enrollmentRequired: false));
        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: true));

        _cfg.SetUserEmail(_alice.Id.ToString("N"), null);
        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: false));

        _cfg.SetUserEmail(_alice.Id.ToString("N"), "alice@example.test");
        _alice.Password = null;
        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: false));
    }

    [Fact]
    public async Task An_account_on_another_provider_gets_none()
    {
        // It couldn't redeem it: the password part is never checked there.
        _alice.AuthenticationProviderId = "Jellyfin.Plugin.LDAP_Auth.LdapAuthenticationProviderPlugin";

        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: false));
    }

    [Fact]
    public async Task One_code_per_device_a_minute_and_three_per_account_in_fifteen_minutes()
    {
        Assert.True(await _codes.SendAsync(Attempt(), enrollmentRequired: false));
        Assert.False(await _codes.SendAsync(Attempt(), enrollmentRequired: false));

        Assert.True(await _codes.SendAsync(Attempt() with { DeviceId = "tv-1" }, enrollmentRequired: false));
        Assert.True(await _codes.SendAsync(Attempt() with { DeviceId = "tv-2" }, enrollmentRequired: false));
        Assert.False(await _codes.SendAsync(Attempt() with { DeviceId = "tv-3" }, enrollmentRequired: false));
    }

    // ---- Redeeming ------------------------------------------------------------

    [Fact]
    public async Task The_code_works_once_and_hands_back_the_first_attempts_challenge()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);

        Assert.Equal((AppSignInCodeService.Outcome.Accepted, "challenge-1"), _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password));
        Assert.Equal(AppSignInCodeService.Outcome.NoCode, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password).Outcome);
    }

    [Fact]
    public async Task Another_device_or_app_finds_no_code()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);

        Assert.Equal(AppSignInCodeService.Outcome.NoCode, _codes.Redeem(_alice.Id, "other-device", "Infuse", Code, _alice.Password).Outcome);
        Assert.Equal(AppSignInCodeService.Outcome.NoCode, _codes.Redeem(_alice.Id, "infuse-1", "Swiftfin", Code, _alice.Password).Outcome);
        Assert.Equal(AppSignInCodeService.Outcome.Accepted, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password).Outcome);
    }

    [Fact]
    public async Task Five_wrong_guesses_void_the_code()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(AppSignInCodeService.Outcome.Wrong, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", "11111111", _alice.Password).Outcome);
        }

        Assert.Equal(AppSignInCodeService.Outcome.NoCode, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password).Outcome);
    }

    [Fact]
    public async Task A_password_change_voids_the_code()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);

        Assert.Equal(AppSignInCodeService.Outcome.Refused, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, "stored-hash-2").Outcome);
        Assert.Equal(AppSignInCodeService.Outcome.NoCode, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password).Outcome);
    }

    [Fact]
    public async Task The_code_expires_with_the_challenge_it_belongs_to()
    {
        _cfg.EmailOtpTtlSeconds = 900;
        _cfg.ChallengeTokenTtlSeconds = 120;
        var now = DateTime.UtcNow;
        _codes.UtcNow = () => now;
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);

        _codes.UtcNow = () => now.AddSeconds(121);

        Assert.Equal(AppSignInCodeService.Outcome.NoCode, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password).Outcome);
    }

    [Fact]
    public async Task The_code_alone_needs_the_first_attempts_address_and_both_known()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);

        Assert.Equal(AppSignInCodeService.Outcome.Refused, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password, ("203.0.113.99", true)).Outcome);
        Assert.Equal(AppSignInCodeService.Outcome.Refused, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password, (AppAddress, false)).Outcome);
        Assert.Equal(AppSignInCodeService.Outcome.Accepted, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password, (AppAddress, true)).Outcome);
    }

    [Fact]
    public async Task The_code_alone_is_refused_when_the_first_attempts_address_was_unknown()
    {
        await _codes.SendAsync(Attempt() with { ClientIpKnown = false }, enrollmentRequired: false);

        Assert.Equal(AppSignInCodeService.Outcome.Refused, _codes.Redeem(_alice.Id, "infuse-1", "Infuse", Code, _alice.Password, (AppAddress, true)).Outcome);
    }

    // ---- Through the middleware ---------------------------------------------

    [Fact]
    public async Task The_password_and_the_sent_code_reach_Jellyfin_as_the_password_alone()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);
        var context = SignIn(Password + Code);

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.PasswordAlone, await _middleware.TryAcceptAsync(context, _cfg));

        Assert.Equal("{\"Username\":\"alice\",\"Pw\":\"MyPassword\"}", await BodyOf(context.Request));
        Assert.True(CodeAfterPasswordMiddleware.WasVerifiedFor(context, _alice.Id));
        Assert.Equal(AppSignInCodeService.AuditMethodAfterPassword, CodeAfterPasswordMiddleware.VerifiedMethod(context));
    }

    [Fact]
    public async Task A_wrong_sent_code_goes_on_unchanged_and_is_audited()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);
        var context = SignIn(Password + "11111111");

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.None, await _middleware.TryAcceptAsync(context, _cfg));

        Assert.Equal(Json(Password + "11111111"), await BodyOf(context.Request));
        Assert.Contains(await _store.GetAuditLogAsync(), e => e.UserId == _alice.Id
            && e.Result == AuditResult.Failed
            && e.Method == AppSignInCodeService.AuditMethodAfterPassword);
    }

    [Fact]
    public async Task A_wrong_password_part_spends_nothing()
    {
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.None, await _middleware.TryAcceptAsync(SignIn("NotMyPassword" + Code), _cfg));

        // The code is still there for the app.
        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.PasswordAlone, await _middleware.TryAcceptAsync(SignIn(Password + Code), _cfg));
    }

    [Fact]
    public async Task While_a_code_is_pending_the_authenticator_code_still_works()
    {
        _cfg.AcceptCodeAfterPassword = true;
        var secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        await _store.MutateAsync(_alice.Id, d =>
        {
            d.TotpEnabled = true;
            d.TotpVerified = true;
            d.EncryptedTotpSecret = _totp.EncryptSecret(secret, _alice.Id);
        });
        await _codes.SendAsync(Attempt(), enrollmentRequired: false);
        var totp = new Totp(Base32Encoding.ToBytes(secret), step: 30, totpSize: 6).ComputeTotp();
        var context = SignIn(Password + totp);

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.PasswordAlone, await _middleware.TryAcceptAsync(context, _cfg));

        Assert.Equal(CodeAfterPasswordMiddleware.AuditMethod, CodeAfterPasswordMiddleware.VerifiedMethod(context));
    }

    [Fact]
    public async Task The_code_alone_completes_the_first_attempts_challenge()
    {
        _cfg.AcceptSignInCodeAlone = true;
        var challenge = PendingChallenge("tok-1");
        await _codes.SendAsync(Attempt() with { ChallengeToken = challenge.Token }, enrollmentRequired: false);
        var context = SignIn(Code);
        context.Response.Body = new MemoryStream();

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.Answered, await _middleware.TryAcceptAsync(context, _cfg));

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        Assert.Equal(challenge.PendingAuthResponse, await new StreamReader(context.Response.Body).ReadToEndAsync());
        Assert.False(_challenges.IsTokenBlocked("tok-1"));
        Assert.True(_challenges.IsTokenVerified("tok-1"));
        Assert.Null(_challenges.GetChallenge(challenge.Token));
        Assert.Contains(await _store.GetAuditLogAsync(), e => e.UserId == _alice.Id
            && e.Result == AuditResult.Success
            && e.Method == AppSignInCodeService.AuditMethodAlone);
    }

    [Fact]
    public async Task The_code_alone_needs_its_own_setting()
    {
        var challenge = PendingChallenge("tok-2");
        await _codes.SendAsync(Attempt() with { ChallengeToken = challenge.Token }, enrollmentRequired: false);

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.None, await _middleware.TryAcceptAsync(SignIn(Code), _cfg));

        Assert.True(_challenges.IsTokenBlocked("tok-2"));
    }

    [Theory]
    [InlineData("203.0.113.99", null)]
    [InlineData(AppAddress, "203.0.113.50")]
    public async Task The_code_alone_from_another_or_an_unknown_address_leaves_the_challenge_alone(string peer, string? forwardedFor)
    {
        _cfg.AcceptSignInCodeAlone = true;
        var challenge = PendingChallenge("tok-3");
        await _codes.SendAsync(Attempt() with { ChallengeToken = challenge.Token }, enrollmentRequired: false);
        var context = SignIn(Code, peer);
        if (forwardedFor is not null)
        {
            context.Request.Headers["X-Forwarded-For"] = forwardedFor;
        }

        Assert.Equal(CodeAfterPasswordMiddleware.Acceptance.None, await _middleware.TryAcceptAsync(context, _cfg));

        Assert.True(_challenges.IsTokenBlocked("tok-3"));
        Assert.NotNull(_challenges.GetChallenge(challenge.Token));
    }

    // ---- Wiring -----------------------------------------------------------------

    [Fact]
    public void The_challenge_sends_the_code_once_the_token_is_held()
    {
        var middleware = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorEnforcementMiddleware.cs");

        var blocked = middleware.IndexOf("_challengeStore.BlockToken(authResult.AccessToken);", StringComparison.Ordinal);
        var hook = middleware.IndexOf("if (config.SendSignInCodeToApps && CodeAfterPasswordMiddleware.IsHandledEndpoint(context))", StringComparison.Ordinal);
        var answered = middleware.IndexOf("var response = new TwoFactorRequiredResponse", StringComparison.Ordinal);
        Assert.True(blocked >= 0 && blocked < hook && hook < answered);
        var block = middleware[hook..answered];
        Assert.Contains("AppSignInCodeService.Capture(context, config, userGuid,", block, StringComparison.Ordinal);
        Assert.Contains("_ = Task.Run(() => _appSignInCodes.SendAsync(attempt, enrollmentRequired));", block, StringComparison.Ordinal);
    }

    [Fact]
    public void The_service_is_registered()
    {
        var registrator = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/PluginServiceRegistrator.cs");

        Assert.Contains("serviceCollection.AddSingleton<AppSignInCodeService>();", registrator, StringComparison.Ordinal);
    }

    [Fact]
    public void The_admin_page_loads_and_saves_both_settings()
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");
        Assert.NotNull(page);
        Assert.NotNull(script);

        Assert.Contains("id=\"cfgSendSignInCodeToApps\"", page, StringComparison.Ordinal);
        Assert.Contains("id=\"cfgAcceptSignInCodeAlone\"", page, StringComparison.Ordinal);
        Assert.Contains("sendCodeEl.checked = c.SendSignInCodeToApps === true;", script, StringComparison.Ordinal);
        Assert.Contains("codeAloneEl.checked = c.AcceptSignInCodeAlone === true;", script, StringComparison.Ordinal);
        Assert.Contains("c.SendSignInCodeToApps = sendCodeSaveEl ? sendCodeSaveEl.checked : (c.SendSignInCodeToApps === true);", script, StringComparison.Ordinal);
        Assert.Contains("c.AcceptSignInCodeAlone = codeAloneSaveEl ? codeAloneSaveEl.checked : (c.AcceptSignInCodeAlone === true);", script, StringComparison.Ordinal);
    }

    // ---- Helpers ----------------------------------------------------------------

    private AppSignInCodeService.SignInAttempt Attempt()
        => new(_alice.Id, "alice", "infuse-1", "Infuse", "iPhone", AppAddress, true, "challenge-1");

    private ChallengeData PendingChallenge(string accessToken)
    {
        var challenge = _challenges.CreateChallenge(_alice.Id, "alice", new List<string> { "email" }, "infuse-1", "iPhone", AppAddress, enrollmentRequired: false);
        challenge.PendingAuthResponse = JsonSerializer.Serialize(new { User = new { Name = "alice" }, AccessToken = accessToken, ServerId = "server" });
        _challenges.BlockToken(accessToken);
        return challenge;
    }

    private static string Json(string typed) => JsonSerializer.Serialize(new { Username = "alice", Pw = typed });

    private static DefaultHttpContext SignIn(string typed, string peer = AppAddress)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/Users/AuthenticateByName";
        context.Request.ContentType = "application/json";
        context.Request.Headers["Authorization"] = Header;
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        var body = Encoding.UTF8.GetBytes(Json(typed));
        context.Request.Body = new MemoryStream(body);
        context.Request.ContentLength = body.Length;
        return context;
    }

    private static async Task<string> BodyOf(HttpRequest request)
    {
        request.Body.Position = 0;
        using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        request.Body.Position = 0;
        return body;
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

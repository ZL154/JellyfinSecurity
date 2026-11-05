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

/// <summary>[#312] An app that can't show the 2FA challenge signs in with the
/// authenticator code typed right after the password ("MyPassword123456").
/// CodeAfterPasswordMiddleware checks the password part, then the code, and
/// only then hands Jellyfin the password alone with a mark the three paths
/// that decide a sign-in honour.</summary>
public sealed class CodeAfterPasswordTests : IDisposable
{
    private const string Password = "MyPassword";
    private const string DeviceHeader = "MediaBrowser Client=\"Infuse\", Device=\"iPhone\", DeviceId=\"infuse-1\", Version=\"8.1\"";

    private readonly string _sandbox;
    private readonly IApplicationPaths _paths;
    private readonly UserTwoFactorStore _store;
    private readonly TotpService _totp;
    private readonly DefaultAuthenticationProvider _passwords = new();
    private readonly IApplicationHost _host = Substitute.For<IApplicationHost>();
    private readonly CodeAfterPasswordMiddleware _middleware;
    private readonly User _alice = new("alice", SignInProviderRestore.JellyfinDefaultProviderId, "reset");
    private readonly string _secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));

    public CodeAfterPasswordTests()
    {
        _paths = TestApplicationPaths.Create(out _sandbox);
        _store = new UserTwoFactorStore(_paths, Substitute.For<IServiceProvider>());
        _totp = new TotpService(_paths, NullLogger<TotpService>.Instance);

        _passwords.SetPassword(_alice, Password);
        var users = Substitute.For<IUserManager>();
        users.GetUserByName("alice").Returns(_alice);
        _host.GetExports<IAuthenticationProvider>(false).Returns(new IAuthenticationProvider[] { _passwords });

        _middleware = new CodeAfterPasswordMiddleware(
            _ => Task.CompletedTask,
            _store,
            users,
            _host,
            _totp,
            new RateLimiter(),
            new IpBanService(_paths, NullLogger<IpBanService>.Instance),
            NullLogger<CodeAfterPasswordMiddleware>.Instance);
    }

    public void Dispose()
    {
        _store.Dispose();
        Directory.Delete(_sandbox, recursive: true);
    }

    // ---- What gets split ----------------------------------------------------

    [Fact]
    public void The_setting_is_off_until_an_admin_turns_it_on()
    {
        Assert.False(new PluginConfiguration().AcceptCodeAfterPassword);
    }

    [Theory]
    [InlineData("MyPassword123456", "MyPassword", "123456")]
    [InlineData("summer123456654321", "summer123456", "654321")]
    [InlineData("pass word 000000", "pass word ", "000000")]
    [InlineData("x999999", "x", "999999")]
    public void The_last_six_digits_are_the_code_and_the_rest_is_the_password(string typed, string password, string code)
    {
        Assert.True(CodeAfterPasswordMiddleware.TrySplit(typed, out var p, out var c));
        Assert.Equal(password, p);
        Assert.Equal(code, c);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("123456")]          // no password part: the code alone never signs in
    [InlineData("      123456")]    // a blank password part, as the empty-password gate sees it
    [InlineData("MyPassword12345")] // five digits
    [InlineData("MyPassword12345a")]
    [InlineData("MyPassword")]
    [InlineData("MyPassword١٢٣٤٥٦")] // Arabic-Indic digits are not a code
    [InlineData("MyPassword１２３４５６")] // nor are fullwidth ones
    public void Anything_else_is_left_as_typed(string? typed)
    {
        Assert.False(CodeAfterPasswordMiddleware.TrySplit(typed, out _, out _));
    }

    [Fact]
    public void Only_an_account_with_a_confirmed_authenticator_qualifies()
    {
        var enrolled = new UserTwoFactorData { TotpEnabled = true, TotpVerified = true, EncryptedTotpSecret = "v2:x" };
        Assert.True(CodeAfterPasswordMiddleware.AppliesTo(enrolled));

        Assert.False(CodeAfterPasswordMiddleware.AppliesTo(new UserTwoFactorData()));
        Assert.False(CodeAfterPasswordMiddleware.AppliesTo(new UserTwoFactorData { TotpEnabled = true, EncryptedTotpSecret = "v2:x" }));
        Assert.False(CodeAfterPasswordMiddleware.AppliesTo(new UserTwoFactorData { TotpEnabled = true, TotpVerified = true }));
    }

    [Fact]
    public void An_account_held_to_recovery_codes_does_not_qualify()
    {
        // The emergency lockout limits the challenge to recovery and email
        // codes; the authenticator code can't take the shortcut either.
        var locked = new UserTwoFactorData
        {
            TotpEnabled = true,
            TotpVerified = true,
            EncryptedTotpSecret = "v2:x",
            ForceRecoveryOnNextLogin = true,
        };

        Assert.False(CodeAfterPasswordMiddleware.AppliesTo(locked));
    }

    // ---- Which provider checks the password part ----------------------------

    private const string Ldap = "Jellyfin.Plugin.LDAP_Auth.LdapAuthenticationProviderPlugin";

    private static readonly IReadOnlyList<(string? TypeName, bool Enabled)> Installed = new (string?, bool)[]
    {
        ("Jellyfin.Server.Implementations.Users.InvalidAuthProvider", false),
        (SignInProviderRestore.JellyfinDefaultProviderId, true),
        (SignInProviderRestore.PluginProviderId, true),
        (Ldap, true),
    };

    [Fact]
    public void An_account_on_Jellyfins_password_provider_is_checked_by_it()
    {
        Assert.Equal(1, CodeAfterPasswordMiddleware.PasswordProviderIndex(SignInProviderRestore.JellyfinDefaultProviderId, Installed));
    }

    [Fact]
    public void An_account_moved_onto_the_plugin_is_checked_by_the_provider_the_plugin_hands_passwords_to()
    {
        Assert.Equal(1, CodeAfterPasswordMiddleware.PasswordProviderIndex(SignInProviderRestore.PluginProviderId, Installed));
    }

    [Theory]
    [InlineData(Ldap)]
    [InlineData("Some.Provider.ThatIsNotLoaded")]
    [InlineData("")]
    [InlineData(null)]
    public void Any_other_account_is_left_to_the_challenge(string? accountProvider)
    {
        // Another provider (LDAP and the like) would be asked twice per
        // sign-in, here and by Jellyfin, and a directory counts both failures.
        Assert.Equal(-1, CodeAfterPasswordMiddleware.PasswordProviderIndex(accountProvider, Installed));
    }

    [Fact]
    public void A_plugin_account_is_left_alone_when_the_plugin_would_hand_its_password_to_another_provider()
    {
        var ldapFirst = new (string?, bool)[]
        {
            (SignInProviderRestore.PluginProviderId, true),
            (Ldap, true),
            (SignInProviderRestore.JellyfinDefaultProviderId, true),
        };

        Assert.Equal(-1, CodeAfterPasswordMiddleware.PasswordProviderIndex(SignInProviderRestore.PluginProviderId, ldapFirst));
    }

    // ---- The request ------------------------------------------------------------

    [Theory]
    [InlineData("POST", "/Users/AuthenticateByName", true)]
    [InlineData("POST", "/jellyfin/Users/AuthenticateByName", true)]
    [InlineData("POST", "/users/authenticatebyname/", true)]
    [InlineData("GET", "/Users/AuthenticateByName", false)]
    [InlineData("POST", "/Users/0f8fad5b-d9cb-469f-a165-70867728950e/Authenticate", false)]
    [InlineData("POST", "/Users/AuthenticateWithQuickConnect", false)]
    public void Only_sign_in_by_name_is_handled(string method, string path, bool handled)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;

        Assert.Equal(handled, CodeAfterPasswordMiddleware.IsHandledEndpoint(context));
    }

    [Fact]
    public async Task Jellyfin_gets_a_body_with_only_the_name_and_the_password()
    {
        // A fresh body, so a duplicate "pw" or anything else in the original
        // can't reach Jellyfin next to the password that was checked.
        var context = new DefaultHttpContext();
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"Username\":\"alice\",\"Pw\":\"MyPassword123456\",\"pw\":\"other\"}"));

        CodeAfterPasswordMiddleware.RewriteCredentials(context.Request, "alice", Password);

        var body = await BodyOf(context.Request);
        Assert.Equal("{\"Username\":\"alice\",\"Pw\":\"MyPassword\"}", body);
        Assert.Equal(Encoding.UTF8.GetByteCount(body), context.Request.ContentLength);
    }

    [Fact]
    public void The_mark_names_one_account()
    {
        var context = new DefaultHttpContext();
        var alice = Guid.NewGuid();
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(context, alice));

        context.Items[CodeAfterPasswordMiddleware.VerifiedUserItemKey] = alice;

        Assert.True(CodeAfterPasswordMiddleware.WasVerifiedFor(context, alice));
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(context, Guid.NewGuid()));
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(context, Guid.Empty));
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(null, alice));
    }

    // ---- The check itself ---------------------------------------------------

    [Fact]
    public async Task The_right_password_and_code_reach_Jellyfin_as_the_password_alone()
    {
        await EnrollAsync();
        var context = SignIn(Password + CurrentCode());

        Assert.True(await _middleware.TryAcceptAsync(context));

        Assert.Equal("{\"Username\":\"alice\",\"Pw\":\"MyPassword\"}", await BodyOf(context.Request));
        Assert.True(CodeAfterPasswordMiddleware.WasVerifiedFor(context, _alice.Id));
        Assert.True((await _store.GetUserDataAsync(_alice.Id)).LastUsedTotpStep > 0);
    }

    [Fact]
    public async Task A_wrong_code_goes_on_unchanged_and_is_audited()
    {
        await EnrollAsync();
        var typed = Password + WrongCode();
        var context = SignIn(typed);

        Assert.False(await _middleware.TryAcceptAsync(context));

        // Unchanged, so Jellyfin refuses it as a wrong password: same 401,
        // and the lockout counts it like any other failed sign-in.
        Assert.Equal(Json(typed), await BodyOf(context.Request));
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(context, _alice.Id));
        var audit = await _store.GetAuditLogAsync();
        Assert.Contains(audit, e => e.UserId == _alice.Id
            && e.Result == AuditResult.Failed
            && e.Method == CodeAfterPasswordMiddleware.AuditMethod
            && e.DeviceId == "infuse-1");
    }

    [Fact]
    public async Task A_wrong_password_part_goes_on_unchanged_without_looking_at_the_code()
    {
        await EnrollAsync();
        var typed = "NotMyPassword" + CurrentCode();
        var context = SignIn(typed);

        Assert.False(await _middleware.TryAcceptAsync(context));

        Assert.Equal(Json(typed), await BodyOf(context.Request));
        Assert.Equal(0, (await _store.GetUserDataAsync(_alice.Id)).LastUsedTotpStep);
        Assert.DoesNotContain(await _store.GetAuditLogAsync(), e => e.Method == CodeAfterPasswordMiddleware.AuditMethod);
    }

    [Fact]
    public async Task A_password_that_ends_in_digits_still_works_typed_alone()
    {
        // The part before the last six digits isn't the password, so the
        // whole string goes on and Jellyfin checks it as typed.
        _passwords.SetPassword(_alice, "summer123456");
        await EnrollAsync();
        var context = SignIn("summer123456");

        Assert.False(await _middleware.TryAcceptAsync(context));

        Assert.Equal(Json("summer123456"), await BodyOf(context.Request));
    }

    [Fact]
    public async Task A_code_works_once()
    {
        await EnrollAsync();
        var code = CurrentCode();
        Assert.True(await _middleware.TryAcceptAsync(SignIn(Password + code)));

        var replay = SignIn(Password + code);

        Assert.False(await _middleware.TryAcceptAsync(replay));
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(replay, _alice.Id));
    }

    [Fact]
    public async Task A_code_used_before_a_restart_is_still_refused()
    {
        // A new TotpService starts with an empty replay cache, as after a
        // restart; the step written to the account record still refuses it.
        await EnrollAsync();
        var code = CurrentCode();
        Assert.True(await _middleware.TryAcceptAsync(SignIn(Password + code)));

        var users = Substitute.For<IUserManager>();
        users.GetUserByName("alice").Returns(_alice);
        var afterRestart = new CodeAfterPasswordMiddleware(
            _ => Task.CompletedTask,
            _store,
            users,
            _host,
            new TotpService(_paths, NullLogger<TotpService>.Instance),
            new RateLimiter(),
            new IpBanService(_paths, NullLogger<IpBanService>.Instance),
            NullLogger<CodeAfterPasswordMiddleware>.Instance);

        Assert.False(await afterRestart.TryAcceptAsync(SignIn(Password + code)));
    }

    [Fact]
    public async Task After_fifteen_wrong_codes_even_the_right_one_is_refused()
    {
        // The challenge page's per-account bucket, shared, and not lifted
        // for administrators the way the lockout is.
        await EnrollAsync();
        for (var i = 0; i < 15; i++)
        {
            Assert.False(await _middleware.TryAcceptAsync(SignIn(Password + WrongCode())));
        }

        var context = SignIn(Password + CurrentCode());

        Assert.False(await _middleware.TryAcceptAsync(context));
        Assert.False(CodeAfterPasswordMiddleware.WasVerifiedFor(context, _alice.Id));
    }

    [Fact]
    public async Task An_account_without_an_authenticator_is_left_alone()
    {
        var context = SignIn(Password + "123456");

        Assert.False(await _middleware.TryAcceptAsync(context));

        Assert.Equal(0, _passwords.Checks);
        Assert.Equal(Json(Password + "123456"), await BodyOf(context.Request));
    }

    [Fact]
    public async Task An_account_on_another_provider_is_left_alone_and_its_provider_never_asked()
    {
        var ldapUser = new User("alice", Ldap, "reset");
        var users = Substitute.For<IUserManager>();
        users.GetUserByName("alice").Returns(ldapUser);
        var middleware = new CodeAfterPasswordMiddleware(
            _ => Task.CompletedTask,
            _store,
            users,
            _host,
            _totp,
            new RateLimiter(),
            new IpBanService(TestApplicationPaths.Create(out var otherSandbox), NullLogger<IpBanService>.Instance),
            NullLogger<CodeAfterPasswordMiddleware>.Instance);
        await EnrollAsync(ldapUser.Id);

        try
        {
            Assert.False(await middleware.TryAcceptAsync(SignIn(Password + CurrentCode())));
            Assert.Equal(0, _passwords.Checks);
        }
        finally
        {
            Directory.Delete(otherSandbox, recursive: true);
        }
    }

    // ---- The paths that decide the sign-in -------------------------------------

    [Fact]
    public void It_runs_after_the_lockout_middleware_and_before_the_rest()
    {
        // After it: the empty-password and Disable-password-sign-in gates and
        // the lockout pre-check see what was typed, and the 401 of a wrong
        // code is counted. Before the others: they all see the password alone.
        var filter = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorStartupFilter.cs");

        var lockout = filter.IndexOf("app.UseMiddleware<LockoutMessageMiddleware>();", StringComparison.Ordinal);
        var codeAfterPassword = filter.IndexOf("app.UseMiddleware<CodeAfterPasswordMiddleware>();", StringComparison.Ordinal);
        var trustCookie = filter.IndexOf("app.UseMiddleware<TrustCookieMiddleware>();", StringComparison.Ordinal);
        Assert.True(lockout >= 0 && lockout < codeAfterPassword && codeAfterPassword < trustCookie);
    }

    [Fact]
    public void The_session_handler_reads_the_mark_while_the_request_is_alive_and_honours_it_first()
    {
        var handler = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/AuthenticationEventHandler.cs");

        Assert.Contains("codeAfterPasswordUser = CodeAfterPasswordMiddleware.VerifiedUser(httpContext);", handler, StringComparison.Ordinal);
        var honoured = handler.IndexOf("if (codeAfterPasswordUser == info.UserId)", StringComparison.Ordinal);
        var preVerified = handler.IndexOf("if (_challengeStore.IsDevicePreVerified(info.UserId, info.DeviceId))", StringComparison.Ordinal);
        Assert.True(honoured >= 0 && honoured < preVerified);
        Assert.Contains("Method = CodeAfterPasswordMiddleware.AuditMethod,", handler, StringComparison.Ordinal);
    }

    [Fact]
    public void The_response_middleware_lets_the_token_through_and_marks_it_verified_before_answering()
    {
        // SessionStarted runs on the thread pool. A handler that only gets to
        // it after the response went out no longer sees the request, so it has
        // to find the token verified and take the session for a reconnect.
        var middleware = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorEnforcementMiddleware.cs");

        var honoured = middleware.IndexOf("if (CodeAfterPasswordMiddleware.WasVerifiedFor(context, userGuid))", StringComparison.Ordinal);
        var waiting = middleware.IndexOf(".WaitForApprovalAsync(", StringComparison.Ordinal);
        Assert.True(honoured >= 0 && honoured < waiting);
        var block = middleware[honoured..waiting];
        Assert.Contains("_challengeStore.MarkTokenVerified(authResult.AccessToken);", block, StringComparison.Ordinal);
        Assert.True(
            block.IndexOf("MarkTokenVerified", StringComparison.Ordinal)
            < block.IndexOf("await originalBody.WriteAsync(bodyBytes)", StringComparison.Ordinal));
    }

    [Fact]
    public void The_plugin_provider_issues_no_challenge_for_a_marked_sign_in()
    {
        var provider = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorAuthProvider.cs");

        var honoured = provider.IndexOf("if (CodeAfterPasswordMiddleware.WasVerifiedFor(_httpContextAccessor.HttpContext, userId))", StringComparison.Ordinal);
        var evaluated = provider.IndexOf("var bypassResult = _bypassEvaluator.Evaluate(", StringComparison.Ordinal);
        var challenged = provider.IndexOf("var challenge = _challengeStore.CreateChallenge(", StringComparison.Ordinal);
        Assert.True(honoured >= 0 && honoured < evaluated && evaluated < challenged);
    }

    [Fact]
    public void Wrong_codes_count_in_the_same_bucket_as_the_challenge_page()
    {
        var controller = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Api/TwoFactorAuthController.cs");
        var middleware = SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/CodeAfterPasswordMiddleware.cs");

        Assert.Contains("_rateLimiter.CheckAndRecord(\"verify_user:\" + challenge.UserId.ToString(\"N\"), 15, TimeSpan.FromMinutes(15));", controller, StringComparison.Ordinal);
        Assert.Contains("var attemptsKey = \"verify_user:\" + user.Id.ToString(\"N\");", middleware, StringComparison.Ordinal);
        Assert.Contains("_rateLimiter.CheckAndRecord(attemptsKey, 15, TimeSpan.FromMinutes(15))", middleware, StringComparison.Ordinal);
    }

    [Fact]
    public void The_admin_page_loads_and_saves_the_setting()
    {
        var page = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin.html");
        var script = ResourceReader.ReadEmbeddedText("Jellyfin.Plugin.TwoFactorAuth.Pages.admin-script.js");
        Assert.NotNull(page);
        Assert.NotNull(script);

        Assert.Contains("id=\"cfgAcceptCodeAfterPassword\"", page, StringComparison.Ordinal);
        Assert.Contains("codeAfterPwEl.checked = c.AcceptCodeAfterPassword === true;", script, StringComparison.Ordinal);
        Assert.Contains("c.AcceptCodeAfterPassword = codeAfterPwSaveEl ? codeAfterPwSaveEl.checked : (c.AcceptCodeAfterPassword === true);", script, StringComparison.Ordinal);
    }

    // ---- Helpers ----------------------------------------------------------------

    private async Task EnrollAsync(Guid? userId = null)
    {
        var id = userId ?? _alice.Id;
        var data = await _store.GetUserDataAsync(id);
        data.TotpEnabled = true;
        data.TotpVerified = true;
        data.EncryptedTotpSecret = _totp.EncryptSecret(_secret, id);
        await _store.SaveUserDataAsync(data);
    }

    private string CurrentCode()
        => new Totp(Base32Encoding.ToBytes(_secret), step: 30, totpSize: 6).ComputeTotp();

    /// <summary>A code no step of the verification window accepts.</summary>
    private string WrongCode()
    {
        var totp = new Totp(Base32Encoding.ToBytes(_secret), step: 30, totpSize: 6);
        var now = DateTime.UtcNow;
        var valid = new[] { -60, -30, 0, 30, 60 }.Select(s => totp.ComputeTotp(now.AddSeconds(s))).ToHashSet();
        for (var candidate = 0; ; candidate++)
        {
            var code = candidate.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
            if (!valid.Contains(code))
            {
                return code;
            }
        }
    }

    private static string Json(string typed) => JsonSerializer.Serialize(new { Username = "alice", Pw = typed });

    private static DefaultHttpContext SignIn(string typed)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/Users/AuthenticateByName";
        context.Request.ContentType = "application/json";
        context.Request.Headers["Authorization"] = DeviceHeader;
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

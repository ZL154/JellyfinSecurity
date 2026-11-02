using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Jellyfin.Data;
using Jellyfin.Data.Queries;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Entities.Security;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Querying;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[CollectionDefinition("SignInPolicy", DisableParallelization = true)]
public class SignInPolicyCollection;

[Collection("SignInPolicy")]
public class SignInChallengeIntegrationTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    public async Task A_passkey_preference_controls_the_challenge_except_for_admin_scope(bool preference, bool admin, bool required)
    {
        using var fixture = new SignInPolicyFixture(admin);
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        await fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = fixture.User.Id,
            PasskeyRequiresSecondFactor = preference,
            Passkeys = { new PasskeyCredential { Id = "key" } },
        });

        var (status, body) = await fixture.SignInAsync();
        Assert.Equal(required ? 401 : 200, status);
        using var result = JsonDocument.Parse(body);
        if (required)
        {
            Assert.True(result.RootElement.GetProperty("TwoFactorRequired").GetBoolean());
            Assert.Contains(result.RootElement.GetProperty("Methods").EnumerateArray(), method => method.GetString() == "passkey");
        }
        else
        {
            Assert.Equal(SignInPolicyFixture.Token, result.RootElement.GetProperty("AccessToken").GetString());
        }

        await fixture.ProcessSessionAsync();
        Assert.Equal(required, fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
        Assert.Equal(required ? 403 : 200, await fixture.UseTokenAsync());
    }

    [Fact]
    public async Task Legacy_all_user_enforcement_does_not_depend_on_a_role_lookup()
    {
        using var fixture = new SignInPolicyFixture();
        fixture.Config.RequireForAllUsers = true;
        fixture.Config.EnforcementScope = EnforcementScope.Admins;
        fixture.Users.GetUserById(fixture.User.Id).Returns(_ => throw new InvalidOperationException("Role lookup unavailable."));
        await fixture.ProcessSessionAsync();
        Assert.True(fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
    }

    [Theory]
    [InlineData(false, 200)]
    [InlineData(true, 401)]
    public async Task Only_a_verified_authenticator_app_triggers_an_optional_challenge(bool verified, int expected)
    {
        using var fixture = new SignInPolicyFixture();
        await fixture.Store.SaveUserDataAsync(new UserTwoFactorData
        {
            UserId = fixture.User.Id,
            TotpEnabled = true,
            TotpVerified = verified,
            PasskeyRequiresSecondFactor = false,
        });
        Assert.Equal(expected, (await fixture.SignInAsync()).Status);
        await fixture.ProcessSessionAsync();
        Assert.Equal(verified, fixture.Challenges.IsTokenBlocked(SignInPolicyFixture.Token));
    }
}

internal sealed class SignInPolicyFixture : IDisposable
{
    internal const string Token = "session-token";
    internal const string DeviceId = "browser-device";
    private readonly Plugin? _previous = Plugin.Instance;
    private readonly Plugin _plugin;
    private readonly HttpClient _http = new();
    private readonly IpBanService _bans;
    private readonly PendingPairingService _pending = new(NullLogger<PendingPairingService>.Instance);
    internal User User { get; } = new("local-user", "provider", "reset");
    internal IUserManager Users { get; } = Substitute.For<IUserManager>();
    internal ISessionManager Sessions { get; } = Substitute.For<ISessionManager>();
    internal IDeviceManager Devices { get; } = Substitute.For<IDeviceManager>();
    internal UserTwoFactorStore Store { get; }
    internal ChallengeStore Challenges { get; } = new();
    internal PluginConfiguration Config => _plugin.Configuration;

    internal SignInPolicyFixture(bool admin = false)
    {
        var paths = TestApplicationPaths.Create();
        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        _plugin = new Plugin(paths, xml, Substitute.For<IApplicationHost>(), NullLogger<Plugin>.Instance);
        Config.Enabled = true;
        Config.RequireForAllUsers = false;
        Config.EnforcementScope = EnforcementScope.Optional;
        Config.EmailOtpEnabled = false;
        Config.LanBypassEnabled = false;
        Config.IpBanEnabled = false;
        Config.HibpEnabled = false;
        Config.SuspiciousLoginEnabled = false;
        Config.ImpossibleTravelEnabled = false;
        if (admin) User.SetPermission(PermissionKind.IsAdministrator, true);
        Users.GetUserById(User.Id).Returns(User);
        Users.GetUserByName(User.Username).Returns(User);
        var services = Substitute.For<IServiceProvider>();
        services.GetService(typeof(IUserManager)).Returns(Users);
        Store = new UserTwoFactorStore(paths, services);
        _bans = new IpBanService(paths, NullLogger<IpBanService>.Instance);
        Devices.GetDevices(Arg.Any<DeviceQuery>()).Returns(new QueryResult<Device>
        {
            Items = new[] { new Device(User.Id, "Web", "1.0", "Browser", DeviceId) { AccessToken = Token, DateLastActivity = DateTime.UtcNow } },
        });
    }

    internal async Task<(int Status, string Body)> SignInAsync()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/Users/AuthenticateByName";
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10");
        context.Request.Headers["X-Emby-Device-Id"] = DeviceId;
        context.Request.ContentType = "application/json";
        using var submitted = new MemoryStream(Encoding.UTF8.GetBytes("{\"Username\":\"local-user\",\"Pw\":\"sample-secret\"}"));
        context.Request.Body = submitted;
        context.Request.ContentLength = submitted.Length;
        using var response = new MemoryStream();
        context.Response.Body = response;
        var middleware = new TwoFactorEnforcementMiddleware(
            async ctx =>
            {
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    AccessToken = Token,
                    SessionInfo = new { Id = "session", DeviceId },
                    User = new { Id = User.Id.ToString("N"), Name = User.Username, Policy = new { IsAdministrator = User.HasPermission(PermissionKind.IsAdministrator) } },
                }));
            }, Store, Challenges, new BypassEvaluator(NullLogger<BypassEvaluator>.Instance), new AppPasswordService(), _pending,
            new RateLimiter(), _bans, new IpAllowlistService(Store, NullLogger<IpAllowlistService>.Instance),
            new HibpService(_http, NullLogger<HibpService>.Instance), NullLogger<TwoFactorEnforcementMiddleware>.Instance);
        await middleware.InvokeAsync(context);
        return (context.Response.StatusCode, Encoding.UTF8.GetString(response.ToArray()));
    }

    internal async Task ProcessSessionAsync()
    {
        var handler = new AuthenticationEventHandler(Sessions, Store, new BypassEvaluator(NullLogger<BypassEvaluator>.Instance),
            Challenges, new NotificationService(NullLogger<NotificationService>.Instance), _pending, Devices, Users,
            new HttpContextAccessor(), null!, NullLogger<AuthenticationEventHandler>.Instance);
        // Await the event's real async body so assertions cannot race its Task.Run hand-off.
        var process = typeof(AuthenticationEventHandler).GetMethod("HandleSessionAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var task = (Task)process.Invoke(handler, new object?[]
        {
            new SessionInfo(Sessions, NullLogger.Instance) { Id = "session", UserId = User.Id, UserName = User.Username, DeviceId = DeviceId, DeviceName = "Browser", RemoteEndPoint = "203.0.113.10" },
            null, null, null, null,
        })!;
        await task;
    }

    internal async Task<int> UseTokenAsync()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/Items";
        context.Request.Headers["X-Emby-Token"] = Token;
        using var response = new MemoryStream();
        context.Response.Body = response;
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("Jellyfin-UserId", User.Id.ToString()) }, "test"));
        var auth = Substitute.For<IAuthenticationService>();
        auth.AuthenticateAsync(Arg.Any<HttpContext>(), "CustomAuthentication")
            .Returns(AuthenticateResult.Success(new AuthenticationTicket(principal, "CustomAuthentication")));
        using var services = new ServiceCollection().AddSingleton(auth).BuildServiceProvider();
        context.RequestServices = services;
        var blocker = new RequestBlockerMiddleware(_ => Task.CompletedTask, Challenges, NullLogger<RequestBlockerMiddleware>.Instance);
        await blocker.InvokeAsync(context);
        return context.Response.StatusCode;
    }

    public void Dispose()
    {
        _http.Dispose();
        _bans.Dispose();
        _pending.Dispose();
        Challenges.Dispose();
        Store.Dispose();
        typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
    }
}

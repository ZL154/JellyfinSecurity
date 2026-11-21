using System.Net.Http.Json;
using System.Text.Json;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Extensions.Json;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Common;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

internal sealed class PasskeyDisableSaveApi : IDisposable
{
    internal const string SavePath = "/Plugins/94879a0c-da24-4eb1-aa06-f28b4b9333b1/Configuration";
    private readonly Plugin? _previous = Plugin.Instance;
    private readonly Plugin _plugin;
    private readonly TestServer _server;
    internal Guid Admin { get; } = Guid.NewGuid();
    internal IUserManager Users { get; } = Substitute.For<IUserManager>();
    internal UserTwoFactorStore Store { get; }
    internal ChallengeStore Challenges { get; } = new();
    internal SecurityScoreService Score { get; }
    internal ConfigExportService Export { get; }
    internal HttpClient Client { get; }
    internal PluginConfiguration Config => _plugin.Configuration;

    internal PasskeyDisableSaveApi()
    {
        var paths = TestApplicationPaths.Create();
        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        var app = Substitute.For<IApplicationHost>();
        _plugin = new Plugin(paths, xml, app, NullLogger<Plugin>.Instance);
        Config.EmailOtpEnabled = false;
        Store = new UserTwoFactorStore(paths, Substitute.For<IServiceProvider>());
        app.Resolve<UserTwoFactorStore>().Returns(Store);
        app.Resolve<IUserManager>().Returns(Users);
        var passkeyDisableGuard = new PasskeyDisableGuard(Store, Users);
        app.Resolve<PasskeyDisableGuard>().Returns(passkeyDisableGuard);
        var totp = new TotpService(paths, NullLogger<TotpService>.Instance);
        var stepUp = new StepUpService(totp, Challenges, NullLogger<StepUpService>.Instance);
        var stats = new StatsService(Store, Users);
        Score = new SecurityScoreService(Store, stats, paths, NullLogger<SecurityScoreService>.Instance, () => Config);
        Export = new ConfigExportService(Store, Score, NullLogger<ConfigExportService>.Instance, () => Config, passkeyDisableGuard);
        _server = new TestServer(new WebHostBuilder().ConfigureServices(services =>
        {
            services.AddAuthentication("test").AddScheme<AuthenticationSchemeOptions, PreferenceTestAuth>("test", _ => { });
            services.AddAuthorization(options => options.AddPolicy("RequiresElevation", p => p.RequireAuthenticatedUser()));
            services.AddSingleton(stepUp);
            services.AddSingleton(NullLogger<PluginConfigStepUpFilter>.Instance as Microsoft.Extensions.Logging.ILogger<PluginConfigStepUpFilter>);
            services.AddControllers(options => options.Filters.Add<PluginConfigStepUpFilter>())
                .AddApplicationPart(typeof(PasskeyConfigurationProbeController).Assembly)
                .AddApplicationPart(typeof(TwoFactorAuth.Api.TwoFactorAuthController).Assembly)
                .AddControllersAsServices();
            services.AddTransient(_ => new Api.TwoFactorAuthController(
                store: Store, challengeStore: Challenges, totpService: totp, emailOtpService: null!,
                deviceTokenService: null!, devicePairingService: null!, notificationService: null!, sessionManager: null!,
                userManager: Users, cookieSigner: null!, rateLimiter: null!, recoveryCodes: null!, appPasswords: null!,
                pendingPairings: null!, deviceManager: null!, sessionTerm: null!, passkeys: null!, passkeyChallenges: null!,
                diagnostics: null!, stats: stats, userExport: null!, recoveryPdf: null!, ipBans: null!, allowlist: null!,
                stepUp: stepUp, scoreService: Score, configExport: Export, onboardingProofs: null!, externalUrls: null!,
                signInObserver: null!, logger: NullLogger<Api.TwoFactorAuthController>.Instance));
        }).Configure(appBuilder =>
        {
            appBuilder.UseRouting(); appBuilder.UseAuthentication(); appBuilder.UseAuthorization();
            appBuilder.UseEndpoints(e => e.MapControllers());
        }));
        Client = _server.CreateClient();
        Client.DefaultRequestHeaders.Add("X-Test-User", Admin.ToString());
    }

    internal PluginConfiguration Copy() => JsonSerializer.Deserialize<PluginConfiguration>(JsonSerializer.Serialize(Config))!;
    internal Task<HttpResponseMessage> SaveAsync(PluginConfiguration config)
        => Client.PostAsJsonAsync(SavePath, config, JsonDefaults.Options);

    internal async Task<Guid> AddAsync(string name, string other = "none", bool secondFactor = false, bool admin = false)
    {
        var user = new User(name, "provider", "reset");
        if (admin) user.SetPermission(PermissionKind.IsAdministrator, true);
        Users.GetUserById(user.Id).Returns(user);
        var data = new UserTwoFactorData
        {
            UserId = user.Id,
            PasskeyRequiresSecondFactor = secondFactor,
            TotpEnabled = other is "totp" or "unverified",
            TotpVerified = other == "totp",
            Passkeys = { new PasskeyCredential { Id = "saved-key" } },
        };
        if (other is "recovery" or "spent-recovery") data.RecoveryCodes.Add(new RecoveryCode { Hash = "saved-code", Used = other == "spent-recovery" });
        if (other == "telegram") data.TelegramChatId = "123456";
        if (other == "sso") data.SsoLinks.Add(new SsoLink { ProviderId = "provider", Subject = "subject" });
        await Store.SaveUserDataAsync(data);
        return user.Id;
    }

    public void Dispose()
    {
        Client.Dispose(); _server.Dispose(); Score.Dispose(); Challenges.Dispose(); Store.Dispose();
        typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
    }
}

// Jellyfin reads the body inside its own action before calling UpdateConfiguration.
// This probe exercises that boundary without substituting a second parse in the filter.
[ApiController]
[Route("Plugins")]
public sealed class PasskeyConfigurationProbeController : ControllerBase
{
    [HttpPost("{pluginId:guid}/Configuration")]
    public async Task<IActionResult> Save(Guid pluginId)
    {
        var incoming = (PluginConfiguration?)await JsonSerializer.DeserializeAsync(Request.Body, typeof(PluginConfiguration), JsonDefaults.Options)
            .ConfigureAwait(false);
        if (incoming is not null) Plugin.Instance!.UpdateConfiguration(incoming);
        return NoContent();
    }
}

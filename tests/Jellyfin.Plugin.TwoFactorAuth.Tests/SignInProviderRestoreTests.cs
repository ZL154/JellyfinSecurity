using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests
{
    /// <summary>
    /// Issue #213: an account moved onto TwoFactorAuthProvider (passkey sign-in, app
    /// password, OIDC bridge) could not sign in at all once the plugin was gone,
    /// because Jellyfin puts it on its InvalidAuthProvider. Uninstalling the plugin,
    /// or disabling it in the dashboard, now hands such accounts back to the
    /// provider the plugin was passing their passwords to, and lists them so the
    /// plugin's next start takes them back.
    /// </summary>
    public sealed class SignInProviderRestoreTests : IDisposable
    {
        private const string Ldap = "Jellyfin.Plugin.Ldap.LdapAuthenticationProvider";
        private const string Target = SignInProviderRestore.JellyfinDefaultProviderId;
        private static readonly string Ours = SignInProviderRestore.PluginProviderId;
        private static readonly Guid PluginGuid = new("94879a0c-da24-4eb1-aa06-f28b4b9333b1");

        private readonly string _dir = Directory.CreateTempSubdirectory("sec213-").FullName;
        private readonly IApplicationPaths _paths = Substitute.For<IApplicationPaths>();

        public SignInProviderRestoreTests()
        {
            _paths.PluginConfigurationsPath.Returns(_dir);
        }

        private string RecordPath => SignInProviderRestore.RecordPath(_paths);

        public void Dispose() => Directory.Delete(_dir, recursive: true);

        [Fact]
        public async Task Moves_only_the_accounts_on_this_plugins_provider()
        {
            var bound = new User("bound", Ours, "reset");
            var admin = new User("admin", Ours, "reset");
            var plain = new User("plain", Target, "reset");
            var ldap = new User("ldap", Ldap, "reset");
            var saved = new List<string>();

            var handedBack = await SignInProviderRestore.RestoreAsync(
                new[] { bound, admin, plain, ldap },
                Target,
                user => { saved.Add(user.Username); return Task.CompletedTask; },
                "Uninstall",
                NullLogger.Instance);

            Assert.Equal(new[] { "bound", "admin" }, handedBack.Select(u => u.Username));
            Assert.Equal(new[] { "bound", "admin" }, saved);
            Assert.Equal(Target, bound.AuthenticationProviderId);
            Assert.Equal(Target, admin.AuthenticationProviderId);
            Assert.Equal(Target, plain.AuthenticationProviderId);
            Assert.Equal(Ldap, ldap.AuthenticationProviderId);
        }

        [Fact]
        public async Task A_provider_id_in_another_case_is_still_this_plugins()
        {
            // Jellyfin matches provider ids ignoring case, so an account stored
            // this way is locked out just the same once the plugin is gone.
            var shouted = new User("shouted", Ours.ToUpperInvariant(), "reset");

            var handedBack = await SignInProviderRestore.RestoreAsync(
                new[] { shouted }, Target, _ => Task.CompletedTask, "Uninstall", NullLogger.Instance);

            Assert.Single(handedBack);
            Assert.Equal(Target, shouted.AuthenticationProviderId);
        }

        [Fact]
        public async Task A_failed_save_does_not_stop_the_others_or_leave_that_account_half_changed()
        {
            var first = new User("first", Ours, "reset");
            var second = new User("second", Ours, "reset");

            var handedBack = await SignInProviderRestore.RestoreAsync(
                new[] { first, second },
                Target,
                user => user.Username == "first"
                    ? Task.FromException(new InvalidOperationException("database is locked"))
                    : Task.CompletedTask,
                "Uninstall",
                NullLogger.Instance);

            Assert.Equal(new[] { second }, handedBack);
            Assert.Equal(Ours, first.AuthenticationProviderId);
            Assert.Equal(Target, second.AuthenticationProviderId);
        }

        [Fact]
        public void Target_is_the_first_enabled_provider_that_is_not_this_plugins()
        {
            var ours = (IAuthenticationProvider)RuntimeHelpers.GetUninitializedObject(typeof(TwoFactorAuthProvider));

            var target = SignInProviderRestore.DelegateProviderId(
                new IAuthenticationProvider[] { ours, new DisabledProvider(), new EnabledProvider() });

            Assert.Equal(typeof(EnabledProvider).FullName, target);
        }

        [Fact]
        public void Target_falls_back_to_Jellyfins_own_provider_when_nothing_else_is_registered()
        {
            var ours = (IAuthenticationProvider)RuntimeHelpers.GetUninitializedObject(typeof(TwoFactorAuthProvider));

            Assert.Equal(Target, SignInProviderRestore.DelegateProviderId(new[] { ours }));
        }

        [Fact]
        public void Target_uses_the_same_rule_as_the_provider_that_checks_the_password()
        {
            // An account moved back keeps signing in against the same credentials
            // only while both pick the provider the same way.
            const string rule = "FirstOrDefault(p => p is not TwoFactorAuthProvider && p.IsEnabled)";
            Assert.Contains(rule, SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorAuthProvider.cs"), StringComparison.Ordinal);
            Assert.Contains(rule, SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/SignInProviderRestore.cs"), StringComparison.Ordinal);
        }

        [Fact]
        public void Plugin_hands_the_accounts_back_when_it_is_uninstalled()
        {
            var method = typeof(Plugin).GetMethod(nameof(Plugin.OnUninstalling))!;
            Assert.Equal(typeof(Plugin), method.DeclaringType);
            Assert.Contains(
                "SignInProviderRestore.RestoreOnUninstall(_appHost, ApplicationPaths, _logger);",
                SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Plugin.cs"),
                StringComparison.Ordinal);
        }

        [Fact]
        public void Plugin_resolves_the_user_manager_lazily()
        {
            // Asking for IUserManager in the constructor would build the user
            // manager, and every authentication provider with it, while Jellyfin is
            // still creating plugins.
            var parameters = typeof(Plugin).GetConstructors().Single().GetParameters();
            Assert.DoesNotContain(parameters, p => p.ParameterType == typeof(IUserManager));
            Assert.Contains(parameters, p => p.ParameterType == typeof(IApplicationHost));
        }

        [Fact]
        public void The_admin_endpoints_and_the_restore_share_one_user_enumeration()
        {
            Assert.Contains(
                "private IEnumerable<User> EnumerateAllUsers() => UserEnumeration.All(_userManager);",
                SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Api/TwoFactorAuthController.cs"),
                StringComparison.Ordinal);
            Assert.Contains(
                "UserEnumeration.All(userManager)",
                SourceFile("src/Jellyfin.Plugin.TwoFactorAuth/Services/SignInProviderRestore.cs"),
                StringComparison.Ordinal);
        }

        [Fact]
        public void Uninstall_lists_the_accounts_it_handed_back()
        {
            var bound = new User("bound", Ours, "reset");
            var admin = new User("admin", Ours, "reset");
            var plain = new User("plain", Target, "reset");
            var (appHost, userManager) = Host(bound, admin, plain);

            SignInProviderRestore.RestoreOnUninstall(appHost, _paths, NullLogger.Instance);

            Assert.Equal(Target, bound.AuthenticationProviderId);
            Assert.Equal(Target, admin.AuthenticationProviderId);
            userManager.Received(1).UpdateUserAsync(bound);
            userManager.Received(1).UpdateUserAsync(admin);
            userManager.DidNotReceive().UpdateUserAsync(plain);
            var listed = SignInProviderRestore.ReadPending(RecordPath, NullLogger.Instance);
            Assert.Equal(new[] { bound.Id, admin.Id }, listed.Select(e => e.UserId));
            Assert.All(listed, e => Assert.Equal(Target, e.Provider));
        }

        [Fact]
        public void Uninstall_with_nothing_to_hand_back_writes_no_list()
        {
            var (appHost, _) = Host(new User("plain", Target, "reset"));

            SignInProviderRestore.RestoreOnUninstall(appHost, _paths, NullLogger.Instance);

            Assert.False(File.Exists(RecordPath));
        }

        [Fact]
        public void Uninstall_keeps_the_accounts_an_earlier_hand_back_listed()
        {
            // A start whose save failed leaves an entry to retry; a second hand-back
            // before that retry must not drop it.
            var waiting = new HandedBackAccount { UserId = Guid.NewGuid(), Provider = Target };
            SignInProviderRestore.WritePending(RecordPath, new[] { waiting });
            var bound = new User("bound", Ours, "reset");
            var (appHost, _) = Host(bound);

            SignInProviderRestore.RestoreOnUninstall(appHost, _paths, NullLogger.Instance);

            var listed = SignInProviderRestore.ReadPending(RecordPath, NullLogger.Instance);
            Assert.Equal(new[] { waiting.UserId, bound.Id }, listed.Select(e => e.UserId));
        }

        [Fact]
        public async Task A_start_takes_back_only_the_accounts_still_where_they_were_handed_back()
        {
            var waiting = new User("waiting", Target, "reset");
            var movedToLdap = new User("ldap", Ldap, "reset");
            var deletedId = Guid.NewGuid();
            var byId = new Dictionary<Guid, User> { [waiting.Id] = waiting, [movedToLdap.Id] = movedToLdap };
            var saved = new List<string>();

            var remaining = await SignInProviderRestore.ReclaimAsync(
                new[]
                {
                    new HandedBackAccount { UserId = waiting.Id, Provider = Target },
                    new HandedBackAccount { UserId = movedToLdap.Id, Provider = Target },
                    new HandedBackAccount { UserId = deletedId, Provider = Target },
                },
                id => byId.GetValueOrDefault(id),
                user => { saved.Add(user.Username); return Task.CompletedTask; },
                NullLogger.Instance);

            Assert.Empty(remaining);
            Assert.Equal(new[] { "waiting" }, saved);
            Assert.Equal(Ours, waiting.AuthenticationProviderId);
            Assert.Equal(Ldap, movedToLdap.AuthenticationProviderId);
        }

        [Fact]
        public async Task A_failed_take_back_stays_listed_and_leaves_the_account_unchanged()
        {
            var first = new User("first", Target, "reset");
            var second = new User("second", Target, "reset");
            var byId = new Dictionary<Guid, User> { [first.Id] = first, [second.Id] = second };
            var firstEntry = new HandedBackAccount { UserId = first.Id, Provider = Target };

            var remaining = await SignInProviderRestore.ReclaimAsync(
                new[] { firstEntry, new HandedBackAccount { UserId = second.Id, Provider = Target } },
                id => byId.GetValueOrDefault(id),
                user => user.Username == "first"
                    ? Task.FromException(new InvalidOperationException("database is locked"))
                    : Task.CompletedTask,
                NullLogger.Instance);

            Assert.Equal(new[] { firstEntry }, remaining);
            Assert.Equal(Target, first.AuthenticationProviderId);
            Assert.Equal(Ours, second.AuthenticationProviderId);
        }

        [Fact]
        public async Task The_startup_service_takes_them_back_and_removes_the_list()
        {
            var bound = new User("bound", Ours, "reset");
            var (appHost, userManager) = Host(bound);
            SignInProviderRestore.RestoreOnUninstall(appHost, _paths, NullLogger.Instance);
            Assert.Equal(Target, bound.AuthenticationProviderId);

            await new SignInProviderReclaimService(userManager, _paths, NullLogger<SignInProviderReclaimService>.Instance)
                .StartAsync(CancellationToken.None);

            Assert.Equal(Ours, bound.AuthenticationProviderId);
            Assert.False(File.Exists(RecordPath));
        }

        [Fact]
        public async Task A_failed_lookup_keeps_the_list_for_the_next_start()
        {
            var entry = new HandedBackAccount { UserId = Guid.NewGuid(), Provider = Target };
            SignInProviderRestore.WritePending(RecordPath, new[] { entry });
            var before = File.ReadAllText(RecordPath);
            var userManager = Substitute.For<IUserManager>();
            userManager.GetUserById(Arg.Any<Guid>()).Returns(_ => throw new InvalidOperationException("database is locked"));

            await SignInProviderRestore.ReclaimAtStartAsync(userManager, _paths, NullLogger.Instance);

            Assert.Equal(before, File.ReadAllText(RecordPath));
        }

        [Fact]
        public async Task A_list_that_is_not_json_is_dropped_without_touching_anyone()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(RecordPath)!);
            File.WriteAllText(RecordPath, "{ not json");
            var userManager = Substitute.For<IUserManager>();

            await SignInProviderRestore.ReclaimAtStartAsync(userManager, _paths, NullLogger.Instance);

            Assert.False(File.Exists(RecordPath));
            userManager.DidNotReceiveWithAnyArgs().GetUserById(default);
        }

        [Fact]
        public async Task Without_a_list_a_start_touches_no_account()
        {
            var userManager = Substitute.For<IUserManager>();

            await SignInProviderRestore.ReclaimAtStartAsync(userManager, _paths, NullLogger.Instance);

            userManager.DidNotReceiveWithAnyArgs().GetUserById(default);
            Assert.False(File.Exists(RecordPath));
        }

        [Fact]
        public void The_take_back_runs_as_a_startup_service()
        {
            var services = new ServiceCollection();

            new PluginServiceRegistrator().RegisterServices(services, Substitute.For<IServerApplicationHost>());

            Assert.Contains(
                services,
                d => d.ServiceType == typeof(IHostedService) && d.ImplementationType == typeof(SignInProviderReclaimService));
        }

        [Fact]
        public async Task Disabling_this_plugin_in_the_dashboard_hands_the_accounts_back()
        {
            var bound = new User("bound", Ours, "reset");
            var (appHost, _) = Host(bound);

            await DisableFilter(appHost).OnActionExecutionAsync(DisableRequest(PluginGuid), Answer(new NoContentResult()));

            Assert.Equal(Target, bound.AuthenticationProviderId);
            Assert.Equal(
                new[] { bound.Id },
                SignInProviderRestore.ReadPending(RecordPath, NullLogger.Instance).Select(e => e.UserId));
        }

        [Fact]
        public async Task A_disable_Jellyfin_refused_hands_nothing_back()
        {
            var bound = new User("bound", Ours, "reset");
            var (appHost, _) = Host(bound);

            await DisableFilter(appHost).OnActionExecutionAsync(DisableRequest(PluginGuid), Answer(new NotFoundResult()));

            Assert.Equal(Ours, bound.AuthenticationProviderId);
            Assert.False(File.Exists(RecordPath));
        }

        [Fact]
        public async Task Disabling_another_plugin_hands_nothing_back()
        {
            var bound = new User("bound", Ours, "reset");
            var (appHost, _) = Host(bound);

            await DisableFilter(appHost).OnActionExecutionAsync(DisableRequest(Guid.NewGuid()), Answer(new NoContentResult()));

            Assert.Equal(Ours, bound.AuthenticationProviderId);
        }

        [Fact]
        public async Task Enabling_this_plugin_hands_nothing_back()
        {
            var bound = new User("bound", Ours, "reset");
            var (appHost, _) = Host(bound);

            await DisableFilter(appHost).OnActionExecutionAsync(
                DisableRequest(PluginGuid, action: "EnablePlugin"), Answer(new NoContentResult()));

            Assert.Equal(Ours, bound.AuthenticationProviderId);
        }

        [Fact]
        public async Task A_DisablePlugin_action_on_another_controller_hands_nothing_back()
        {
            var bound = new User("bound", Ours, "reset");
            var (appHost, _) = Host(bound);

            await DisableFilter(appHost).OnActionExecutionAsync(
                DisableRequest(PluginGuid, controller: typeof(SignInProviderRestoreTests)), Answer(new NoContentResult()));

            Assert.Equal(Ours, bound.AuthenticationProviderId);
        }

        [Fact]
        public void The_disable_filter_matches_this_plugins_id()
        {
            // The filter keeps its own copy of the id; this pins it to Plugin.Id.
            var plugin = (Plugin)RuntimeHelpers.GetUninitializedObject(typeof(Plugin));

            Assert.Equal(plugin.Id, PluginGuid);
        }

        [Fact]
        public void The_disable_filter_runs_on_every_controller_action()
        {
            var options = new MvcOptions();

            new PluginMvcOptionsSetup().Configure(options);

            Assert.Contains(
                options.Filters,
                f => f is TypeFilterAttribute t && t.ImplementationType == typeof(PluginDisableHandBackFilter));
        }

        private PluginDisableHandBackFilter DisableFilter(IApplicationHost appHost)
            => new(appHost, _paths, NullLogger<PluginDisableHandBackFilter>.Instance);

        private static ActionExecutingContext DisableRequest(Guid pluginId, string action = "DisablePlugin", Type? controller = null)
        {
            var descriptor = new ControllerActionDescriptor
            {
                ControllerTypeInfo = (controller ?? typeof(global::Jellyfin.Api.Controllers.PluginsController)).GetTypeInfo(),
                ControllerName = "Plugins",
                ActionName = action,
            };

            return new ActionExecutingContext(
                new ActionContext(new DefaultHttpContext(), new RouteData(), descriptor),
                new List<IFilterMetadata>(),
                new Dictionary<string, object?> { ["pluginId"] = pluginId, ["version"] = new Version(2, 6, 1, 0) },
                controller: new object());
        }

        private static ActionExecutionDelegate Answer(IActionResult result)
            => () => Task.FromResult(new ActionExecutedContext(
                new ActionContext(new DefaultHttpContext(), new RouteData(), new ControllerActionDescriptor()),
                new List<IFilterMetadata>(),
                controller: new object())
            {
                Result = result,
            });

        private static (IApplicationHost AppHost, IUserManager UserManager) Host(params User[] users)
        {
            var userManager = Substitute.For<IUserManager>();
            userManager.GetUsers().Returns(users.ToList());
            foreach (var user in users)
            {
                userManager.GetUserById(user.Id).Returns(user);
            }

            userManager.UpdateUserAsync(Arg.Any<User>()).Returns(Task.CompletedTask);

            var ours = (IAuthenticationProvider)RuntimeHelpers.GetUninitializedObject(typeof(TwoFactorAuthProvider));
            var appHost = Substitute.For<IApplicationHost>();
            appHost.Resolve<IUserManager>().Returns(userManager);
            appHost.GetExports<IAuthenticationProvider>(false).Returns(new[] { ours });
            return (appHost, userManager);
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

        private sealed class DisabledProvider : FakeProvider
        {
            public override bool IsEnabled => false;
        }

        private sealed class EnabledProvider : FakeProvider
        {
            public override bool IsEnabled => true;
        }

        private abstract class FakeProvider : IAuthenticationProvider
        {
            public string Name => GetType().Name;

            public abstract bool IsEnabled { get; }

            public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
                => throw new NotSupportedException();

            public bool HasPassword(User user) => true;

            public Task ChangePassword(User user, string newPassword) => throw new NotSupportedException();
        }
    }
}

namespace Jellyfin.Api.Controllers
{
    /// <summary>
    /// Stand-in with the full name of Jellyfin's own controller, which the plugin
    /// does not reference; PluginDisableHandBackFilter matches on that name.
    /// </summary>
    internal sealed class PluginsController
    {
    }
}

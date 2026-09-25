using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Issue #213: an account moved onto TwoFactorAuthProvider (passkey sign-in, app
/// password, OIDC bridge) could not sign in at all once the plugin was gone,
/// because Jellyfin puts it on its InvalidAuthProvider. Uninstalling now hands
/// such accounts back to the provider the plugin was passing their passwords to.
/// </summary>
public class SignInProviderRestoreTests
{
    private const string Ldap = "Jellyfin.Plugin.Ldap.LdapAuthenticationProvider";
    private const string Target = SignInProviderRestore.JellyfinDefaultProviderId;
    private static readonly string Ours = SignInProviderRestore.PluginProviderId;

    [Fact]
    public async Task Moves_only_the_accounts_on_this_plugins_provider()
    {
        var bound = new User("bound", Ours, "reset");
        var admin = new User("admin", Ours, "reset");
        var plain = new User("plain", Target, "reset");
        var ldap = new User("ldap", Ldap, "reset");
        var saved = new List<string>();

        var restored = await SignInProviderRestore.RestoreAsync(
            new[] { bound, admin, plain, ldap },
            Target,
            user => { saved.Add(user.Username); return Task.CompletedTask; },
            NullLogger.Instance);

        Assert.Equal(2, restored);
        Assert.Equal(new[] { "bound", "admin" }, saved);
        Assert.Equal(Target, bound.AuthenticationProviderId);
        Assert.Equal(Target, admin.AuthenticationProviderId);
        Assert.Equal(Target, plain.AuthenticationProviderId);
        Assert.Equal(Ldap, ldap.AuthenticationProviderId);
    }

    [Fact]
    public async Task A_failed_save_does_not_stop_the_others_or_leave_that_account_half_changed()
    {
        var first = new User("first", Ours, "reset");
        var second = new User("second", Ours, "reset");

        var restored = await SignInProviderRestore.RestoreAsync(
            new[] { first, second },
            Target,
            user => user.Username == "first"
                ? Task.FromException(new InvalidOperationException("database is locked"))
                : Task.CompletedTask,
            NullLogger.Instance);

        Assert.Equal(1, restored);
        Assert.Equal(Ours, first.AuthenticationProviderId);
        Assert.Equal(Target, second.AuthenticationProviderId);
    }

    [Fact]
    public void Target_is_the_first_enabled_provider_that_is_not_this_plugins()
    {
        var ours = (IAuthenticationProvider)RuntimeHelpers.GetUninitializedObject(typeof(TwoFactorAuthProvider));

        var target = SignInProviderRestore.PasswordProviderId(
            new IAuthenticationProvider[] { ours, new DisabledProvider(), new EnabledProvider() });

        Assert.Equal(typeof(EnabledProvider).FullName, target);
    }

    [Fact]
    public void Target_falls_back_to_Jellyfins_own_provider_when_nothing_else_is_registered()
    {
        var ours = (IAuthenticationProvider)RuntimeHelpers.GetUninitializedObject(typeof(TwoFactorAuthProvider));

        Assert.Equal(Target, SignInProviderRestore.PasswordProviderId(new[] { ours }));
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
            "SignInProviderRestore.RestoreOnUninstall(_appHost, _logger);",
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

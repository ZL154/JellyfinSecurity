using System.Reflection;
using System.Reflection.Emit;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Jellyfin.Server.Implementations.Users;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[Collection("SignInPolicy")]
public sealed class AccountPasswordSignInTests : IDisposable
{
    private readonly IApplicationHost _host = Substitute.For<IApplicationHost>();
    private readonly Plugin? _previous = Plugin.Instance;
    private readonly Plugin _plugin;
    private readonly string _directory;
    private readonly User _user = new("member", SignInProviderRestore.PluginProviderId, "reset");
    private static readonly Type Own = typeof(TwoFactorAuthProvider);
    private static readonly Type BuiltIn = HostProviderIdentityFixture.PasswordProvider;
    private static readonly Type Invalid = HostProviderIdentityFixture.InvalidProvider;

    public AccountPasswordSignInTests()
    {
        var paths = TestApplicationPaths.Create(out _directory);
        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        _plugin = new Plugin(paths, serializer, _host, NullLogger<Plugin>.Instance);
        _plugin.Configuration.Enabled = true;
        _plugin.Configuration.BlockEmptyPasswordLogin = true;
        SetProviders(Own, BuiltIn);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("   ", false)]
    [InlineData("stored-value", false)]
    public void Only_a_null_or_empty_stored_password_qualifies(string? password, bool expected)
    {
        _user.Password = password;
        Assert.Equal(expected, _plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void The_current_password_and_both_configuration_gates_are_read_on_each_decision()
    {
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
        _user.Password = "newly-set";
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        _user.Password = null;
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
        _plugin.Configuration.BlockEmptyPasswordLogin = false;
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        _plugin.Configuration.BlockEmptyPasswordLogin = true;
        _plugin.Configuration.Enabled = false;
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void An_unresolved_account_keeps_its_challenge()
    {
        Assert.False(_plugin.AccountPasswordSignInUnavailable(null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Unknown.Provider")]
    [InlineData(SignInProviderRestore.JellyfinDefaultProviderId)]
    public void The_account_must_be_explicitly_assigned_to_the_plugin(string? providerId)
    {
        _user.AuthenticationProviderId = providerId!;
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void The_explicit_plugin_assignment_is_case_insensitive()
    {
        _user.AuthenticationProviderId = SignInProviderRestore.PluginProviderId.ToUpperInvariant();
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void Discovery_never_constructs_providers_and_skips_the_hosts_disabled_provider_in_any_position()
    {
        SetProviders(Own, BuiltIn, Invalid);
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders(Invalid, BuiltIn, Own);
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
        _host.DidNotReceiveWithAnyArgs().GetExports<IAuthenticationProvider>(false);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Any_external_type_keeps_the_challenge_even_if_construction_omits_it(bool externalFirst)
    {
        // Simulate a host that silently omitted an external provider from its instance exports.
        var external = Substitute.For<IAuthenticationProvider>().GetType();
        var ownInstance = (TwoFactorAuthProvider)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(Own);
        _host.GetExports<IAuthenticationProvider>(false).Returns(new IAuthenticationProvider[] { ownInstance, new DefaultAuthenticationProvider() });
        SetProviders(externalFirst ? [Own, external, BuiltIn] : [Own, BuiltIn, external]);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        _user.AuthenticationProviderId = external.FullName!;
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        _host.DidNotReceiveWithAnyArgs().GetExports<IAuthenticationProvider>(false);
    }

    [Fact]
    public void Namesakes_cannot_stand_in_for_the_real_provider_types()
    {
        SetProviders(Own, typeof(DefaultAuthenticationProvider));
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders(HostProviderIdentityFixture.PluginNamesake, BuiltIn);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders(Own, BuiltIn, HostProviderIdentityFixture.InvalidNamesake);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void Missing_duplicate_or_incomplete_provider_lists_keep_the_challenge()
    {
        foreach (var types in new Type[][]
        {
            [], [BuiltIn], [Own], [Own, Invalid], [Own, Own, BuiltIn], [Own, BuiltIn, BuiltIn],
            [Own, BuiltIn, Invalid, Invalid], [Own, BuiltIn, null!],
        })
        {
            SetProviders(types);
            Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        }
    }

    [Fact]
    public void A_discovery_failure_after_the_expected_types_keeps_the_challenge()
    {
        static IEnumerable<Type> Incomplete()
        {
            yield return Own;
            yield return BuiltIn;
            throw new InvalidOperationException();
        }

        _host.GetExportTypes<IAuthenticationProvider>().Returns(_ => Incomplete());
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    private void SetProviders(params Type[] types)
        => _host.GetExportTypes<IAuthenticationProvider>().Returns(types);

    public void Dispose()
    {
        typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
        Directory.Delete(_directory, recursive: true);
    }
}

/// <summary>Provides concrete CLR type identities for the server assembly, which the
/// plugin's test project does not reference. Only type discovery is meaningful here.</summary>
public abstract class HostProviderIdentityFixture : IAuthenticationProvider
{
    internal static readonly Type PasswordProvider;
    internal static readonly Type InvalidProvider;
    internal static readonly Type PluginNamesake;
    internal static readonly Type InvalidNamesake;

    static HostProviderIdentityFixture()
    {
        var host = CreateModule("Jellyfin.Server.Implementations");
        var extension = CreateModule("NamesakeExtension");
        const string invalidName = "Jellyfin.Server.Implementations.Users.InvalidAuthProvider";
        PasswordProvider = DefineProvider(host, SignInProviderRestore.JellyfinDefaultProviderId);
        InvalidProvider = DefineProvider(host, invalidName);
        InvalidNamesake = DefineProvider(extension, invalidName);
        PluginNamesake = DefineProvider(extension, SignInProviderRestore.PluginProviderId);
    }

    private static ModuleBuilder CreateModule(string name)
        => AssemblyBuilder.DefineDynamicAssembly(new AssemblyName(name), AssemblyBuilderAccess.Run).DefineDynamicModule(name);

    private static Type DefineProvider(ModuleBuilder module, string fullName)
        => module.DefineType(fullName, TypeAttributes.Public | TypeAttributes.Sealed, typeof(HostProviderIdentityFixture)).CreateType()!;

    protected HostProviderIdentityFixture() => throw new NotSupportedException();
    public string Name => throw new NotSupportedException();
    public bool IsEnabled => throw new NotSupportedException();
    public bool HasPassword(User user) => throw new NotSupportedException();
    public Task ChangePassword(User user, string newPassword) => throw new NotSupportedException();
    public Task<ProviderAuthenticationResult> Authenticate(string username, string password) => throw new NotSupportedException();
}

using System.Runtime.CompilerServices;
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
    private readonly IAuthenticationProvider _own =
        (TwoFactorAuthProvider)RuntimeHelpers.GetUninitializedObject(typeof(TwoFactorAuthProvider));
    private readonly DefaultAuthenticationProvider _builtIn = new();

    public AccountPasswordSignInTests()
    {
        var paths = TestApplicationPaths.Create(out _directory);
        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(typeof(PluginConfiguration), Arg.Any<string>()).Returns(new PluginConfiguration());
        _plugin = new Plugin(paths, serializer, _host, NullLogger<Plugin>.Instance);
        _plugin.Configuration.Enabled = true;
        _plugin.Configuration.BlockEmptyPasswordLogin = true;
        SetProviders(_own, _builtIn);
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
    public void An_account_assigned_to_an_installed_external_provider_keeps_its_challenge()
    {
        var external = Substitute.For<IAuthenticationProvider>();
        external.IsEnabled.Returns(true);
        SetProviders(_own, _builtIn, external);
        _user.AuthenticationProviderId = external.GetType().FullName!;
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void Delegation_follows_the_current_order_of_enabled_providers()
    {
        var external = Substitute.For<IAuthenticationProvider>();
        external.IsEnabled.Returns(true);
        SetProviders(_builtIn, external, _own);
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders(_own, external, _builtIn);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        external.IsEnabled.Returns(false);
        Assert.True(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders(_own, external);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void Both_the_assigned_plugin_and_its_delegate_must_be_installed()
    {
        SetProviders(_builtIn);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders(_own);
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
        SetProviders();
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    [Fact]
    public void A_failed_provider_lookup_keeps_the_challenge()
    {
        _host.GetExports<IAuthenticationProvider>(false).Returns(_ => throw new InvalidOperationException());
        Assert.False(_plugin.AccountPasswordSignInUnavailable(_user));
    }

    private void SetProviders(params IAuthenticationProvider[] providers)
        => _host.GetExports<IAuthenticationProvider>(false).Returns(providers);

    public void Dispose()
    {
        typeof(Plugin).GetProperty(nameof(Plugin.Instance))!.SetValue(null, _previous);
        Directory.Delete(_directory, recursive: true);
    }
}

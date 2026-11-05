using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Authentication;

namespace Jellyfin.Server.Implementations.Users;

/// <summary>Stands in for Jellyfin's own password provider. It carries the
/// same full type name, which is how the plugin recognizes that provider
/// (SignInProviderRestore.JellyfinDefaultProviderId), and accepts one
/// password per account, like the real one.</summary>
internal sealed class DefaultAuthenticationProvider : IAuthenticationProvider, IRequiresResolvedUser
{
    private readonly Dictionary<Guid, string> _passwords = new();

    /// <summary>How many times a password was checked.</summary>
    public int Checks { get; private set; }

    public string Name => "Default";

    public bool IsEnabled => true;

    public void SetPassword(User user, string password) => _passwords[user.Id] = password;

    public Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        => throw new NotImplementedException();

    public Task<ProviderAuthenticationResult> Authenticate(string username, string password, User? resolvedUser)
    {
        Checks++;
        if (resolvedUser is null
            || !_passwords.TryGetValue(resolvedUser.Id, out var expected)
            || !string.Equals(expected, password, StringComparison.Ordinal))
        {
            throw new AuthenticationException("Invalid username or password");
        }

        return Task.FromResult(new ProviderAuthenticationResult { Username = username });
    }

    public bool HasPassword(User user) => _passwords.ContainsKey(user.Id);

    public Task ChangePassword(User user, string newPassword)
    {
        _passwords[user.Id] = newPassword;
        return Task.CompletedTask;
    }
}

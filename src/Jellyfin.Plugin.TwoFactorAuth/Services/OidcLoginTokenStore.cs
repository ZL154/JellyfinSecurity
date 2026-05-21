using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>One-shot bridge tokens that turn a successful OIDC callback into a
/// real Jellyfin session. The OIDC flow runs entirely server-side and proves
/// the user is who they say — but Jellyfin's session manager only knows how
/// to mint sessions from username+password. So we mint a 60-second random
/// token, redirect the browser to the login page, and the page submits
/// username + token. Our IAuthenticationProvider recognises the token prefix,
/// validates it against this store, and signals success without any password
/// check.
///
/// Tokens are single-use (consumed on first match) and expire fast — replay
/// is impossible after either trigger.</summary>
public class OidcLoginTokenStore : IDisposable
{
    public const string TokenPrefix = "oidcbr_";

    private record Entry(Guid UserId, string Username, string ProviderId, bool BypassPluginTwoFa, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, Entry> _tokens = new();
    private readonly Timer _sweep;
    private bool _disposed;

    public OidcLoginTokenStore()
    {
        _sweep = new Timer(_ => Sweep(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing) _sweep.Dispose();
        _disposed = true;
    }

    public string Mint(Guid userId, string username, string providerId, TimeSpan? ttl = null, bool bypassPluginTwoFa = true)
    {
        var token = TokenPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        _tokens[token] = new Entry(userId, username, providerId, bypassPluginTwoFa,
            DateTime.UtcNow.Add(ttl ?? TimeSpan.FromSeconds(60)));
        return token;
    }

    /// <summary>Look up + atomically consume. Returns null if missing/expired.
    /// Username check guards against the rare case where the login form
    /// submits a different username than the one the IdP authenticated.</summary>
    public (Guid UserId, string ProviderId, bool BypassPluginTwoFa)? Consume(string token, string username)
    {
        if (!token.StartsWith(TokenPrefix, StringComparison.Ordinal)) return null;
        if (!_tokens.TryRemove(token, out var entry)) return null;
        if (entry.ExpiresAt <= DateTime.UtcNow) return null;
        if (!string.Equals(entry.Username, username, StringComparison.OrdinalIgnoreCase)) return null;
        return (entry.UserId, entry.ProviderId, entry.BypassPluginTwoFa);
    }

    public static bool LooksLikeBridgeToken(string? value)
        => !string.IsNullOrEmpty(value) && value.StartsWith(TokenPrefix, StringComparison.Ordinal);

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _tokens)
        {
            if (kv.Value.ExpiresAt <= now) _tokens.TryRemove(kv.Key, out _);
        }
    }
}

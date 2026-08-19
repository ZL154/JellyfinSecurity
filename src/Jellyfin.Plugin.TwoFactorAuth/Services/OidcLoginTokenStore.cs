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
        // SECURITY [v2.5.6] (third-audit F7): Ordinal not OrdinalIgnoreCase.
        // Mint stores the IdP-resolved username case-sensitively; case-
        // insensitive match would let `ADMIN` consume a token minted for
        // `admin` if both existed as distinct Jellyfin users.
        if (!string.Equals(entry.Username, username, StringComparison.Ordinal)) return null;
        return (entry.UserId, entry.ProviderId, entry.BypassPluginTwoFa);
    }

    public static bool LooksLikeBridgeToken(string? value)
        => !string.IsNullOrEmpty(value) && value.StartsWith(TokenPrefix, StringComparison.Ordinal);

    /// <summary>[v2.5.22] Non-consuming existence check for a bridge token.
    ///
    /// <see cref="LooksLikeBridgeToken"/> is a pure string-prefix test, which is
    /// the right shape for "should the provider try the bridge fast-path" but
    /// the WRONG shape for a security gate: any password beginning with
    /// <c>oidcbr_</c> satisfies it. LockoutMessageMiddleware used it to decide
    /// whether to waive DisablePasswordLogin, so a user could opt themselves
    /// out of the server-wide policy by choosing such a password.
    ///
    /// This asks the store instead, so only a token this server actually minted
    /// can waive the policy. Deliberately does NOT consume: the gate runs before
    /// the provider, which is the code that legitimately consumes the token, and
    /// consuming here would break every SSO sign-in.
    ///
    /// Deliberately does NOT check expiry either. An expired-but-real token
    /// should still reach the provider so the user gets its accurate "Invalid or
    /// expired sign-in token" error rather than a misleading "password sign-in
    /// is disabled". An attacker cannot forge an entry in this dictionary, so
    /// skipping the expiry check costs nothing: the provider's Consume still
    /// enforces both expiry and single-use.</summary>
    public bool IsKnownBridgeToken(string? value)
        => LooksLikeBridgeToken(value) && _tokens.ContainsKey(value!);

    // ---------------------------------------------------------------------
    // [v2.5.9] (issue #64): native/webview device-poll flow.
    //
    // Google blocks its OAuth consent inside embedded app webviews, and the
    // Jellyfin Android app can't receive an OAuth redirect back from an
    // external browser. So an app-initiated login routes the consent through
    // the system browser and the app's webview POLLS for completion:
    //   - Begin (in the app webview): map the OIDC `state` (which round-trips
    //     through the IdP and is known to the callback) to a high-entropy
    //     poll token kept ONLY in the app webview. The poll token never
    //     travels through the external browser, so the browser-visible
    //     `state` can't be used to steal the session.
    //   - Callback (in the external browser): stash the minted bridge token +
    //     resolved username under the flow.
    //   - Poll (in the app webview): one-shot pick-up, then the app completes
    //     login exactly like the browser bridge page (AuthenticateByName).
    private const string PollPrefix = "oidcpoll_";
    private const int MaxDeviceFlows = 2000;

    private sealed class DeviceEntry
    {
        public string PollToken = string.Empty;
        public string? Username;
        public string? BridgeToken;
        public DateTime ExpiresAt;
    }

    private readonly ConcurrentDictionary<string, DeviceEntry> _deviceByState = new();
    private readonly ConcurrentDictionary<string, DeviceEntry> _deviceByPoll = new();

    /// <summary>Start a device-poll flow for an app-initiated OIDC login.
    /// Returns the secret poll token the app webview keeps and polls with.</summary>
    public string BeginDeviceFlow(string state)
    {
        if (string.IsNullOrEmpty(state)) return string.Empty;
        PruneDeviceFlows();
        var pollToken = PollPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entry = new DeviceEntry
        {
            PollToken = pollToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        };
        _deviceByState[state] = entry;
        _deviceByPoll[pollToken] = entry;
        return pollToken;
    }

    public bool HasDeviceFlow(string state)
        => !string.IsNullOrEmpty(state) && _deviceByState.ContainsKey(state);

    /// <summary>Callback side: stash the minted bridge token + username for the
    /// polling app to pick up. Returns false if this wasn't a device flow.</summary>
    public bool CompleteDeviceFlow(string state, string username, string bridgeToken)
    {
        if (string.IsNullOrEmpty(state)) return false;
        if (!_deviceByState.TryGetValue(state, out var entry)) return false;
        entry.Username = username;
        entry.BridgeToken = bridgeToken;
        // [v2.5.12] (issue #64): window for the app to poll-pick the token after
        // the user manually returns from the system browser. Kept in lockstep
        // with the device-flow bridge-token TTL minted in the callback (3 min) —
        // if this window were longer than the token TTL, a slow return would
        // poll-pick a token that AuthenticateByName then rejects as expired
        // (the original 90s-vs-60s mismatch that 403'd app logins).
        entry.ExpiresAt = DateTime.UtcNow.AddMinutes(3);
        return true;
    }

    /// <summary>App poll: returns + one-shot-consumes (username, bridgeToken)
    /// once the browser side completed. Null while pending/unknown/expired.</summary>
    public (string Username, string BridgeToken)? PollDeviceFlow(string pollToken)
    {
        if (string.IsNullOrEmpty(pollToken)) return null;
        if (!_deviceByPoll.TryGetValue(pollToken, out var entry)) return null;
        if (entry.ExpiresAt <= DateTime.UtcNow)
        {
            RemoveDeviceFlow(entry);
            return null;
        }
        if (entry.BridgeToken is null || entry.Username is null) return null; // still pending
        var result = (entry.Username, entry.BridgeToken);
        RemoveDeviceFlow(entry); // one-shot
        return result;
    }

    private void RemoveDeviceFlow(DeviceEntry entry)
    {
        _deviceByPoll.TryRemove(entry.PollToken, out _);
        foreach (var kv in _deviceByState)
        {
            if (ReferenceEquals(kv.Value, entry))
            {
                _deviceByState.TryRemove(kv.Key, out _);
                break;
            }
        }
    }

    private void PruneDeviceFlows()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _deviceByPoll)
        {
            if (kv.Value.ExpiresAt <= now) RemoveDeviceFlow(kv.Value);
        }
        while (_deviceByPoll.Count >= MaxDeviceFlows)
        {
            DeviceEntry? oldest = null;
            foreach (var kv in _deviceByPoll)
            {
                if (oldest is null || kv.Value.ExpiresAt < oldest.ExpiresAt) oldest = kv.Value;
            }
            if (oldest is null) break;
            RemoveDeviceFlow(oldest);
        }
    }

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _tokens)
        {
            if (kv.Value.ExpiresAt <= now) _tokens.TryRemove(kv.Key, out _);
        }
        PruneDeviceFlows();
    }
}

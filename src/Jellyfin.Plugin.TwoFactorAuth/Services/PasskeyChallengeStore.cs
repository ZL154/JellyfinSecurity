using System;
using System.Collections.Concurrent;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Holds the FIDO2 server-side state between Begin and Finish for a single
/// passkey registration or authentication ceremony. Each entry is a chunk of
/// JSON (the `CredentialCreateOptions` or `AssertionOptions` produced by
/// Fido2NetLib at Begin time) that the Finish handler needs to validate the
/// browser's response. 5-minute TTL — same window the WebAuthn timeout uses
/// in the browser, so a longer server-side TTL would only hold dead state.
///
/// Keyed by a random base64url nonce returned to the browser at Begin and
/// re-submitted on Finish; the nonce never reaches public APIs.
/// </summary>
public class PasskeyChallengeStore : IDisposable
{
    private record Entry(string OptionsJson, Guid? UserId, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, Entry> _entries = new();
    private readonly Timer _cleanup;
    private bool _disposed;

    public PasskeyChallengeStore()
    {
        _cleanup = new Timer(_ => Sweep(), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
    }

    /// <summary>Stash the Begin-side state. Returns a nonce the browser sends
    /// back on Finish. UserId is optional — passkey assertion doesn't yet know
    /// which user; registration does.</summary>
    public string Begin(string optionsJson, Guid? userId)
    {
        var nonce = NewNonce();
        _entries[nonce] = new Entry(optionsJson, userId, DateTime.UtcNow.AddMinutes(5));
        return nonce;
    }

    /// <summary>Atomically remove and return the stashed options. Returns
    /// (null, null) if the nonce is unknown or expired — both treat as failure
    /// at the call site.</summary>
    public (string? OptionsJson, Guid? UserId) Consume(string nonce)
    {
        if (string.IsNullOrEmpty(nonce)) return (null, null);
        if (!_entries.TryRemove(nonce, out var e)) return (null, null);
        if (e.ExpiresAt <= DateTime.UtcNow) return (null, null);
        return (e.OptionsJson, e.UserId);
    }

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _entries)
        {
            if (kv.Value.ExpiresAt <= now) _entries.TryRemove(kv.Key, out _);
        }
    }

    private static string NewNonce()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(24);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cleanup.Dispose();
        GC.SuppressFinalize(this);
    }
}

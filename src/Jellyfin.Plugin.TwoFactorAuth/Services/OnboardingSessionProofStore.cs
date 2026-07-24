using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Short-lived, single-use proof that the current OIDC provider session was
/// silently revalidated for the Jellyfin user on the SetPassword page.
/// Keeping the binding server-side prevents a forged query/fragment flag from
/// bypassing issue #135's provider-session check.
/// </summary>
public sealed class OnboardingSessionProofStore
{
    private sealed record Proof(Guid UserId, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, Proof> _proofs =
        new(StringComparer.Ordinal);

    public string Mint(Guid userId)
    {
        Sweep();
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        _proofs[token] = new Proof(userId, DateTime.UtcNow.AddMinutes(2));
        return token;
    }

    public bool Validate(Guid userId, string? token, bool consume)
    {
        if (string.IsNullOrWhiteSpace(token)
            || !_proofs.TryGetValue(token, out var proof)
            || proof.UserId != userId
            || proof.ExpiresAt <= DateTime.UtcNow)
        {
            if (!string.IsNullOrWhiteSpace(token))
            {
                _proofs.TryRemove(token, out _);
            }
            return false;
        }

        if (consume && !_proofs.TryRemove(token, out _))
        {
            return false;
        }

        return true;
    }

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        foreach (var item in _proofs)
        {
            if (item.Value.ExpiresAt <= now)
            {
                _proofs.TryRemove(item.Key, out _);
            }
        }
    }
}

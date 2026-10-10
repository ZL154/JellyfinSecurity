using System;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Replaces a user's authenticator without a moment where the account has no
/// second factor.
///
/// Rotation used to overwrite the secret and clear TotpVerified in one step.
/// From then until a confirmation the account counted as having no TOTP: a
/// password alone signed in, and the old authenticator had already stopped
/// working. The Setup page offered no confirmation step, so a user who closed
/// the tab stayed that way.
///
/// The new secret now waits next to the active one. The active secret keeps
/// signing the user in until a code from the new one is confirmed, and a
/// rotation that is never confirmed changes nothing and expires.
/// </summary>
internal static class TotpRotation
{
    /// <summary>How long a started rotation waits for a code from the new
    /// secret. Long enough to scan a QR and type a code.</summary>
    internal static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(10);

    /// <summary>Replay-cache key for codes from the pending secret. The
    /// rotation request itself spends a code from the active secret, and the
    /// cache tracks time steps, not secrets: under the user's own key a code
    /// from the new secret in that same 30 second window would be refused as
    /// a replay.</summary>
    internal static string ReplayKey(Guid userId) => "totp-rotation:" + userId.ToString("N");

    /// <summary>Stores <paramref name="encryptedSecret"/> as the pending
    /// secret. The active secret and TotpVerified are left as they are.</summary>
    internal static void Begin(UserTwoFactorData data, string encryptedSecret, DateTime utcNow)
    {
        data.PendingEncryptedTotpSecret = encryptedSecret;
        data.PendingTotpSecretIssuedAt = utcNow;
    }

    /// <summary>The pending secret, or null when there is none, it expired,
    /// or TOTP stopped being active after the rotation started.</summary>
    internal static string? PendingSecret(UserTwoFactorData data, DateTime utcNow)
    {
        if (string.IsNullOrEmpty(data.PendingEncryptedTotpSecret) || data.PendingTotpSecretIssuedAt is not { } issuedAt)
        {
            return null;
        }

        if (!data.TotpEnabled || !data.TotpVerified || utcNow - issuedAt > PendingLifetime)
        {
            return null;
        }

        return data.PendingEncryptedTotpSecret;
    }

    /// <summary>Makes <paramref name="confirmedSecret"/> the active secret,
    /// after the caller validated a code from it at
    /// <paramref name="acceptedStep"/>. Returns false, changing nothing, when
    /// the record no longer holds that pending secret: it was disabled, reset
    /// or rotated again between the read that validated the code and this
    /// write.</summary>
    internal static bool TryComplete(UserTwoFactorData data, string confirmedSecret, long acceptedStep, DateTime utcNow)
    {
        if (!string.Equals(PendingSecret(data, utcNow), confirmedSecret, StringComparison.Ordinal))
        {
            return false;
        }

        data.EncryptedTotpSecret = confirmedSecret;
        if (acceptedStep > data.LastUsedTotpStep)
        {
            data.LastUsedTotpStep = acceptedStep;
        }

        Clear(data);
        return true;
    }

    /// <summary>Drops a pending rotation. Called wherever the active secret
    /// is replaced or wiped, so an old rotation cannot be finished later.</summary>
    internal static void Clear(UserTwoFactorData data)
    {
        data.PendingEncryptedTotpSecret = null;
        data.PendingTotpSecretIssuedAt = null;
    }
}

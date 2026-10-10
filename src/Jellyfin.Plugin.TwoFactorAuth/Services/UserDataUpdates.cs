using System;
using System.Linq;
using Jellyfin.Plugin.TwoFactorAuth.Models;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Targeted changes to a user's record, meant to run inside
/// <see cref="UserTwoFactorStore.MutateAsync"/>.
///
/// The sign-in paths used to read the record, change a field on that copy and
/// write the whole copy back with <see cref="UserTwoFactorStore.SaveUserDataAsync"/>.
/// Whatever another request changed in between (a disable, a revoked device,
/// a language, a recovery code another sign-in had just spent) was written
/// over with the older values. Each method here changes only what its caller
/// means to change, on the record as it is under the store's lock.
/// </summary>
internal static class UserDataUpdates
{
    /// <summary>SEC-L1: cap on trusted devices per user. Authenticated users
    /// would otherwise grow the list without bound by repeatedly choosing
    /// "Trust this device"; 30 is about six times a typical browser count.</summary>
    internal const int MaxTrustedDevices = 30;

    /// <summary>Marks the recovery code with this hash used, if the record
    /// still has it unused. Returns false otherwise (another request spent
    /// it, or the codes were regenerated), and the sign-in must not accept
    /// the code then: checking it against an earlier copy is not enough to
    /// keep it single-use.</summary>
    internal static bool TryConsumeRecoveryCode(UserTwoFactorData data, string? hash, DateTime utcNow)
    {
        if (string.IsNullOrEmpty(hash))
        {
            return false;
        }

        var code = data.RecoveryCodes.FirstOrDefault(c =>
            !c.Used && string.Equals(c.Hash, hash, StringComparison.Ordinal));
        if (code is null)
        {
            return false;
        }

        code.Used = true;
        code.UsedAt = utcNow;
        return true;
    }

    /// <summary>Stores the re-encrypted TOTP secret, but only while the record
    /// still holds the ciphertext it was made from. A secret replaced or
    /// wiped in the meantime stays as it is, and an empty result never
    /// replaces a secret.</summary>
    internal static void ApplySecretUpgrade(UserTwoFactorData data, string from, string? to)
    {
        if (!string.IsNullOrEmpty(to)
            && string.Equals(data.EncryptedTotpSecret, from, StringComparison.Ordinal))
        {
            data.EncryptedTotpSecret = to;
        }
    }

    /// <summary>Raises the TOTP replay floor to <paramref name="acceptedStep"/>.
    /// Never lowers it, so a slower request cannot undo a newer step.</summary>
    internal static void RaiseReplayFloor(UserTwoFactorData data, long acceptedStep)
    {
        if (acceptedStep > data.LastUsedTotpStep)
        {
            data.LastUsedTotpStep = acceptedStep;
        }
    }

    /// <summary>Adds a trusted device, then applies <see cref="EnforceTrustedDeviceCap"/>.</summary>
    internal static void AddTrustedDevice(UserTwoFactorData data, TrustedDevice device)
    {
        data.TrustedDevices.Add(device);
        EnforceTrustedDeviceCap(data);
    }

    /// <summary>Drops the least recently used trusted devices beyond
    /// <see cref="MaxTrustedDevices"/>, so a device that was just added, the
    /// most recently used one, stays.</summary>
    internal static void EnforceTrustedDeviceCap(UserTwoFactorData data)
    {
        if (data.TrustedDevices.Count <= MaxTrustedDevices)
        {
            return;
        }

        data.TrustedDevices.Sort((a, b) => a.LastUsedAt.CompareTo(b.LastUsedAt));
        data.TrustedDevices.RemoveRange(0, data.TrustedDevices.Count - MaxTrustedDevices);
    }

    /// <summary>Records a use of a trusted device. Returns false when the
    /// record no longer exists, for example because the user revoked it while
    /// this request was running; the caller must then not trust the device.</summary>
    internal static bool TouchTrustedDevice(UserTwoFactorData data, string recordId, DateTime utcNow)
    {
        var record = data.TrustedDevices.FirstOrDefault(d =>
            string.Equals(d.Id, recordId, StringComparison.Ordinal));
        if (record is null)
        {
            return false;
        }

        record.LastUsedAt = utcNow;
        return true;
    }

    /// <summary>Removes the paired device with this record id and returns it,
    /// or returns null when there is none.</summary>
    internal static PairedDevice? RemovePairedDevice(UserTwoFactorData data, string id)
    {
        var target = data.PairedDevices.FirstOrDefault(p =>
            string.Equals(p.Id, id, StringComparison.Ordinal));
        if (target is not null)
        {
            data.PairedDevices.Remove(target);
        }

        return target;
    }
}

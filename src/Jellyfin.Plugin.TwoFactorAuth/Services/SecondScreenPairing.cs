using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#216] Remembers the device that a person deliberately approved on a
/// second screen.
///
/// Two sign-ins end that way and both used to forget the device the moment
/// they finished:
///   * the OIDC device flow, where a TV shows the login QR and the consent is
///     granted in the IdP on a phone. The bridge path only marks the device
///     pre-verified in <see cref="ChallengeStore"/>, which is in memory.
///   * QuickConnect, where the code shown on the TV is authorised from an
///     already signed-in device. That allowance is a one-shot with a
///     two-minute life, so the next session starts from zero again.
///
/// A TV cannot render the challenge page, so "start from zero" is not a minor
/// cost there: it is the difference between watching something and not. This
/// writes the same <see cref="PairedDevice"/> record the Setup page's approval
/// flow writes, which the user can see, revoke, and mark as indefinitely
/// trusted when the admin allows it.
///
/// Recording is NOT granting. A paired device only waives 2FA while
/// <see cref="PluginConfiguration.BareDeviceIdBypassEnabled"/> is on, since a
/// bare DeviceId is client-supplied and not a secret. With that flag off (the
/// default) this changes what the user sees in their device list and nothing
/// about what the server accepts.
/// </summary>
public static class SecondScreenPairing
{
    /// <summary>Source tag for a pairing that came out of the OIDC device
    /// flow (the login QR). Sits alongside the "auto", "qr" and "manual"
    /// values the Setup page's approval paths write.</summary>
    public const string SourceOidc = "oidc";

    /// <summary>Source tag for a pairing that came out of a QuickConnect
    /// authorisation.</summary>
    public const string SourceQuickConnect = "quickconnect";

    /// <summary>Client-supplied names are trimmed to this before they are
    /// persisted, matching the cap the manual pairing endpoint applies to a
    /// user-typed label.</summary>
    private const int MaxNameLength = 80;

    /// <summary>A DeviceId longer than this is refused rather than stored: it
    /// cannot be anything Jellyfin issued, and the value lands in a file we
    /// read on every auth request.</summary>
    private const int MaxDeviceIdLength = 256;

    /// <summary>Whether this approval should produce a pairing record at all.
    /// Split out from the write so the decision can be read on its own.</summary>
    internal static bool ShouldPair(bool enabled, string? deviceId, IEnumerable<PairedDevice>? existing)
    {
        if (!enabled) return false;
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        if (deviceId!.Length > MaxDeviceIdLength) return false;
        return !IsAlreadyPaired(existing, deviceId);
    }

    /// <summary>Matches with <see cref="BypassEvaluator.DeviceIdMatches"/> so
    /// the Jellyfin Web UA-hash ids that carry a per-session suffix (Tizen,
    /// webOS) do not add a fresh row on every app restart.</summary>
    internal static bool IsAlreadyPaired(IEnumerable<PairedDevice>? existing, string? deviceId)
        => existing is not null
            && existing.Any(p => BypassEvaluator.DeviceIdMatches(p.DeviceId, deviceId));

    internal static PairedDevice BuildRecord(
        string deviceId,
        string? deviceName,
        string? appName,
        string? remoteIp,
        string source,
        DateTime utcNow) => new()
        {
            Id = Guid.NewGuid().ToString("N"),
            DeviceId = deviceId,
            DeviceName = Truncate(deviceName) ?? "Unknown device",
            AppName = Truncate(appName) ?? string.Empty,
            Source = source,
            CreatedAt = utcNow,
            LastUsedAt = utcNow,
            LastIp = remoteIp ?? string.Empty,
        };

    /// <summary>Pairs the device if the configuration asks for it and it is
    /// not paired already. Returns whether a new record was written.
    ///
    /// The duplicate check runs inside the mutation so two sign-ins racing
    /// each other cannot both add a row for the same device.</summary>
    public static async Task<bool> RecordAsync(
        UserTwoFactorStore store,
        PluginConfiguration? config,
        Guid userId,
        string username,
        string? deviceId,
        string? deviceName,
        string? appName,
        string? remoteIp,
        string source,
        ILogger logger,
        DateTime? utcNow = null)
    {
        if (config?.PairDeviceOnSecondScreenApproval != true) return false;
        if (string.IsNullOrWhiteSpace(deviceId) || deviceId!.Length > MaxDeviceIdLength) return false;

        var now = utcNow ?? DateTime.UtcNow;
        var added = false;

        await store.MutateAsync(userId, ud =>
        {
            var existing = ud.PairedDevices.FirstOrDefault(p =>
                BypassEvaluator.DeviceIdMatches(p.DeviceId, deviceId));
            if (existing is not null)
            {
                // The device did just sign in, so the row has to say so. The
                // bypass paths refresh this too, but only when the bypass is
                // enabled; without this, a TV that signs in every day would
                // show a months-old "last used" to the user deciding whether
                // to revoke it.
                existing.LastUsedAt = now;
                if (!string.IsNullOrEmpty(remoteIp)) existing.LastIp = remoteIp!;
                return;
            }

            ud.PairedDevices.Add(BuildRecord(deviceId, deviceName, appName, remoteIp, source, now));
            added = true;
        }).ConfigureAwait(false);

        if (!added) return false;

        await store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = now,
            UserId = userId,
            Username = username,
            RemoteIp = remoteIp ?? string.Empty,
            DeviceId = deviceId,
            DeviceName = Truncate(deviceName) ?? string.Empty,
            // Same result as the Setup page's pairing endpoints: this adds a
            // standing entry to the user's own security settings.
            Result = AuditResult.ConfigChanged,
            Method = "device_paired_" + source,
        }).ConfigureAwait(false);

        logger.LogInformation(
            "[2FA] Paired device {Device} for {User} after a second-screen approval ({Source})",
            deviceName, username, source);
        return true;
    }

    private static string? Truncate(string? value)
    {
        var trimmed = value?.Trim();
        if (string.IsNullOrEmpty(trimmed)) return null;
        return trimmed!.Length <= MaxNameLength ? trimmed : trimmed.Substring(0, MaxNameLength);
    }
}

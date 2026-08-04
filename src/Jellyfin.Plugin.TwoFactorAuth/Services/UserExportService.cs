using System;
using System.Linq;
using System.Threading.Tasks;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Per-user GDPR export. Returns JSON-friendly object describing
/// everything we have on file for one user — minus secrets (no TOTP seed,
/// no recovery code hashes, no public-key blobs, no token hashes).</summary>
public class UserExportService
{
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;

    public UserExportService(UserTwoFactorStore store, IUserManager userManager)
    {
        _store = store;
        _userManager = userManager;
    }

    /// <summary>[v2.5.21] (#156, MilesTEG1) Lightweight, non-sensitive summary
    /// for the admin Users table's inline "details" panel.
    ///
    /// That panel used to call BuildExportAsync via GET Users/{id}/Export,
    /// which is gated behind StepUpAction.ExportWithSecrets — so on any server
    /// with StepUpLevel >= Destructive, simply expanding a row 403'd and the UI
    /// printed "Failed to load details." The panel only ever rendered device
    /// labels and dates, so it never needed the full export.
    ///
    /// This returns strictly the fields the panel shows. Compared with the full
    /// export it deliberately omits the audit log, remote IPs, raw device ids,
    /// seen ASN/country contexts and the user's email — everything that made
    /// the export worth gating. What remains (device display names, passkey and
    /// app-password labels, timestamps) is no more sensitive than the counts
    /// already rendered in the same table, so admin authorization alone is the
    /// right bar.</summary>
    public async Task<object> BuildSummaryAsync(Guid userId)
    {
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        return new
        {
            userId = userId.ToString("D"),
            devices = new
            {
                trusted = data.TrustedDevices
                    .OrderByDescending(d => d.LastUsedAt)
                    .Select(d => new { deviceName = d.DeviceName, lastUsedAt = d.LastUsedAt })
                    .ToList(),
                paired = data.PairedDevices
                    .OrderByDescending(d => d.LastUsedAt)
                    .Select(d => new { deviceName = d.DeviceName, appName = d.AppName })
                    .ToList(),
            },
            twoFactor = new
            {
                passkeys = data.Passkeys
                    .OrderByDescending(p => p.CreatedAt)
                    .Select(p => new { label = p.Label, createdAt = p.CreatedAt })
                    .ToList(),
                appPasswords = data.AppPasswords
                    .OrderByDescending(a => a.CreatedAt)
                    .Select(a => new { label = a.Label, createdAt = a.CreatedAt })
                    .ToList(),
            },
        };
    }

    public async Task<object> BuildExportAsync(Guid userId)
    {
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var user = _userManager.GetUserById(userId);
        // SECURITY [v2.5.5] (Finding 18): hard-cap the audit-log fetch so a
        // very large configured AuditLogMaxEntries (or a long-running install
        // with deep history) doesn't load an unbounded JSON blob per export
        // call.
        var audit = await _store.GetAuditLogAsync(limit: 10_000).ConfigureAwait(false);
        var auditForUser = audit.Where(e => e.UserId == userId).ToList();
        var email = Plugin.Instance?.Configuration?.GetUserEmail(userId.ToString("N"));

        return new
        {
            schemaVersion = 1,
            exportedAt = DateTime.UtcNow,
            userId = userId.ToString("D"),
            username = user?.Username ?? string.Empty,
            email,
            twoFactor = new
            {
                totpEnabled = data.TotpEnabled,
                totpVerified = data.TotpVerified,
                emailOtpPreferred = data.EmailOtpPreferred,
                recoveryCodes = new
                {
                    total = data.RecoveryCodes.Count,
                    used = data.RecoveryCodes.Count(c => c.Used),
                    generatedAt = data.RecoveryCodesGeneratedAt,
                },
                passkeys = data.Passkeys.Select(p => new
                {
                    id = p.Id,
                    label = p.Label,
                    aaguid = p.Aaguid,
                    transports = p.Transports,
                    createdAt = p.CreatedAt,
                    lastUsedAt = p.LastUsedAt,
                }),
                appPasswords = data.AppPasswords.Select(a => new
                {
                    id = a.Id,
                    label = a.Label,
                    createdAt = a.CreatedAt,
                    lastUsedAt = a.LastUsedAt,
                    lastDeviceName = a.LastDeviceName,
                }),
            },
            devices = new
            {
                trusted = data.TrustedDevices.Select(d => new
                {
                    id = d.Id,
                    deviceId = d.DeviceId,
                    deviceName = d.DeviceName,
                    createdAt = d.CreatedAt,
                    lastUsedAt = d.LastUsedAt,
                }),
                paired = data.PairedDevices.Select(d => new
                {
                    id = d.Id,
                    deviceId = d.DeviceId,
                    deviceName = d.DeviceName,
                    appName = d.AppName,
                    source = d.Source,
                    createdAt = d.CreatedAt,
                    lastUsedAt = d.LastUsedAt,
                    lastIp = d.LastIp,
                }),
                registeredIds = data.RegisteredDeviceIds,
            },
            seenContexts = data.SeenContexts.Select(c => new
            {
                asn = c.Asn,
                country = c.Country,
                firstSeen = c.FirstSeen,
                lastSeen = c.LastSeen,
                requestCount = c.RequestCount,
            }),
            auditLog = auditForUser.Select(a => new
            {
                timestamp = a.Timestamp,
                result = a.Result.ToString(),
                method = a.Method,
                remoteIp = a.RemoteIp,
                deviceId = a.DeviceId,
                deviceName = a.DeviceName,
                details = a.Details,
            }),
        };
    }
}

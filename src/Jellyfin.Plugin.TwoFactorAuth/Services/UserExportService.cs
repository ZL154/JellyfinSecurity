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

    public async Task<object> BuildExportAsync(Guid userId)
    {
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var user = _userManager.GetUserById(userId);
        var audit = await _store.GetAuditLogAsync(limit: null).ConfigureAwait(false);
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

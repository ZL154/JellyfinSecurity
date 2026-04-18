using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Numbers for the admin "Overview" tab. Cheap derivation from the
/// per-user files plus the audit log — no new storage.</summary>
public class StatsService
{
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;

    public StatsService(UserTwoFactorStore store, IUserManager userManager)
    {
        _store = store;
        _userManager = userManager;
    }

    public record AdoptionStats(
        int TotalUsers,
        int EnrolledCount,
        double EnrolledPercent,
        int RecentEnrollments7d,
        int FailedVerifies24h,
        int Lockouts24h,
        int SuccessfulLogins24h,
        IReadOnlyList<UserBehindDeadline> UsersBehindDeadline);

    public record UserBehindDeadline(Guid UserId, string Username, DateTime DeadlineUtc);

    public async Task<AdoptionStats> ComputeAsync()
    {
        var jfUsers = _userManager.Users.ToList();
        var totalUsers = jfUsers.Count;
        var data = await _store.GetAllUsersAsync().ConfigureAwait(false);

        var enrolled = data.Count(d => d.TotpEnabled || d.Passkeys.Count > 0);
        double pct = totalUsers > 0 ? Math.Round(100.0 * enrolled / totalUsers, 1) : 0;

        var since7 = DateTime.UtcNow.AddDays(-7);
        var since24 = DateTime.UtcNow.AddHours(-24);

        var recent7 = data.Count(d => d.RecoveryCodesGeneratedAt >= since7);

        var audit = await _store.GetAuditLogAsync(limit: null).ConfigureAwait(false);
        int failedVerifies24 = audit.Count(e => e.Timestamp >= since24 && e.Result == AuditResult.Failed);
        int lockouts24 = audit.Count(e => e.Timestamp >= since24 && e.Result == AuditResult.Locked);
        int success24 = audit.Count(e => e.Timestamp >= since24 && e.Result == AuditResult.Success);

        IReadOnlyList<UserBehindDeadline> behind = Array.Empty<UserBehindDeadline>();
        var deadline = Plugin.Instance?.Configuration?.EnrollmentDeadline;
        if (deadline.HasValue && deadline.Value <= DateTime.UtcNow)
        {
            // Past the deadline — list users who STILL aren't enrolled.
            var enrolledIds = new HashSet<Guid>(data
                .Where(d => d.TotpEnabled || d.Passkeys.Count > 0)
                .Select(d => d.UserId));
            behind = jfUsers
                .Where(u => !enrolledIds.Contains(u.Id))
                .Select(u => new UserBehindDeadline(u.Id, u.Username, deadline.Value))
                .ToList();
        }

        return new AdoptionStats(totalUsers, enrolled, pct, recent7,
            failedVerifies24, lockouts24, success24, behind);
    }
}

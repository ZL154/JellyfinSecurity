using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Computes a 0-100 security posture score by aggregating 12 weighted factors
/// over plugin config, the per-user 2FA store, and the audit log. The factors
/// sum to 130 raw points and are normalized to a 100-ceiling for grading.
/// Pure compute (Task 3 of v2.5.0 Phase 2) — snapshot/history persistence is
/// layered on in Task 4.
/// </summary>
public class SecurityScoreService : IDisposable
{
    private const int MaxHistoryEntries = 365;

    private readonly UserTwoFactorStore _store;
    private readonly StatsService _stats;
    private readonly IUserManager? _userManager;
    private readonly ILogger<SecurityScoreService> _logger;
    private readonly Func<PluginConfiguration> _configAccessor;
    private readonly string _historyPath;
    private readonly SemaphoreSlim _historyLock = new(1, 1);
    private readonly Timer _snapshotTimer;
    private bool _disposed;

    public SecurityScoreService(
        UserTwoFactorStore store,
        StatsService stats,
        IUserManager userManager,
        IApplicationPaths paths,
        ILogger<SecurityScoreService> logger)
        : this(store, stats, userManager, paths, logger, () => Plugin.Instance?.Configuration ?? new PluginConfiguration())
    {
    }

    // Test seam — accepts a config accessor delegate so tests can mutate config
    // without spinning up the full Plugin singleton. userManager is nullable in the
    // test ctor so existing tests that don't touch admin-enumeration paths still work.
    internal SecurityScoreService(
        UserTwoFactorStore store,
        StatsService stats,
        IApplicationPaths paths,
        ILogger<SecurityScoreService> logger,
        Func<PluginConfiguration> configAccessor)
        : this(store, stats, null!, paths, logger, configAccessor)
    {
    }

    internal SecurityScoreService(
        UserTwoFactorStore store,
        StatsService stats,
        IUserManager? userManager,
        IApplicationPaths paths,
        ILogger<SecurityScoreService> logger,
        Func<PluginConfiguration> configAccessor)
    {
        _store = store;
        _stats = stats;
        _userManager = userManager;
        _logger = logger;
        _configAccessor = configAccessor;

        var dir = Path.Combine(paths.PluginConfigurationsPath, "TwoFactorAuth");
        Directory.CreateDirectory(dir);
        _historyPath = Path.Combine(dir, "score-history.json");

        // Fire once an hour; the method itself dedupes by UTC date so the cost
        // is one read+early-return per hour after the first daily snapshot.
        // The _disposed guard is defense-in-depth — Dispose() drains in-flight
        // callbacks via Timer.Dispose(WaitHandle), but the early-exit makes the
        // intent explicit for any callback already past the gate.
        _snapshotTimer = new Timer(
            _ =>
            {
                if (_disposed) return;
                _ = TakeSnapshotAsync();
            },
            null,
            TimeSpan.FromMinutes(1),
            TimeSpan.FromHours(1));
    }

    public async Task<SecurityScore> ComputeAsync()
    {
        var cfg = _configAccessor();
        var factors = new List<ScoreFactor>(12);

        // 1. 2FA coverage (30 pts, scaled by %)
        // v2.5.0: each factor carries a LabelKey / NextActionKey so the admin UI
        // can localize the breakdown card. NextActionData ships the interpolation
        // payload (e.g., { count = N }) for actions that include dynamic numbers.
        var users = await _store.GetAllUsersAsync().ConfigureAwait(false);
        int enrolled = users.Count(u => u.TotpEnabled || u.Passkeys.Count > 0);
        int totalUsers = users.Count;
        double pctEnrolled = totalUsers > 0 ? (double)enrolled / totalUsers : 0;
        int coverage = (int)Math.Round(30 * pctEnrolled);
        int remainingToEnroll = totalUsers - enrolled;
        factors.Add(new ScoreFactor
        {
            Id = "coverage",
            Label = "2FA coverage",
            LabelKey = "tfa.factor.coverage.label",
            Earned = coverage,
            Possible = 30,
            Status = pctEnrolled >= 1 ? "ok" : pctEnrolled >= 0.5 ? "partial" : "fail",
            NextAction = pctEnrolled < 1 ? $"Enroll the remaining {remainingToEnroll} user(s) in 2FA." : null,
            NextActionKey = pctEnrolled < 1 ? "tfa.factor.coverage.action" : null,
            NextActionData = pctEnrolled < 1 ? new Dictionary<string, object> { ["count"] = remainingToEnroll } : null
        });

        // 2. All admins protected (20 pts, binary)
        bool allAdminsProtected = AreAllAdminsProtected(users);
        factors.Add(new ScoreFactor
        {
            Id = "admins",
            Label = "All admins protected",
            LabelKey = "tfa.factor.admins.label",
            Earned = allAdminsProtected ? 20 : 0,
            Possible = 20,
            Status = allAdminsProtected ? "ok" : "fail",
            NextAction = allAdminsProtected ? null : "At least one admin account is missing 2FA. Enroll all admins.",
            NextActionKey = allAdminsProtected ? null : "tfa.factor.admins.action"
        });

        // 3. Enforcement mode (15 / 8 / 0)
        int enforcement = cfg.EnforcementScope switch
        {
            EnforcementScope.All => 15,
            EnforcementScope.Admins => 8,
            _ => 0
        };
        factors.Add(new ScoreFactor
        {
            Id = "enforcement",
            Label = "Enforcement mode",
            LabelKey = "tfa.factor.enforcement.label",
            Earned = enforcement,
            Possible = 15,
            Status = enforcement == 15 ? "ok" : enforcement == 8 ? "partial" : "fail",
            NextAction = enforcement < 15 ? "Switch enforcement to 'All users' for full credit." : null,
            NextActionKey = enforcement < 15 ? "tfa.factor.enforcement.action" : null
        });

        // 4. Audit chain verified (10 / 0)
        var audit = await _store.GetAuditLogAsync(limit: null).ConfigureAwait(false);
        int broken = DiagnosticsService.VerifyAuditChainPublic(audit);
        factors.Add(new ScoreFactor
        {
            Id = "audit-chain",
            Label = "Audit chain integrity",
            LabelKey = "tfa.factor.audit_chain.label",
            Earned = broken == 0 ? 10 : 0,
            Possible = 10,
            Status = broken == 0 ? "ok" : "fail",
            NextAction = broken == 0 ? null : $"{broken} audit entr{(broken == 1 ? "y has" : "ies have")} a broken hash. Investigate.",
            // Pluralization is handled by picking the singular vs. plural key
            // server-side. Both keys exist in en.json + every translation file.
            NextActionKey = broken == 0
                ? null
                : (broken == 1 ? "tfa.factor.audit_chain.action_one" : "tfa.factor.audit_chain.action_many"),
            NextActionData = broken == 0 ? null : new Dictionary<string, object> { ["count"] = broken }
        });

        // 5. IP banning (8 / 0)
        factors.Add(new ScoreFactor
        {
            Id = "ipban",
            Label = "IP brute-force ban",
            LabelKey = "tfa.factor.ipban.label",
            Earned = cfg.IpBanEnabled ? 8 : 0,
            Possible = 8,
            Status = cfg.IpBanEnabled ? "ok" : "fail",
            NextAction = cfg.IpBanEnabled ? null : "Enable IP banning to stop repeated brute-force attempts.",
            NextActionKey = cfg.IpBanEnabled ? null : "tfa.factor.ipban.action"
        });

        // 6. Impossible-travel (7 / 0)
        // v2.5.0: previously this only checked the toggle, so an admin could
        // score full credit without ever configuring the GeoLite2-City.mmdb
        // database that the detector actually needs. Require BOTH the toggle
        // AND a non-empty city-DB path so the factor reflects real coverage.
        var travelEnabled = cfg.ImpossibleTravelEnabled && !string.IsNullOrWhiteSpace(cfg.GeoIpCityDbPath);
        factors.Add(new ScoreFactor
        {
            Id = "travel",
            Label = "Impossible-travel detection",
            LabelKey = "tfa.factor.travel.label",
            Earned = travelEnabled ? 7 : 0,
            Possible = 7,
            Status = travelEnabled ? "ok" : "fail",
            NextAction = travelEnabled ? null : "Enable impossible-travel detection AND configure the GeoIP city DB path.",
            NextActionKey = travelEnabled ? null : "tfa.factor.travel.action"
        });

        // 7. HIBP (5 / 0)
        factors.Add(new ScoreFactor
        {
            Id = "hibp",
            Label = "HIBP password breach check",
            LabelKey = "tfa.factor.hibp.label",
            Earned = cfg.HibpEnabled ? 5 : 0,
            Possible = 5,
            Status = cfg.HibpEnabled ? "ok" : "fail",
            NextAction = cfg.HibpEnabled ? null : "Enable HIBP breach checking on new/changed passwords.",
            NextActionKey = cfg.HibpEnabled ? null : "tfa.factor.hibp.action"
        });

        // 8. No breach/lockout in last 7 days (5 / 0)
        var since7 = DateTime.UtcNow.AddDays(-7);
        bool clean7 = !audit.Any(e => e.Timestamp >= since7 &&
            (e.Result == AuditResult.Locked || e.Result == AuditResult.Failed));
        factors.Add(new ScoreFactor
        {
            Id = "clean-7d",
            Label = "No failed-auth events in 7 days",
            LabelKey = "tfa.factor.clean_7d.label",
            Earned = clean7 ? 5 : 0,
            Possible = 5,
            Status = clean7 ? "ok" : "fail",
            NextAction = clean7 ? null : "Recent failed-auth or lockout events. Review the audit log.",
            NextActionKey = clean7 ? null : "tfa.factor.clean_7d.action"
        });

        // 9. v2.5.0: Require 2FA before a user can disable their own 2FA (8 / 0)
        factors.Add(new ScoreFactor
        {
            Id = "require-to-disable",
            Label = "Require 2FA to disable own 2FA",
            LabelKey = "tfa.factor.require_to_disable.label",
            Earned = cfg.RequireTwoFactorToDisable ? 8 : 0,
            Possible = 8,
            Status = cfg.RequireTwoFactorToDisable ? "ok" : "partial",
            NextAction = cfg.RequireTwoFactorToDisable ? null : "Turn on \"Require authenticator/recovery code before a user can turn off their own 2FA\" in Hardening.",
            NextActionKey = cfg.RequireTwoFactorToDisable ? null : "tfa.factor.require_to_disable.action"
        });

        // 10. v2.5.0: Step-up authentication level (7 / 0, graded)
        int stepUpEarned = cfg.StepUpLevel switch
        {
            StepUpLevel.Off => 0,
            StepUpLevel.Destructive => 4,
            StepUpLevel.AllConfigChanges => 6,
            StepUpLevel.Everything => 7,
            _ => 0
        };
        factors.Add(new ScoreFactor
        {
            Id = "stepup",
            Label = "Step-up authentication enabled",
            LabelKey = "tfa.factor.stepup.label",
            Earned = stepUpEarned,
            Possible = 7,
            Status = stepUpEarned >= 6 ? "ok" : stepUpEarned > 0 ? "partial" : "fail",
            NextAction = stepUpEarned >= 7 ? null : "Raise step-up level to AllConfigChanges or Everything for full credit.",
            NextActionKey = stepUpEarned >= 7 ? null : "tfa.factor.stepup.action"
        });

        // 11. v2.5.0: Webhook configured for security events (5 / 0)
        bool webhookConfigured = !string.IsNullOrWhiteSpace(cfg.WebhookUrl);
        factors.Add(new ScoreFactor
        {
            Id = "webhook",
            Label = "Webhook for security events",
            LabelKey = "tfa.factor.webhook.label",
            Earned = webhookConfigured ? 5 : 0,
            Possible = 5,
            Status = webhookConfigured ? "ok" : "partial",
            NextAction = webhookConfigured ? null : "Configure a webhook URL so security events (bans, lockouts, 2FA changes) trigger notifications.",
            NextActionKey = webhookConfigured ? null : "tfa.factor.webhook.action"
        });

        // 12. v2.5.0: Recovery codes generated for enrolled users (5 / 0, scaled)
        // Counts only TOTP-enrolled users — a passkey-only user has no use
        // for backup OTP recovery codes. If nobody is TOTP-enrolled the factor
        // is "fail" with no nextAction, since the gap is fixed by enrollment
        // (already covered by the coverage factor) rather than by anything
        // recovery-code specific.
        var totpUsers = users.Where(u => u.TotpEnabled).ToList();
        int withCodes = totpUsers.Count(u => u.RecoveryCodes.Count > 0);
        int recoveryEarned = totpUsers.Count == 0
            ? 0
            : (int)Math.Round(5.0 * withCodes / totpUsers.Count);
        factors.Add(new ScoreFactor
        {
            Id = "recovery-codes",
            Label = "Recovery codes generated",
            LabelKey = "tfa.factor.recovery_codes.label",
            Earned = recoveryEarned,
            Possible = 5,
            Status = totpUsers.Count == 0 ? "fail" : (recoveryEarned == 5 ? "ok" : "partial"),
            NextAction = (totpUsers.Count == 0 || recoveryEarned == 5)
                ? null
                : "Ask enrolled users to generate recovery codes — they're a critical backup factor.",
            NextActionKey = (totpUsers.Count == 0 || recoveryEarned == 5)
                ? null
                : "tfa.factor.recovery_codes.action"
        });

        int total = factors.Sum(f => f.Earned);
        int possible = factors.Sum(f => f.Possible);
        // v2.5.0: scale to a 100 ceiling so adding factors doesn't break the
        // "0-100 grade" expectation downstream. Sum-of-possibles is now 130;
        // we normalize earned into the same 0-100 frame.
        int scaledTotal = possible > 0 ? (int)Math.Round(100.0 * total / possible) : 0;
        return new SecurityScore
        {
            Total = scaledTotal,
            Possible = 100,
            Grade = GradeFromTotal(scaledTotal),
            Factors = factors,
            ComputedAt = DateTime.UtcNow
        };
    }

    public static string GradeFromTotal(int total) => total switch
    {
        >= 90 => "A",
        >= 80 => "B+",
        >= 70 => "B",
        >= 60 => "C",
        >= 50 => "D",
        _ => "F"
    };

    private bool AreAllAdminsProtected(IReadOnlyList<UserTwoFactorData> data)
    {
        // v2.5.0 fix #2: HasPermission is an EXTENSION METHOD on User, so
        // GetType().GetMethod("HasPermission") returns null and every user gets
        // classified as non-admin. Use IUserManager.Users directly with the typed
        // extension call. _userManager is null only on the test seam ctor — in
        // that case treat factor as vacuously true to preserve existing test
        // semantics.
        if (_userManager is null) return true;
        var enrolledIds = new HashSet<Guid>(data
            .Where(d => d.TotpEnabled || d.Passkeys.Count > 0)
            .Select(d => d.UserId));
        foreach (var u in _userManager.Users)
        {
            if (!u.HasPermission(PermissionKind.IsAdministrator)) continue;
            if (!enrolledIds.Contains(u.Id)) return false;
        }
        // "No admins exist" still scores full credit (vacuous truth).
        return true;
    }

    /// <summary>
    /// Records today's score to <c>score-history.json</c>. Idempotent per UTC day —
    /// repeated calls within the same day are no-ops. Fired hourly by the snapshot
    /// timer; only the first call per day pays the compute+write cost.
    /// </summary>
    public async Task TakeSnapshotAsync()
    {
        try
        {
            var today = DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            var hist = await LoadHistoryAsync().ConfigureAwait(false);
            if (hist.Any(h => h.Date == today)) return; // already recorded today
            var score = await ComputeAsync().ConfigureAwait(false);
            await _historyLock.WaitAsync().ConfigureAwait(false);
            try
            {
                hist = await LoadHistoryAsync().ConfigureAwait(false); // re-read under lock
                if (hist.Any(h => h.Date == today)) return;
                hist.Add(new ScoreSnapshot { Date = today, Score = score.Total });
                if (hist.Count > MaxHistoryEntries)
                {
                    hist = hist.Skip(hist.Count - MaxHistoryEntries).ToList();
                }

                await SaveHistoryAsync(hist).ConfigureAwait(false);
            }
            finally { _historyLock.Release(); }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Score snapshot failed");
        }
    }

    /// <summary>
    /// Returns the recorded history entries with a date >= (today - <paramref name="days"/>).
    /// Pass a non-positive value to return the full history (capped at 365 entries).
    /// </summary>
    public async Task<IReadOnlyList<ScoreSnapshot>> GetHistoryAsync(int days)
    {
        var hist = await LoadHistoryAsync().ConfigureAwait(false);
        if (days <= 0) return hist;
        var cutoff = DateTime.UtcNow.AddDays(-days).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        return hist.Where(h => string.CompareOrdinal(h.Date, cutoff) >= 0).ToList();
    }

    /// <summary>
    /// Test-only direct append (bypasses score compute). Used by snapshot-capping
    /// tests to pre-populate history without spinning real wall-clock days.
    /// </summary>
    internal async Task AppendForTestAsync(string date, int score)
    {
        var hist = await LoadHistoryAsync().ConfigureAwait(false);
        hist.Add(new ScoreSnapshot { Date = date, Score = score });
        if (hist.Count > MaxHistoryEntries)
        {
            hist = hist.Skip(hist.Count - MaxHistoryEntries).ToList();
        }

        await SaveHistoryAsync(hist).ConfigureAwait(false);
    }

    private async Task<List<ScoreSnapshot>> LoadHistoryAsync()
    {
        if (!File.Exists(_historyPath)) return new List<ScoreSnapshot>();
        try
        {
            var json = await File.ReadAllTextAsync(_historyPath).ConfigureAwait(false);
            return System.Text.Json.JsonSerializer.Deserialize<List<ScoreSnapshot>>(json) ?? new List<ScoreSnapshot>();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to load score history; starting fresh.");
            return new List<ScoreSnapshot>();
        }
    }

    private async Task SaveHistoryAsync(List<ScoreSnapshot> hist)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(hist);
        await File.WriteAllTextAsync(_historyPath, json).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Drain in-flight callbacks before disposing dependent resources, so a
        // mid-flight TakeSnapshotAsync cannot try to acquire a disposed
        // _historyLock and throw ObjectDisposedException on plugin reload.
        using var waitHandle = new ManualResetEvent(false);
        _snapshotTimer.Dispose(waitHandle);
        waitHandle.WaitOne(TimeSpan.FromSeconds(5));
        _historyLock.Dispose();
        GC.SuppressFinalize(this);
    }
}

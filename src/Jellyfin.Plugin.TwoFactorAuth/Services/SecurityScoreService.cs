using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Common.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Computes a 0-100 security posture score by aggregating 8 weighted factors
/// over plugin config, the per-user 2FA store, and the audit log. Pure compute
/// (Task 3 of v2.5.0 Phase 2) — snapshot/history persistence is layered on in
/// Task 4.
/// </summary>
public class SecurityScoreService : IDisposable
{
    private const int MaxHistoryEntries = 365;

    private readonly UserTwoFactorStore _store;
    private readonly StatsService _stats;
    private readonly ILogger<SecurityScoreService> _logger;
    private readonly Func<PluginConfiguration> _configAccessor;
    private readonly string _historyPath;
    private readonly SemaphoreSlim _historyLock = new(1, 1);
    private readonly Timer _snapshotTimer;
    private bool _disposed;

    public SecurityScoreService(
        UserTwoFactorStore store,
        StatsService stats,
        IApplicationPaths paths,
        ILogger<SecurityScoreService> logger)
        : this(store, stats, paths, logger, () => Plugin.Instance?.Configuration ?? new PluginConfiguration())
    {
    }

    // Test seam — accepts a config accessor delegate so tests can mutate config
    // without spinning up the full Plugin singleton.
    internal SecurityScoreService(
        UserTwoFactorStore store,
        StatsService stats,
        IApplicationPaths paths,
        ILogger<SecurityScoreService> logger,
        Func<PluginConfiguration> configAccessor)
    {
        _store = store;
        _stats = stats;
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
        var factors = new List<ScoreFactor>(8);

        // 1. 2FA coverage (30 pts, scaled by %)
        var users = await _store.GetAllUsersAsync().ConfigureAwait(false);
        int enrolled = users.Count(u => u.TotpEnabled || u.Passkeys.Count > 0);
        int totalUsers = users.Count;
        double pctEnrolled = totalUsers > 0 ? (double)enrolled / totalUsers : 0;
        int coverage = (int)Math.Round(30 * pctEnrolled);
        factors.Add(new ScoreFactor
        {
            Id = "coverage",
            Label = "2FA coverage",
            Earned = coverage,
            Possible = 30,
            Status = pctEnrolled >= 1 ? "ok" : pctEnrolled >= 0.5 ? "partial" : "fail",
            NextAction = pctEnrolled < 1 ? $"Enroll the remaining {totalUsers - enrolled} user(s) in 2FA." : null
        });

        // 2. All admins protected (20 pts, binary)
        bool allAdminsProtected = AreAllAdminsProtected(users);
        factors.Add(new ScoreFactor
        {
            Id = "admins",
            Label = "All admins protected",
            Earned = allAdminsProtected ? 20 : 0,
            Possible = 20,
            Status = allAdminsProtected ? "ok" : "fail",
            NextAction = allAdminsProtected ? null : "At least one admin account is missing 2FA. Enroll all admins."
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
            Earned = enforcement,
            Possible = 15,
            Status = enforcement == 15 ? "ok" : enforcement == 8 ? "partial" : "fail",
            NextAction = enforcement < 15 ? "Switch enforcement to 'All users' for full credit." : null
        });

        // 4. Audit chain verified (10 / 0)
        var audit = await _store.GetAuditLogAsync(limit: null).ConfigureAwait(false);
        int broken = DiagnosticsService.VerifyAuditChainPublic(audit);
        factors.Add(new ScoreFactor
        {
            Id = "audit-chain",
            Label = "Audit chain integrity",
            Earned = broken == 0 ? 10 : 0,
            Possible = 10,
            Status = broken == 0 ? "ok" : "fail",
            NextAction = broken == 0 ? null : $"{broken} audit entr{(broken == 1 ? "y has" : "ies have")} a broken hash. Investigate."
        });

        // 5. IP banning (8 / 0)
        factors.Add(new ScoreFactor
        {
            Id = "ipban",
            Label = "IP brute-force ban",
            Earned = cfg.IpBanEnabled ? 8 : 0,
            Possible = 8,
            Status = cfg.IpBanEnabled ? "ok" : "fail",
            NextAction = cfg.IpBanEnabled ? null : "Enable IP banning to stop repeated brute-force attempts."
        });

        // 6. Impossible-travel (7 / 0)
        factors.Add(new ScoreFactor
        {
            Id = "travel",
            Label = "Impossible-travel detection",
            Earned = cfg.ImpossibleTravelEnabled ? 7 : 0,
            Possible = 7,
            Status = cfg.ImpossibleTravelEnabled ? "ok" : "fail",
            NextAction = cfg.ImpossibleTravelEnabled ? null : "Enable impossible-travel detection (needs GeoIP city DB)."
        });

        // 7. HIBP (5 / 0)
        factors.Add(new ScoreFactor
        {
            Id = "hibp",
            Label = "HIBP password breach check",
            Earned = cfg.HibpEnabled ? 5 : 0,
            Possible = 5,
            Status = cfg.HibpEnabled ? "ok" : "fail",
            NextAction = cfg.HibpEnabled ? null : "Enable HIBP breach checking on new/changed passwords."
        });

        // 8. No breach/lockout in last 7 days (5 / 0)
        var since7 = DateTime.UtcNow.AddDays(-7);
        bool clean7 = !audit.Any(e => e.Timestamp >= since7 &&
            (e.Result == AuditResult.Locked || e.Result == AuditResult.Failed));
        factors.Add(new ScoreFactor
        {
            Id = "clean-7d",
            Label = "No failed-auth events in 7 days",
            Earned = clean7 ? 5 : 0,
            Possible = 5,
            Status = clean7 ? "ok" : "fail",
            NextAction = clean7 ? null : "Recent failed-auth or lockout events. Review the audit log."
        });

        int total = factors.Sum(f => f.Earned);
        int possible = factors.Sum(f => f.Possible);
        return new SecurityScore
        {
            Total = total,
            Possible = possible,
            Grade = GradeFromTotal(total),
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
        IEnumerable<object> jfUsers;
        try { jfUsers = _stats.EnumerateUsersPublic(); }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Admin enumeration failed; treating admins factor as vacuously true.");
            return true;
        }
        var enrolledIds = new HashSet<Guid>(data
            .Where(d => d.TotpEnabled || d.Passkeys.Count > 0)
            .Select(d => d.UserId));
        foreach (var u in jfUsers)
        {
            var idProp = u.GetType().GetProperty("Id");
            var policyProp = u.GetType().GetProperty("Policy");
            if (idProp?.GetValue(u) is not Guid id) continue;
            var policy = policyProp?.GetValue(u);
            var isAdmin = policy?.GetType().GetProperty("IsAdministrator")?.GetValue(policy) as bool? ?? false;
            if (!isAdmin) continue;
            if (!enrolledIds.Contains(id)) return false;
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

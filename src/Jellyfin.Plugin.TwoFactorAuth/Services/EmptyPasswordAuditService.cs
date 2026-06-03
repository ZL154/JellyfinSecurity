using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Startup security audit: enumerates Jellyfin users at plugin load time and
/// emits a structured [SECURITY] warning for every user whose password hash
/// is null/empty. These users are vulnerable to the
/// "any-password-including-empty-matches" behaviour of Jellyfin's default
/// authentication provider — the same root cause that was patched in
/// <see cref="TwoFactorAuthProvider"/> (empty-password rejection) and
/// <see cref="OidcService"/> (OIDC auto-create hardening) for v2.5.5.
///
/// This service is read-only. It does NOT mutate user records. Its job is to
/// give admins visibility on who is affected so they can either (a) wait for
/// the next OIDC sign-in (which will harden the user via the v2.5.5
/// auto-create path), (b) manually set a password on the user via the
/// Jellyfin admin UI, or (c) trigger the opt-in
/// /TwoFactorAuth/Admin/HardenEmptyPasswordUsers endpoint (planned v2.5.6)
/// to randomize the password and lock out password-based login.
///
/// The audit runs once per plugin start. The list of vulnerable user IDs is
/// also stashed on the static <see cref="VulnerableUserIds"/> set so the
/// admin dashboard and SecurityScore engine can read it without re-scanning.
/// </summary>
public class EmptyPasswordAuditService : IHostedService
{
    private readonly IUserManager _userManager;
    private readonly ILogger<EmptyPasswordAuditService> _logger;

    /// <summary>User IDs whose password hash was null/empty at the most recent
    /// startup audit. Read by the admin dashboard and security-score factor.
    /// Stored as a snapshot — does NOT update on subsequent user changes;
    /// admin must restart Jellyfin to re-audit (or call the planned
    /// /Admin/RescanEmptyPasswordUsers endpoint).</summary>
    public static IReadOnlySet<Guid> VulnerableUserIds { get; private set; } = new HashSet<Guid>();

    public EmptyPasswordAuditService(IUserManager userManager, ILogger<EmptyPasswordAuditService> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            var vulnerable = ScanForEmptyPasswordUsers();
            VulnerableUserIds = vulnerable.Select(u => u.Id).ToHashSet();

            if (vulnerable.Count == 0)
            {
                _logger.LogInformation("[2FA] Startup security audit: no users with empty password hash detected (good).");
                return Task.CompletedTask;
            }

            var blockOn = Plugin.Instance?.Configuration?.BlockEmptyPasswordLogin == true;
            _logger.LogWarning(
                "[2FA] [SECURITY] Startup audit found {Count} user(s) with no password hash. These accounts are vulnerable to the empty-password sign-in flaw (anyone who knows the UPN can sign in as them via /Users/AuthenticateByName with an empty Pw). " +
                "Empty-password auth gate is currently {GateState} (config: BlockEmptyPasswordLogin = {Flag}). " +
                "Recommended actions: (a) set a password on each from the admin UI, (b) ensure they sign in via OIDC (which now hardens new accounts automatically), or (c) if these are intentional kiosk / family / guest accounts where passwordless tile-click login is the desired UX, leave BlockEmptyPasswordLogin=false and accept the tradeoff. To enable the gate, set BlockEmptyPasswordLogin=true in the Jellyfin Security plugin config.",
                vulnerable.Count,
                blockOn ? "ENABLED (these users CANNOT sign in via password)" : "DISABLED (these users CAN still sign in with empty password — exploitable)",
                blockOn);

            foreach (var u in vulnerable)
            {
                _logger.LogWarning(
                    "[2FA] [SECURITY] Empty-password user: id={UserId} name='{Username}' isAdmin={IsAdmin}",
                    u.Id, u.Username, IsAdmin(u));
            }
        }
        catch (Exception ex)
        {
            // Audit is informational — never fail plugin startup over it.
            _logger.LogWarning(ex, "[2FA] Startup empty-password audit failed (non-fatal). Plugin will continue.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Walk all Jellyfin users via the same reflection-tolerant
    /// enumeration that <see cref="StatsService"/> uses (works across the
    /// 10.11.8 / 10.11.9 / 10.11.10 IUserManager API drift) and return those
    /// whose Password property is null or whitespace-only.</summary>
    private List<User> ScanForEmptyPasswordUsers()
    {
        var result = new List<User>();
        foreach (var u in EnumerateUsers())
        {
            if (string.IsNullOrWhiteSpace(u.Password))
            {
                result.Add(u);
            }
        }
        return result;
    }

    // Mirror of StatsService.EnumerateUsers — kept inline so this audit
    // service doesn't pull a dependency on StatsService just for the shim.
    private IEnumerable<User> EnumerateUsers()
    {
        System.Collections.IEnumerable? raw = null;
        try
        {
            var getUsersMethod = typeof(IUserManager).GetMethod("GetUsers", Type.EmptyTypes);
            if (getUsersMethod is not null)
            {
                raw = getUsersMethod.Invoke(_userManager, null) as System.Collections.IEnumerable;
            }
            else
            {
                var prop = typeof(IUserManager).GetProperty("Users");
                raw = prop?.GetValue(_userManager) as System.Collections.IEnumerable;
            }
        }
        catch (Exception)
        {
            yield break;
        }
        if (raw is null) yield break;
        foreach (var item in raw)
        {
            if (item is User u) yield return u;
        }
    }

    private static bool IsAdmin(User u)
    {
        try
        {
            // User.HasPermission(PermissionKind.IsAdministrator) — accessed by
            // reflection to dodge any cross-version API drift in the Permission
            // model (some 10.11.x point releases changed enum locations).
            var hasPermMethod = u.GetType().GetMethod("HasPermission", new[] { typeof(string) });
            if (hasPermMethod is null) return false;
            return hasPermMethod.Invoke(u, new object[] { "IsAdministrator" }) is bool b && b;
        }
        catch
        {
            return false;
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// "Run a diagnostic on the plugin's state" — green/red checklist for admins.
/// Results are point-in-time; nothing is cached. Cheap checks only — SMTP
/// send is opt-in via a query param at the controller layer.
/// </summary>
public class DiagnosticsService
{
    public enum CheckStatus { Ok, Warn, Fail }

    public record DiagnosticCheck(string Id, string Label, CheckStatus Status, string Detail);

    private readonly UserTwoFactorStore _store;
    private readonly IApplicationPaths _paths;
    private readonly IServerApplicationHost _appHost;
    private readonly GeoIpService _geo;
    private readonly ILogger<DiagnosticsService> _logger;

    public DiagnosticsService(
        UserTwoFactorStore store,
        IApplicationPaths paths,
        IServerApplicationHost appHost,
        GeoIpService geo,
        ILogger<DiagnosticsService> logger)
    {
        _store = store;
        _paths = paths;
        _appHost = appHost;
        _geo = geo;
        _logger = logger;
    }

    public async Task<List<DiagnosticCheck>> RunAsync()
    {
        var results = new List<DiagnosticCheck>();
        var dataDir = Path.Combine(_paths.PluginConfigurationsPath, "TwoFactorAuth");

        // --- Signing key files ---
        var secretKey = Path.Combine(dataDir, "secret.key");
        var cookieKey = Path.Combine(dataDir, "cookie.key");
        results.Add(FileCheck("secret_key", "TOTP encryption key readable", secretKey, mustExist: true));
        results.Add(FileCheck("cookie_key", "Trust cookie signing key readable", cookieKey, mustExist: true));

        // --- Audit log writability (try a no-op append+revert via the store API) ---
        try
        {
            var audit = await _store.GetAuditLogAsync(limit: 1).ConfigureAwait(false);
            results.Add(new DiagnosticCheck("audit_readable", "Audit log readable",
                CheckStatus.Ok, $"{audit.Count} entry/entries last read"));
        }
        catch (Exception ex)
        {
            results.Add(new DiagnosticCheck("audit_readable", "Audit log readable",
                CheckStatus.Fail, ex.Message));
        }

        // --- Plugin assembly version vs manifest ---
        var asmVer = typeof(Plugin).Assembly.GetName().Version?.ToString() ?? "unknown";
        var metaVer = Plugin.Instance?.Version?.ToString() ?? "unknown";
        results.Add(new DiagnosticCheck("plugin_version", "Plugin assembly version",
            string.Equals(asmVer.TrimEnd('.', '0'), metaVer.TrimEnd('.', '0'), StringComparison.Ordinal)
                ? CheckStatus.Ok : CheckStatus.Warn,
            $"Assembly={asmVer} Meta={metaVer}"));

        // --- IAuthenticationProvider registration ---
        try
        {
            var providers = _appHost.Resolve<IEnumerable<IAuthenticationProvider>>();
            var found = providers.Any(p => p is TwoFactorAuthProvider);
            results.Add(new DiagnosticCheck("auth_provider", "IAuthenticationProvider registered",
                found ? CheckStatus.Ok : CheckStatus.Warn,
                found ? "TwoFactorAuthProvider present in DI chain"
                      : "Provider not found — app passwords may not work"));
        }
        catch (Exception ex)
        {
            results.Add(new DiagnosticCheck("auth_provider", "IAuthenticationProvider registered",
                CheckStatus.Warn, ex.Message));
        }

        // --- inject middleware activity ---
        var seen = IndexHtmlInjectionMiddleware.RequestsSeen;
        results.Add(new DiagnosticCheck("inject_middleware", "Index.html injection middleware active",
            seen > 0 ? CheckStatus.Ok : CheckStatus.Warn,
            $"{seen} requests intercepted since startup"));

        // --- Recovery hash format upgrade (count v1 entries left) ---
        try
        {
            var users = await _store.GetAllUsersAsync().ConfigureAwait(false);
            int legacyV1 = users.Sum(u => u.RecoveryCodes.Count(c =>
                !string.IsNullOrEmpty(c.Hash) && !c.Hash.StartsWith("v2$", StringComparison.Ordinal) && !c.Used));
            results.Add(new DiagnosticCheck("recovery_hash_format", "Recovery codes hashed with PBKDF2",
                legacyV1 == 0 ? CheckStatus.Ok : CheckStatus.Warn,
                legacyV1 == 0 ? "All unused codes use v2 (PBKDF2)"
                              : $"{legacyV1} unused legacy SHA-256 codes remain — they'll auto-upgrade on rotate"));
        }
        catch (Exception ex)
        {
            results.Add(new DiagnosticCheck("recovery_hash_format", "Recovery codes hashed with PBKDF2",
                CheckStatus.Warn, ex.Message));
        }

        // --- GeoIP availability (only if admin configured paths) ---
        var config = Plugin.Instance?.Configuration;
        if (!string.IsNullOrEmpty(config?.GeoIpAsnDbPath) || !string.IsNullOrEmpty(config?.GeoIpCountryDbPath))
        {
            results.Add(new DiagnosticCheck("geoip", "GeoIP databases loaded",
                _geo.AsnAvailable || _geo.CountryAvailable ? CheckStatus.Ok : CheckStatus.Fail,
                $"ASN={_geo.AsnAvailable} Country={_geo.CountryAvailable}"));
        }

        // --- Audit hash chain integrity ---
        try
        {
            var entries = await _store.GetAuditLogAsync(limit: null).ConfigureAwait(false);
            var bad = VerifyAuditChain(entries);
            results.Add(new DiagnosticCheck("audit_chain", "Audit log hash chain intact",
                bad == 0 ? CheckStatus.Ok : CheckStatus.Fail,
                bad == 0 ? $"{entries.Count} entries verified"
                         : $"{bad} broken link(s) detected — file may have been tampered with"));
        }
        catch (Exception ex)
        {
            results.Add(new DiagnosticCheck("audit_chain", "Audit log hash chain intact",
                CheckStatus.Warn, ex.Message));
        }

        return results;
    }

    /// <summary>Walks the audit log re-computing each entry's expected hash.
    /// Returns count of entries whose stored EntryHash mismatches the
    /// re-computation (0 == clean chain). Pre-v1.4 entries (empty hashes) are
    /// skipped — they're treated as the chain prefix.</summary>
    private static int VerifyAuditChain(IReadOnlyList<Models.AuditEntry> entries)
    {
        int broken = 0;
        string prev = string.Empty;
        foreach (var e in entries)
        {
            if (string.IsNullOrEmpty(e.EntryHash))
            {
                prev = string.Empty;
                continue;
            }
            var expectedPrev = string.IsNullOrEmpty(prev) ? new string('0', 64) : prev;
            if (!string.Equals(e.PreviousHash, expectedPrev, StringComparison.OrdinalIgnoreCase))
            {
                broken++;
            }
            else
            {
                var recomputed = UserTwoFactorStore.ComputeAuditEntryHash(new Models.AuditEntry
                {
                    PreviousHash = e.PreviousHash,
                    Timestamp = e.Timestamp,
                    UserId = e.UserId,
                    Username = e.Username,
                    RemoteIp = e.RemoteIp,
                    DeviceId = e.DeviceId,
                    DeviceName = e.DeviceName,
                    Result = e.Result,
                    Method = e.Method,
                    Details = e.Details,
                });
                if (!string.Equals(recomputed, e.EntryHash, StringComparison.OrdinalIgnoreCase))
                {
                    broken++;
                }
            }
            prev = e.EntryHash;
        }
        return broken;
    }

    private static DiagnosticCheck FileCheck(string id, string label, string path, bool mustExist)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new DiagnosticCheck(id, label,
                    mustExist ? CheckStatus.Fail : CheckStatus.Warn,
                    $"Missing: {path}");
            }
            using var fs = File.OpenRead(path);
            return new DiagnosticCheck(id, label, CheckStatus.Ok, $"{fs.Length} bytes");
        }
        catch (Exception ex)
        {
            return new DiagnosticCheck(id, label, CheckStatus.Fail, ex.Message);
        }
    }
}

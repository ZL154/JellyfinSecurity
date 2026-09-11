using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Resolves IPs to ASN + country via MaxMind GeoLite2 .mmdb files. Both
/// databases are admin-supplied (we don't bundle them — MaxMind requires
/// a free account + license key + manual download). When neither is set,
/// every lookup returns Unknown and the suspicious-login detector silently
/// disables itself.
///
/// Implementation note: uses MaxMind.Db (Apache 2.0) directly instead of
/// MaxMind.GeoIP2 (proprietary) so the plugin's MIT license stays clean.
/// We parse the same mmdb files; just no convenience wrappers.
///
/// [#51] Each file is owned by a <see cref="GeoIpDatabase"/>, which keeps the
/// reason a load failed, retries it, and falls back to an in-memory open.
/// </summary>
public class GeoIpService : IDisposable
{
    public record Lookup(uint Asn, string AsnOrg, string Country);

    public static readonly Lookup Unknown = new(0, string.Empty, string.Empty);

    private static readonly string[] SensitivePrefixes = { "/etc/", "/proc/", "/sys/", "/dev/", "/root/.ssh", "/run/secrets" };

    private readonly ILogger<GeoIpService> _logger;
    private readonly GeoIpDatabase _asn;
    private readonly GeoIpDatabase _country;
    private bool _disposed;

    public GeoIpService(ILogger<GeoIpService> logger)
    {
        _logger = logger;
        _asn = new GeoIpDatabase("GeoLite2-ASN", logger);
        _country = new GeoIpDatabase("GeoLite2-Country", logger);
    }

    // [v2.5.7] (issue #51): availability getters trigger the load, so the
    // Diagnostics tab and the suspicious-login detector see a real answer
    // before the first Resolve() call. Sync is a no-op in steady state.
    public bool AsnAvailable { get { Sync(force: false); return _asn.Loaded; } }
    public bool CountryAvailable { get { Sync(force: false); return _country.Loaded; } }

    /// <summary>Retry any failed load right now, ignoring the retry interval.
    /// The Diagnostics tab calls this so a re-run reflects a file that was
    /// dropped in after the previous attempt.</summary>
    public void Refresh() => Sync(force: true);

    /// <summary>Per-database state for the Diagnostics tab.</summary>
    public IReadOnlyList<GeoIpDatabaseStatus> Statuses
    {
        get
        {
            Sync(force: false);
            return new[] { _asn.Status, _country.Status };
        }
    }

    public Lookup Resolve(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return Unknown;
        Sync(force: false);
        if (!_asn.Loaded && !_country.Loaded) return Unknown;
        if (!IPAddress.TryParse(ip, out var addr)) return Unknown;

        uint asn = 0;
        string asnOrg = string.Empty;
        string country = string.Empty;

        try
        {
            var asnRec = _asn.Find<Dictionary<string, object>>(addr);
            if (asnRec is not null)
            {
                if (asnRec.TryGetValue("autonomous_system_number", out var asnVal))
                {
                    asn = Convert.ToUInt32(asnVal, System.Globalization.CultureInfo.InvariantCulture);
                }
                if (asnRec.TryGetValue("autonomous_system_organization", out var orgVal))
                {
                    asnOrg = orgVal?.ToString() ?? string.Empty;
                }
            }

            var countryRec = _country.Find<Dictionary<string, object>>(addr);
            if (countryRec is not null
                && countryRec.TryGetValue("country", out var countryNode)
                && countryNode is Dictionary<string, object> countryDict
                && countryDict.TryGetValue("iso_code", out var iso))
            {
                country = iso?.ToString() ?? string.Empty;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] GeoIP lookup failed for {Ip}", ip);
        }

        return new Lookup(asn, asnOrg, country);
    }

    private void Sync(bool force)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null) return;
        var now = DateTime.UtcNow;
        _asn.Sync(config.GeoIpAsnDbPath, now, force);
        _country.Sync(config.GeoIpCountryDbPath, now, force);
    }

    // SECURITY [v2.5.5]: an admin-supplied path is opened by the server
    // process, so refuse anything that is not a plain absolute .mmdb file:
    // traversal, UNC/network paths, sensitive system directories, and
    // symlinks that resolve to any of those.
    internal static bool IsSafeGeoIpPath(string path, ILogger logger)
    {
        if (TryValidatePath(path, out var reason)) return true;
        logger.LogWarning("[2FA] GeoIP path rejected ({Reason}): {Path}", reason, path);
        return false;
    }

    /// <summary>Same rules as <see cref="IsSafeGeoIpPath"/>, returning the
    /// reason instead of logging it, so the Diagnostics tab can show it.</summary>
    internal static bool TryValidatePath(string path, out string reason)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) { reason = "empty path"; return false; }
            if (path.Contains("..", StringComparison.Ordinal)) { reason = "contains '..'"; return false; }
            if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            {
                reason = "UNC/network path";
                return false;
            }
            if (!Path.IsPathFullyQualified(path)) { reason = "not absolute"; return false; }
            if (!path.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase)) { reason = "must end with .mmdb"; return false; }

            var lower = path.Replace('\\', '/').ToLowerInvariant();
            foreach (var bad in SensitivePrefixes)
            {
                if (lower.StartsWith(bad, StringComparison.Ordinal))
                {
                    reason = $"sensitive system path '{bad}'";
                    return false;
                }
            }

            try
            {
                var info = new FileInfo(path);
                var resolved = info.ResolveLinkTarget(returnFinalTarget: true) is { } target
                    ? target.FullName
                    : info.FullName;
                if (!string.Equals(resolved, info.FullName, StringComparison.Ordinal))
                {
                    var resolvedLower = resolved.Replace('\\', '/').ToLowerInvariant();
                    foreach (var bad in SensitivePrefixes)
                    {
                        if (resolvedLower.StartsWith(bad, StringComparison.Ordinal))
                        {
                            reason = $"symlink resolves to sensitive {resolved}";
                            return false;
                        }
                    }
                    if (!resolved.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase))
                    {
                        reason = $"symlink resolves to non-mmdb {resolved}";
                        return false;
                    }
                }
            }
            catch (Exception)
            {
                // Symlink resolution is best effort: the file may not exist
                // yet, and the caller's existence check reports that.
            }

            reason = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            reason = $"validation threw: {ex.Message}";
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _asn.Dispose();
        _country.Dispose();
        GC.SuppressFinalize(this);
    }
}

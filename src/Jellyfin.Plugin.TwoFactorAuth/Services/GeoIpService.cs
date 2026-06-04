using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using MaxMind.Db;
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
/// </summary>
public class GeoIpService : IDisposable
{
    public record Lookup(uint Asn, string AsnOrg, string Country);

    public static readonly Lookup Unknown = new(0, string.Empty, string.Empty);

    private readonly ILogger<GeoIpService> _logger;
    private Reader? _asnReader;
    private Reader? _countryReader;
    private DateTime _asnLoadedAt;
    private DateTime _countryLoadedAt;
    private string? _loadedAsnPath;
    private string? _loadedCountryPath;
    private bool _disposed;

    public GeoIpService(ILogger<GeoIpService> logger)
    {
        _logger = logger;
    }

    public bool AsnAvailable => _asnReader is not null;
    public bool CountryAvailable => _countryReader is not null;

    public Lookup Resolve(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return Unknown;
        ReloadIfConfigChanged();
        if (_asnReader is null && _countryReader is null) return Unknown;
        if (!IPAddress.TryParse(ip, out var addr)) return Unknown;

        uint asn = 0;
        string asnOrg = string.Empty;
        string country = string.Empty;

        try
        {
            if (_asnReader is not null)
            {
                var rec = _asnReader.Find<Dictionary<string, object>>(addr);
                if (rec is not null)
                {
                    if (rec.TryGetValue("autonomous_system_number", out var asnVal))
                    {
                        asn = Convert.ToUInt32(asnVal, System.Globalization.CultureInfo.InvariantCulture);
                    }
                    if (rec.TryGetValue("autonomous_system_organization", out var orgVal))
                    {
                        asnOrg = orgVal?.ToString() ?? string.Empty;
                    }
                }
            }
            if (_countryReader is not null)
            {
                var rec = _countryReader.Find<Dictionary<string, object>>(addr);
                if (rec is not null
                    && rec.TryGetValue("country", out var countryNode)
                    && countryNode is Dictionary<string, object> countryDict
                    && countryDict.TryGetValue("iso_code", out var iso))
                {
                    country = iso?.ToString() ?? string.Empty;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] GeoIP lookup failed for {Ip}", ip);
        }

        return new Lookup(asn, asnOrg, country);
    }

    private void ReloadIfConfigChanged()
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null) return;

        var asnPath = config.GeoIpAsnDbPath;
        var countryPath = config.GeoIpCountryDbPath;

        if (!string.Equals(asnPath, _loadedAsnPath, StringComparison.Ordinal))
        {
            _asnReader?.Dispose();
            _asnReader = null;
            _loadedAsnPath = asnPath;
            if (!string.IsNullOrWhiteSpace(asnPath) && IsSafeGeoIpPath(asnPath) && File.Exists(asnPath))
            {
                try
                {
                    _asnReader = new Reader(asnPath);
                    _asnLoadedAt = DateTime.UtcNow;
                    _logger.LogInformation("[2FA] Loaded GeoLite2-ASN from {Path}", asnPath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[2FA] Failed to open GeoLite2-ASN at {Path}", asnPath);
                }
            }
        }

        if (!string.Equals(countryPath, _loadedCountryPath, StringComparison.Ordinal))
        {
            _countryReader?.Dispose();
            _countryReader = null;
            _loadedCountryPath = countryPath;
            if (!string.IsNullOrWhiteSpace(countryPath) && IsSafeGeoIpPath(countryPath) && File.Exists(countryPath))
            {
                try
                {
                    _countryReader = new Reader(countryPath);
                    _countryLoadedAt = DateTime.UtcNow;
                    _logger.LogInformation("[2FA] Loaded GeoLite2-Country from {Path}", countryPath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[2FA] Failed to open GeoLite2-Country at {Path}", countryPath);
                }
            }
        }
    }

    /// <summary>SECURITY [v2.5.5] (Finding 8): only accept GeoIP DB paths that
    /// are absolute, end with `.mmdb`, do not traverse via `..`, and (on
    /// Windows) are not UNC paths. Reject sensitive Unix system paths
    /// outright. Failing the check leaves the reader null = GeoIP inactive,
    /// which degrades gracefully.</summary>
    private bool IsSafeGeoIpPath(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            if (path.Contains("..", StringComparison.Ordinal))
            {
                _logger.LogWarning("[2FA] GeoIP path rejected (contains '..'): {Path}", path);
                return false;
            }
            if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            {
                _logger.LogWarning("[2FA] GeoIP path rejected (UNC/network path): {Path}", path);
                return false;
            }
            if (!Path.IsPathFullyQualified(path))
            {
                _logger.LogWarning("[2FA] GeoIP path rejected (not absolute): {Path}", path);
                return false;
            }
            if (!path.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("[2FA] GeoIP path rejected (must end with .mmdb): {Path}", path);
                return false;
            }
            var lower = path.Replace('\\', '/').ToLowerInvariant();
            foreach (var bad in new[] { "/etc/", "/proc/", "/sys/", "/dev/", "/root/.ssh", "/run/secrets" })
            {
                if (lower.StartsWith(bad, StringComparison.Ordinal))
                {
                    _logger.LogWarning("[2FA] GeoIP path rejected (sensitive system path '{Bad}'): {Path}", bad, path);
                    return false;
                }
            }

            // SECURITY [v2.5.5] (N-A3): resolve symlinks. The string-level
            // check above can be bypassed by `ln -s /etc/shadow legit.mmdb`
            // — the path string starts with /opt/, the suffix is .mmdb, but
            // the actual file the loader will mmap is /etc/shadow. Re-apply
            // the sensitive-path blocklist against the resolved target.
            try
            {
                var info = new FileInfo(path);
                var resolved = info.ResolveLinkTarget(returnFinalTarget: true) is { } target
                    ? target.FullName
                    : info.FullName;
                if (!string.Equals(resolved, info.FullName, StringComparison.Ordinal))
                {
                    var resolvedLower = resolved.Replace('\\', '/').ToLowerInvariant();
                    foreach (var bad in new[] { "/etc/", "/proc/", "/sys/", "/dev/", "/root/.ssh", "/run/secrets" })
                    {
                        if (resolvedLower.StartsWith(bad, StringComparison.Ordinal))
                        {
                            _logger.LogWarning("[2FA] GeoIP path rejected: symlink {Path} resolves to sensitive {Resolved}", path, resolved);
                            return false;
                        }
                    }
                    if (!resolved.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogWarning("[2FA] GeoIP path rejected: symlink {Path} resolves to non-mmdb {Resolved}", path, resolved);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[2FA] GeoIP symlink resolution non-fatal for {Path}", path);
                // Fall through — the file may not exist yet, which is handled
                // by the caller's File.Exists check.
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] GeoIP path validation threw, treating as unsafe: {Path}", path);
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _asnReader?.Dispose();
        _countryReader?.Dispose();
        GC.SuppressFinalize(this);
    }
}

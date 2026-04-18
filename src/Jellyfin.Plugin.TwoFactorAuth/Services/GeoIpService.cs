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
            if (!string.IsNullOrWhiteSpace(asnPath) && File.Exists(asnPath))
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
            if (!string.IsNullOrWhiteSpace(countryPath) && File.Exists(countryPath))
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

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _asnReader?.Dispose();
        _countryReader?.Dispose();
        GC.SuppressFinalize(this);
    }
}

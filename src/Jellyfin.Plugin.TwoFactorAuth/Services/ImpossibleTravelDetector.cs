using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MaxMind.Db;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Flags sign-ins where the geographic distance from the user's
/// last-known location exceeds what's physically possible in the elapsed
/// time. Tuned to commercial-jet cruise speed (~900 km/h default) so:
///  - Same city, 30s apart → 0 km/h, fine
///  - London ↔ Paris, 4h apart → ~85 km/h, fine
///  - London ↔ Tokyo, 30min apart → ~19000 km/h, IMPOSSIBLE → alert
///
/// Requires GeoLite2-City.mmdb to resolve lat/lon. Falls back to skipping
/// when only ASN/Country dbs are available (handled by SuspiciousLoginDetector
/// instead).</summary>
public class ImpossibleTravelDetector : IDisposable
{
    private readonly UserTwoFactorStore _store;
    private readonly NotificationService _notifications;
    private readonly ILogger<ImpossibleTravelDetector> _logger;
    private Reader? _cityReader;
    private string? _loadedCityPath;
    private bool _disposed;

    public ImpossibleTravelDetector(UserTwoFactorStore store, NotificationService notifications, ILogger<ImpossibleTravelDetector> logger)
    {
        _store = store;
        _notifications = notifications;
        _logger = logger;
    }

    /// <summary>Compare current sign-in location to last-known. Fires a
    /// notification + audit when the implied travel speed exceeds the
    /// configured threshold. Updates last-known to the new location either
    /// way (so consecutive impossible-travel events don't fire repeatedly).</summary>
    public async Task ObserveAsync(Guid userId, string username, string ip)
    {
        if (userId == Guid.Empty) return;
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.ImpossibleTravelEnabled) return;

        ReloadIfConfigChanged();
        if (_cityReader is null) return;
        if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip, out var addr)) return;

        var (lat, lon, country, asn) = ResolveCity(addr);
        if (lat == 0 && lon == 0) return; // No usable geo data

        var now = DateTime.UtcNow;
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var previous = data.LastLocation;

        if (previous is not null && previous.Latitude != 0 && previous.Longitude != 0)
        {
            var distanceKm = HaversineKm(previous.Latitude, previous.Longitude, lat, lon);
            var elapsedHours = Math.Max(0.0001, (now - previous.At).TotalHours);
            var speedKmh = distanceKm / elapsedHours;

            // Same-city or near-zero distance — no alert. Filter at >50km to
            // avoid noise from city-level resolution variation.
            if (distanceKm > 50 && speedKmh > config.ImpossibleTravelMaxKmh)
            {
                _logger.LogWarning("[2FA] Impossible travel for {User}: {Dist}km in {Hours}h = {Speed}km/h",
                    username, (int)distanceKm, elapsedHours, (int)speedKmh);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _notifications.NotifySuspiciousLoginAsync(
                            username, ip, country,
                            $"Impossible travel: {(int)distanceKm}km in {elapsedHours:F1}h ≈ {(int)speedKmh}km/h from {previous.Country}",
                            asn).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[2FA] Impossible-travel notification failed");
                    }
                });
            }
        }

        // Update the cache to the current location regardless.
        await _store.MutateAsync(userId, ud =>
        {
            ud.LastLocation = new LastKnownLocation
            {
                Asn = asn,
                Country = country,
                Latitude = lat,
                Longitude = lon,
                At = now,
                Ip = ip,
            };
        }).ConfigureAwait(false);
    }

    private (double Lat, double Lon, string Country, uint Asn) ResolveCity(IPAddress addr)
    {
        try
        {
            var rec = _cityReader!.Find<Dictionary<string, object>>(addr);
            if (rec is null) return (0, 0, string.Empty, 0);

            double lat = 0, lon = 0;
            string country = string.Empty;
            if (rec.TryGetValue("location", out var locObj) && locObj is Dictionary<string, object> loc)
            {
                if (loc.TryGetValue("latitude", out var la)) lat = Convert.ToDouble(la, System.Globalization.CultureInfo.InvariantCulture);
                if (loc.TryGetValue("longitude", out var lo)) lon = Convert.ToDouble(lo, System.Globalization.CultureInfo.InvariantCulture);
            }
            if (rec.TryGetValue("country", out var coObj) && coObj is Dictionary<string, object> co
                && co.TryGetValue("iso_code", out var iso))
            {
                country = iso?.ToString() ?? string.Empty;
            }
            return (lat, lon, country, 0);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] City lookup failed for {Ip}", addr);
            return (0, 0, string.Empty, 0);
        }
    }

    private void ReloadIfConfigChanged()
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null) return;
        var path = config.GeoIpCityDbPath;
        if (string.Equals(path, _loadedCityPath, StringComparison.Ordinal)) return;

        _cityReader?.Dispose();
        _cityReader = null;
        _loadedCityPath = path;
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            try
            {
                _cityReader = new Reader(path);
                _logger.LogInformation("[2FA] Loaded GeoLite2-City from {Path}", path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Failed to open GeoLite2-City at {Path}", path);
            }
        }
    }

    /// <summary>Great-circle distance in kilometres between two coords.</summary>
    private static double HaversineKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double R = 6371.0;
        var dLat = (lat2 - lat1) * Math.PI / 180;
        var dLon = (lon2 - lon1) * Math.PI / 180;
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                Math.Cos(lat1 * Math.PI / 180) * Math.Cos(lat2 * Math.PI / 180) *
                Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return 2 * R * Math.Asin(Math.Sqrt(a));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cityReader?.Dispose();
        GC.SuppressFinalize(this);
    }
}

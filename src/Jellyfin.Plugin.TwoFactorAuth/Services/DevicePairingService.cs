using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class DevicePairingService : IDisposable
{
    private const string ValidChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private const int CodeLength = 5;

    private readonly ILogger<DevicePairingService> _logger;
    private readonly ConcurrentDictionary<string, PairingRequest> _activePairings = new();
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    public DevicePairingService(ILogger<DevicePairingService> logger)
    {
        _logger = logger;
        _cleanupTimer = new Timer(_ => CleanupExpired(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Creates a new pairing request for a TV or limited-input device.
    /// </summary>
    public PairingRequest CreatePairing(
        Guid userId,
        string username,
        string deviceId,
        string deviceName,
        string challengeToken)
    {
        var ttlSeconds = Plugin.Instance?.Configuration.PairingCodeTtlSeconds ?? 300;
        var now = DateTime.UtcNow;
        var code = GenerateCode();

        var request = new PairingRequest
        {
            Code = code,
            UserId = userId,
            Username = username,
            DeviceId = deviceId,
            DeviceName = deviceName,
            ChallengeToken = challengeToken,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            Status = PairingStatus.Pending,
        };

        _activePairings[code] = request;
        _logger.LogInformation(
            "Created pairing request '{Code}' for user '{Username}' (device: '{DeviceName}')",
            code, username, deviceName);

        return request;
    }

    /// <summary>
    /// Returns the pairing request for the given code if it exists and has not expired.
    /// </summary>
    public PairingRequest? GetPairing(string code)
    {
        if (!_activePairings.TryGetValue(code, out var request))
        {
            return null;
        }

        if (request.ExpiresAt <= DateTime.UtcNow)
        {
            request.Status = PairingStatus.Expired;
            return null;
        }

        return request;
    }

    /// <summary>
    /// Returns all pending pairing requests that have not yet expired.
    /// </summary>
    public IReadOnlyList<PairingRequest> GetPendingPairings()
    {
        var now = DateTime.UtcNow;
        return _activePairings.Values
            .Where(r => r.Status == PairingStatus.Pending && r.ExpiresAt > now)
            .ToList()
            .AsReadOnly();
    }

    /// <summary>
    /// Approves a pending pairing request. Returns true if the request was in Pending state.
    /// </summary>
    public bool ApprovePairing(string code)
    {
        if (!_activePairings.TryGetValue(code, out var request))
        {
            return false;
        }

        if (request.Status != PairingStatus.Pending)
        {
            return false;
        }

        request.Status = PairingStatus.Approved;
        _logger.LogInformation("Pairing request '{Code}' approved", code);
        return true;
    }

    /// <summary>
    /// Denies a pending pairing request. Returns true if the request was in Pending state.
    /// </summary>
    public bool DenyPairing(string code)
    {
        if (!_activePairings.TryGetValue(code, out var request))
        {
            return false;
        }

        if (request.Status != PairingStatus.Pending)
        {
            return false;
        }

        request.Status = PairingStatus.Denied;
        _logger.LogInformation("Pairing request '{Code}' denied", code);
        return true;
    }

    private static string GenerateCode()
    {
        var chars = new char[CodeLength];
        for (var i = 0; i < CodeLength; i++)
        {
            chars[i] = ValidChars[RandomNumberGenerator.GetInt32(ValidChars.Length)];
        }

        return new string(chars);
    }

    private void CleanupExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in _activePairings)
        {
            var r = kvp.Value;
            if (r.ExpiresAt <= now || r.Status is PairingStatus.Approved or PairingStatus.Denied or PairingStatus.Expired)
            {
                _activePairings.TryRemove(kvp.Key, out _);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _cleanupTimer.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

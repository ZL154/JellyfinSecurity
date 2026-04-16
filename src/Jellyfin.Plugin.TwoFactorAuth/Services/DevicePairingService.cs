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
    private readonly ConcurrentDictionary<string, string> _pollTokenIndex = new();
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
    /// TV-initiated pairing: device asks the server for a code + opaque poll token.
    /// The user types the displayed code into the admin UI, which approves it and
    /// stashes a Quick Connect secret the TV can finalize with.
    /// </summary>
    public PairingRequest InitiatePairing(string username, string deviceName)
    {
        var ttlSeconds = Plugin.Instance?.Configuration.PairingCodeTtlSeconds ?? 300;
        var now = DateTime.UtcNow;
        var code = GenerateCode();
        var pollToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        var request = new PairingRequest
        {
            Code = code,
            UserId = Guid.Empty,
            Username = username ?? string.Empty,
            DeviceId = string.Empty,
            DeviceName = deviceName ?? string.Empty,
            ChallengeToken = string.Empty,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            Status = PairingStatus.Pending,
            PollToken = pollToken,
        };

        _activePairings[code] = request;
        _pollTokenIndex[pollToken] = code;
        _logger.LogInformation(
            "TV pairing initiated, code '{Code}' for user '{Username}' device '{DeviceName}'",
            code, username, deviceName);
        return request;
    }

    /// <summary>Look up a pairing request by its opaque poll token (TV polling).</summary>
    public PairingRequest? PollByToken(string pollToken)
    {
        if (!_pollTokenIndex.TryGetValue(pollToken, out var code))
        {
            return null;
        }

        if (!_activePairings.TryGetValue(code, out var request))
        {
            return null;
        }

        if (request.ExpiresAt <= DateTime.UtcNow && request.Status == PairingStatus.Pending)
        {
            request.Status = PairingStatus.Expired;
        }

        return request;
    }

    /// <summary>Approve a pending pairing and stash the Quick Connect secret for the TV to finalize with.</summary>
    public bool ApprovePairingWithSecret(string code, string quickConnectSecret)
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
        request.QuickConnectSecret = quickConnectSecret;
        _logger.LogInformation("Pairing request '{Code}' approved with QC secret", code);
        return true;
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
            // Keep approved records for a short window so the TV can pick up its QC secret.
            var isTerminal = r.Status is PairingStatus.Denied or PairingStatus.Expired;
            var approvedStale = r.Status == PairingStatus.Approved && r.ExpiresAt <= now;
            if (r.ExpiresAt <= now && r.Status == PairingStatus.Pending)
            {
                r.Status = PairingStatus.Expired;
                isTerminal = true;
            }

            if (isTerminal || approvedStale)
            {
                _activePairings.TryRemove(kvp.Key, out _);
                if (!string.IsNullOrEmpty(r.PollToken))
                {
                    _pollTokenIndex.TryRemove(r.PollToken, out _);
                }
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

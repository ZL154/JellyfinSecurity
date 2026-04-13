using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class EmailOtpService
{
    private readonly ILogger<EmailOtpService> _logger;

    private readonly ConcurrentDictionary<string, EmailOtpEntry> _pendingCodes = new();
    private readonly ConcurrentDictionary<Guid, List<DateTime>> _sendHistory = new();

    private const int MaxSendsPerWindow = 3;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromMinutes(10);

    public EmailOtpService(ILogger<EmailOtpService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Generates a 6-digit OTP and stores it against the given challengeToken.
    /// Returns the code and whether it was "sent" (logged). Actual email delivery
    /// requires Jellyfin's mail infrastructure wired externally.
    /// </summary>
    public (string code, bool sent) GenerateAndSendCode(Guid userId, string username, string? email, string challengeToken)
    {
        CleanupExpired();

        if (!CheckRateLimit(userId))
        {
            _logger.LogWarning(
                "Email OTP rate limit exceeded for user '{Username}' ({UserId})",
                username, userId);
            return (string.Empty, false);
        }

        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");

        var ttlSeconds = Plugin.Instance?.Configuration.EmailOtpTtlSeconds ?? 300;
        var now = DateTime.UtcNow;
        var entry = new EmailOtpEntry
        {
            Code = code,
            UserId = userId,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            IsUsed = false
        };

        _pendingCodes[challengeToken] = entry;

        RecordSend(userId, now);

        _logger.LogInformation(
            "Email OTP generated for user '{Username}' ({UserId}), expires at {ExpiresAt}. " +
            "Email delivery target: {Email}. Code logged for debugging only — wire INotificationManager for real delivery.",
            username, userId, entry.ExpiresAt, email ?? "(no address)");

        return (code, true);
    }

    /// <summary>
    /// Validates a submitted code against the stored entry for the given challenge token.
    /// Marks the entry as used on success.
    /// </summary>
    public bool ValidateCode(string challengeToken, string code)
    {
        if (!_pendingCodes.TryGetValue(challengeToken, out var entry))
        {
            return false;
        }

        if (entry.IsUsed || DateTime.UtcNow > entry.ExpiresAt)
        {
            return false;
        }

        var storedBytes = Encoding.UTF8.GetBytes(entry.Code);
        var submittedBytes = Encoding.UTF8.GetBytes(code);

        if (!CryptographicOperations.FixedTimeEquals(storedBytes, submittedBytes))
        {
            return false;
        }

        entry.IsUsed = true;
        return true;
    }

    /// <summary>
    /// Removes all expired entries from the pending codes dictionary.
    /// </summary>
    public void CleanupExpired()
    {
        var now = DateTime.UtcNow;

        foreach (var kvp in _pendingCodes)
        {
            if (kvp.Value.ExpiresAt < now || kvp.Value.IsUsed)
            {
                _pendingCodes.TryRemove(kvp.Key, out _);
            }
        }
    }

    private bool CheckRateLimit(Guid userId)
    {
        var history = _sendHistory.GetOrAdd(userId, _ => new List<DateTime>());
        var cutoff = DateTime.UtcNow - RateLimitWindow;

        lock (history)
        {
            history.RemoveAll(t => t < cutoff);
            return history.Count < MaxSendsPerWindow;
        }
    }

    private void RecordSend(Guid userId, DateTime sentAt)
    {
        var history = _sendHistory.GetOrAdd(userId, _ => new List<DateTime>());
        lock (history)
        {
            history.Add(sentAt);
        }
    }

    private sealed class EmailOtpEntry
    {
        public string Code { get; set; } = string.Empty;
        public Guid UserId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; }
    }
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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
    /// Generates a 6-digit OTP, stores it against the challenge token, and sends it via SMTP.
    /// Returns (code, sent). If SMTP isn't configured, code is generated but only logged.
    /// </summary>
    public async Task<(string code, bool sent)> GenerateAndSendCodeAsync(Guid userId, string username, string? email, string challengeToken)
    {
        CleanupExpired();

        if (!CheckRateLimit(userId))
        {
            _logger.LogWarning("Email OTP rate limit exceeded for {Username}", username);
            return (string.Empty, false);
        }

        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");
        var ttlSeconds = Plugin.Instance?.Configuration.EmailOtpTtlSeconds ?? 300;
        var now = DateTime.UtcNow;

        _pendingCodes[challengeToken] = new EmailOtpEntry
        {
            Code = code,
            UserId = userId,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            IsUsed = false,
        };

        RecordSend(userId, now);

        var sent = await TrySendEmailAsync(email, username, code, ttlSeconds).ConfigureAwait(false);
        return (code, sent);
    }

    private async Task<bool> TrySendEmailAsync(string? email, string username, string code, int ttlSeconds)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null)
        {
            _logger.LogWarning("Email OTP: plugin not initialized");
            return false;
        }

        if (string.IsNullOrEmpty(email))
        {
            _logger.LogWarning("Email OTP for {User}: no email address configured. configure SMTP in plugin settings", username);
            return false;
        }

        if (string.IsNullOrEmpty(config.SmtpHost) || string.IsNullOrEmpty(config.SmtpFromAddress))
        {
            _logger.LogWarning("Email OTP for {User}: SMTP not configured (host or from address missing). configure SMTP in plugin settings", username);
            return false;
        }

        try
        {
            using var smtp = new SmtpClient(config.SmtpHost, config.SmtpPort)
            {
                EnableSsl = config.SmtpUseSsl,
                Timeout = 10000,
            };

            if (!string.IsNullOrEmpty(config.SmtpUsername))
            {
                smtp.Credentials = new NetworkCredential(config.SmtpUsername, config.SmtpPassword);
            }

            using var msg = new MailMessage
            {
                From = new MailAddress(config.SmtpFromAddress, string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName),
                Subject = "Jellyfin sign-in code",
                Body = $"Hi {username},\n\nYour Jellyfin sign-in code is:\n\n  {code}\n\nThis code expires in {ttlSeconds / 60} minutes. If you did not request this code, change your password and revoke active sessions immediately.\n\n— Jellyfin 2FA",
                IsBodyHtml = false,
            };
            msg.To.Add(email);

            await smtp.SendMailAsync(msg).ConfigureAwait(false);
            _logger.LogInformation("Email OTP sent to {Email} for {User}", email, username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email OTP SMTP send failed for {User}", username);
            return false;
        }
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

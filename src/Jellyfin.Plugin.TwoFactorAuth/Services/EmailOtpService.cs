using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
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

        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6", CultureInfo.InvariantCulture);
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

    /// <summary>
    /// Public test method — sends a "Hello from Jellyfin 2FA" mail using current SMTP config.
    /// Throws on failure so callers can surface the error.
    /// </summary>
    public async Task SendTestEmailAsync(string toAddress)
    {
        var config = Plugin.Instance?.Configuration ?? throw new InvalidOperationException("Plugin not initialized");
        if (string.IsNullOrEmpty(config.SmtpHost) || string.IsNullOrEmpty(config.SmtpFromAddress))
        {
            throw new InvalidOperationException("SMTP host and from address must be set in plugin settings.");
        }

        var msg = BuildMimeMessage(
            config.SmtpFromAddress,
            string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName,
            toAddress,
            "Jellyfin 2FA — SMTP test",
            "If you received this, your SMTP configuration is working. Sent at " + DateTime.UtcNow.ToString("u") + " UTC.");

        await SendMimeMessageAsync(config, msg).ConfigureAwait(false);
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
            var msg = BuildMimeMessage(
                config.SmtpFromAddress,
                string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName,
                email,
                "Jellyfin sign-in code",
                $"Hi {username},\n\nYour Jellyfin sign-in code is:\n\n  {code}\n\nThis code expires in {ttlSeconds / 60} minutes. If you did not request this code, change your password and revoke active sessions immediately.\n\n— Jellyfin 2FA");

            await SendMimeMessageAsync(config, msg).ConfigureAwait(false);

            // Mask the local-part of the email before logging — full addresses
            // in log files are PII (GDPR / general data minimisation).
            _logger.LogInformation("Email OTP sent to {Email} for {User}", MaskEmail(email), username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email OTP SMTP send failed for {User}", username);
            return false;
        }
    }

    private static MimeMessage BuildMimeMessage(string fromAddress, string fromName, string toAddress, string subject, string body)
    {
        var msg = new MimeMessage();
        msg.From.Add(new MailboxAddress(fromName, fromAddress));
        msg.To.Add(MailboxAddress.Parse(toAddress));
        msg.Subject = subject;
        msg.Body = new TextPart("plain") { Text = body };
        return msg;
    }

    /// <summary>
    /// Send a MimeMessage via MailKit, honouring the plugin's SMTP config.
    /// Issue #29: replaces System.Net.Mail.SmtpClient which only does STARTTLS
    /// and silently fails on port 465 (Implicit TLS). MailKit picks the
    /// right transport per port:
    ///   - Port 465 → SslOnConnect (Implicit TLS / SMTPS)
    ///   - Port 587 → StartTls
    ///   - Other ports + UseSsl=true → StartTlsWhenAvailable
    ///   - UseSsl=false → None (plaintext, opt-in for local testing)
    /// </summary>
    internal static SecureSocketOptions PickSocketOptions(int port, bool useSsl)
    {
        if (!useSsl) return SecureSocketOptions.None;
        // Port 465 is Implicit TLS by spec — the client MUST initiate an SSL
        // handshake before sending any SMTP commands. STARTTLS on 465 is
        // wrong and the silent-failure root cause of issue #29.
        if (port == 465) return SecureSocketOptions.SslOnConnect;
        // Port 587 is the standard submission port using STARTTLS.
        if (port == 587) return SecureSocketOptions.StartTls;
        // Anything else: try STARTTLS if the server advertises it, otherwise
        // proceed plaintext. Better than refusing to connect.
        return SecureSocketOptions.StartTlsWhenAvailable;
    }

    private async Task SendMimeMessageAsync(Configuration.PluginConfiguration config, MimeMessage msg)
    {
        using var smtp = new SmtpClient
        {
            // 10s connect/handshake budget — same as the old SmtpClient.Timeout.
            Timeout = 10_000,
        };

        var options = PickSocketOptions(config.SmtpPort, config.SmtpUseSsl);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await smtp.ConnectAsync(config.SmtpHost, config.SmtpPort, options, cts.Token).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(config.SmtpUsername))
            {
                await smtp.AuthenticateAsync(config.SmtpUsername, config.SmtpPassword, cts.Token).ConfigureAwait(false);
            }
            await smtp.SendAsync(msg, cts.Token).ConfigureAwait(false);
        }
        finally
        {
            if (smtp.IsConnected)
            {
                try { await smtp.DisconnectAsync(quit: true, cts.Token).ConfigureAwait(false); }
                catch { /* best-effort QUIT */ }
            }
        }
    }

    /// <summary>Mask an email address so log files don't contain the full
    /// PII string. "alice@example.com" -> "a***@example.com". Domain is
    /// preserved because it's typically the IdP host (gmail/outlook/...) and
    /// useful for debugging delivery issues.</summary>
    private static string MaskEmail(string? email)
    {
        if (string.IsNullOrEmpty(email)) return "(empty)";
        var at = email.IndexOf('@');
        if (at <= 0) return "***";
        var local = email.AsSpan(0, at);
        var domain = email.AsSpan(at);
        return local.Length == 1
            ? string.Concat(local, "***", domain)
            : string.Concat(local[..1], "***", domain);
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

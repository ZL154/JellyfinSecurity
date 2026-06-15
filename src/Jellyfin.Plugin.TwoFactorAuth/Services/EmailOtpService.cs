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

    // SECURITY [v2.5.5] (Finding 5): per-process random HMAC key.
    // Restarts invalidate pending OTPs (5-min TTL anyway, acceptable) and
    // a memory dump can no longer surface usable codes — only the HMAC
    // output is stored, not the plaintext digits.
    private static readonly byte[] _otpHmacKey = RandomNumberGenerator.GetBytes(32);

    private static byte[] HashOtp(string code)
    {
        return HMACSHA256.HashData(_otpHmacKey, Encoding.UTF8.GetBytes(code));
    }

    public EmailOtpService(ILogger<EmailOtpService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Generates an 8-digit OTP (v2.5.5: raised from 6 digits — 10^6 space was
    /// brute-forceable at ~8 hours under the existing rate limits per audit
    /// Finding 5), HMAC-hashes it for in-memory storage, and sends the
    /// plaintext via SMTP. Returns (code, sent). If SMTP isn't configured,
    /// code is generated but only logged.
    /// </summary>
    public async Task<(string code, bool sent)> GenerateAndSendCodeAsync(Guid userId, string username, string? email, string challengeToken)
    {
        CleanupExpired();

        if (!CheckRateLimit(userId))
        {
            _logger.LogWarning("Email OTP rate limit exceeded for {Username}", username);
            return (string.Empty, false);
        }

        // SECURITY [v2.5.5] (Finding 5): 8 digits, code space 10^8 = 100M.
        // At the existing 10/min/IP + 15/15min/user rate limit a full-space
        // brute force now takes weeks instead of hours.
        var code = RandomNumberGenerator.GetInt32(10_000_000, 100_000_000).ToString("D8", CultureInfo.InvariantCulture);
        var ttlSeconds = Plugin.Instance?.Configuration.EmailOtpTtlSeconds ?? 300;
        var now = DateTime.UtcNow;

        _pendingCodes[challengeToken] = new EmailOtpEntry
        {
            // SECURITY [v2.5.5] (Finding 5): never store plaintext in memory.
            // Only the HMAC-SHA256 is retained — a heap dump yields nothing
            // useful even mid-flight.
            CodeHash = HashOtp(code),
            UserId = userId,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            IsUsed = false,
        };

        RecordSend(userId, now);

        var sent = await TrySendEmailAsync(email, username, code, ttlSeconds).ConfigureAwait(false);
        return (code, sent);
    }

    // [v2.5.6] (round-5d): user-self step-up email codes. Distinct dict from
    // _pendingCodes (which is keyed by challenge-token for the login flow)
    // because step-up codes are issued OUTSIDE a login challenge — when a
    // signed-in user wants to verify a factor mutation via email. Keyed by
    // userId, single-entry per user (a new send overwrites). 5-minute TTL.
    private readonly ConcurrentDictionary<Guid, EmailOtpEntry> _stepUpCodes = new();

    /// <summary>[v2.5.6] (round-5d): generate + send an email step-up code
    /// to the user's configured email. Returns true on successful send,
    /// false if SMTP isn't configured / send failed / rate-limited.</summary>
    public async Task<bool> SendStepUpCodeAsync(Guid userId, string username, string email)
    {
        CleanupExpired();
        if (!CheckRateLimit(userId))
        {
            _logger.LogWarning("Email step-up rate limit exceeded for {Username}", username);
            return false;
        }
        if (string.IsNullOrEmpty(email)) return false;
        var code = RandomNumberGenerator.GetInt32(10_000_000, 100_000_000).ToString("D8", CultureInfo.InvariantCulture);
        var ttlSeconds = Plugin.Instance?.Configuration.EmailOtpTtlSeconds ?? 300;
        var now = DateTime.UtcNow;
        _stepUpCodes[userId] = new EmailOtpEntry
        {
            CodeHash = HashOtp(code),
            UserId = userId,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            IsUsed = false,
        };
        RecordSend(userId, now);
        return await TrySendEmailAsync(email, username, code, ttlSeconds).ConfigureAwait(false);
    }

    /// <summary>[v2.5.6] (round-5d): validate + consume the user's step-up
    /// email code. Returns true on match (and removes the entry); false on
    /// no-match / expired / not-found. Same constant-time-compare and
    /// single-use semantics as the login flow's ValidateCode.</summary>
    public bool ValidateStepUpCode(Guid userId, string code)
    {
        if (!_stepUpCodes.TryGetValue(userId, out var entry)) return false;
        if (entry.IsUsed || DateTime.UtcNow > entry.ExpiresAt) return false;
        var submitted = HashOtp(code ?? string.Empty);
        if (!CryptographicOperations.FixedTimeEquals(entry.CodeHash, submitted)) return false;
        // Atomic single-use removal — same pattern as ValidateCode (N-A1).
        return _stepUpCodes.TryRemove(userId, out _);
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

    /// <summary>[v2.5.11] (#71) Email a one-time password-reset link. No-ops if
    /// SMTP isn't configured. Callers must NOT surface success/failure to the
    /// requester (anti-enumeration).</summary>
    public async Task SendPasswordResetAsync(string email, string username, string resetUrl, int ttlMinutes)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null || string.IsNullOrEmpty(email)
            || string.IsNullOrEmpty(config.SmtpHost) || string.IsNullOrEmpty(config.SmtpFromAddress))
        {
            _logger.LogWarning("Password-reset email for {User}: SMTP not configured or no email address.", username);
            return;
        }

        var msg = BuildMimeMessage(
            config.SmtpFromAddress,
            string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName,
            email,
            "Reset your Jellyfin password",
            $"Hi {username},\n\nWe received a request to reset your Jellyfin password. Open this link to choose a new one:\n\n  {resetUrl}\n\nThis link expires in {ttlMinutes} minutes and can be used once. If you didn't request this, you can ignore this email — your password won't change.\n\n— Jellyfin 2FA");

        await SendMimeMessageAsync(config, msg).ConfigureAwait(false);
        _logger.LogInformation("Password-reset email sent to {Email} for {User}", MaskEmail(email), username);
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

        // SECURITY [v2.5.5] (Finding 5): hash the submitted code with the
        // same per-process HMAC key and constant-time-compare against the
        // stored hash. Plaintext never leaves the email body.
        var submittedHash = HashOtp(code ?? string.Empty);
        if (!CryptographicOperations.FixedTimeEquals(entry.CodeHash, submittedHash))
        {
            // SECURITY [v2.5.9] (audit medium): bound wrong guesses per code.
            // The send path is rate-limited but ValidateCode wasn't — a held
            // challenge token could otherwise hammer the 10^8 space for the
            // full TTL. After 8 wrong attempts, consume the code so it can no
            // longer be guessed (the user must request a fresh one).
            if (System.Threading.Interlocked.Increment(ref entry.Attempts) >= 8)
            {
                _pendingCodes.TryRemove(challengeToken, out _);
            }
            return false;
        }

        // SECURITY [v2.5.5] (N-A1): atomically consume via TryRemove instead
        // of setting IsUsed=true on the shared entry. Two concurrent
        // ValidateCode calls with the same token both passed the
        // FixedTimeEquals check above (the mutation was non-atomic), and
        // both returned true. TryRemove returns true exactly once; the
        // losing call returns false even though it had the right code,
        // and ConsumeChallenge / the upstream auth flow correctly handles
        // the single-use semantic.
        if (!_pendingCodes.TryRemove(challengeToken, out _))
        {
            return false;
        }
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

        // SECURITY [v2.5.6] (third-audit Finding 8): also purge stale
        // _sendHistory entries. Prior versions only cleaned _pendingCodes,
        // leaving per-user List<DateTime> entries accumulated indefinitely
        // for any user who ever requested one email OTP. At scale this is
        // unbounded growth. Remove timestamps older than the rate-limit
        // window, drop the entry entirely if empty.
        var historyCutoff = now - RateLimitWindow;
        foreach (var kvp in _sendHistory)
        {
            lock (kvp.Value)
            {
                kvp.Value.RemoveAll(t => t < historyCutoff);
                if (kvp.Value.Count == 0)
                {
                    _sendHistory.TryRemove(kvp.Key, out _);
                }
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
        // SECURITY [v2.5.5] (Finding 5): renamed Code -> CodeHash. Now stores
        // a 32-byte HMAC-SHA256(plaintext) instead of plaintext digits.
        public byte[] CodeHash { get; set; } = Array.Empty<byte>();
        public Guid UserId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; }

        // SECURITY [v2.5.9] (audit medium): per-code wrong-guess counter.
        // Field (not property) so Interlocked.Increment can take it by ref.
        public int Attempts;
    }
}

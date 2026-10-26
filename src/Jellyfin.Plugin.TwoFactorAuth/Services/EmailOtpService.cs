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

    // [#259] Only SendAlertEmailsAsync reads the configuration through this,
    // so its SMTP session can be tested against a local fake server.
    private readonly Func<Configuration.PluginConfiguration?> _configAccessor;

    public EmailOtpService(ILogger<EmailOtpService> logger)
        : this(logger, () => Plugin.Instance?.Configuration)
    {
    }

    // [#259] Test seam, as in SecurityScoreService.
    internal EmailOtpService(ILogger<EmailOtpService> logger, Func<Configuration.PluginConfiguration?> configAccessor)
    {
        _logger = logger;
        _configAccessor = configAccessor;
    }

    /// <summary>[#259] Ceiling for one alert session, all addresses included.
    /// It keeps the admin test button, which waits for the result, under the
    /// 60-second read timeout common on reverse proxies. Tests shorten it.</summary>
    internal TimeSpan AlertSessionBudget { get; set; } = TimeSpan.FromSeconds(45);

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
    /// to the user's configured email. Returns (sent, code): sent is true on a
    /// successful email send; code is the plaintext (empty when rate-limited) so
    /// the caller can also deliver it over another channel such as Telegram
    /// ([#285]). The caller must not surface the code to anyone but the owner.</summary>
    public async Task<(bool Sent, string Code)> SendStepUpCodeAsync(Guid userId, string username, string email)
    {
        CleanupExpired();
        if (!CheckRateLimit(userId))
        {
            _logger.LogWarning("Email step-up rate limit exceeded for {Username}", username);
            return (false, string.Empty);
        }

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

        // The code is stored above, so even with no email address (Telegram-only
        // user) it can still be delivered by the caller and validated later.
        var sent = !string.IsNullOrEmpty(email)
            && await TrySendEmailAsync(email, username, code, ttlSeconds).ConfigureAwait(false);
        return (sent, code);
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

    // [#285] Pending Telegram chat links: a code BOUND to the candidate chat it
    // was sent to, so confirming proves control of THAT chat (a user can't get a
    // code delivered to chat A then confirm chat B). Keyed by userId, single
    // entry per user, 5-minute TTL; only the HMAC of the code is kept, like
    // every other OTP here. The controller delivers it through
    // NotificationService — this service must not depend on that one.
    private sealed class TelegramLinkPending
    {
        public byte[] CodeHash { get; init; } = Array.Empty<byte>();

        public string ChatId { get; init; } = string.Empty;

        public DateTime ExpiresAt { get; init; }
    }

    private readonly ConcurrentDictionary<Guid, TelegramLinkPending> _telegramLinkCodes = new();

    /// <summary>[#285] Issue a 6-digit code to confirm a Telegram chat link,
    /// bound to <paramref name="chatId"/>. The caller delivers it to that chat;
    /// a user who reads it back controls the chat. Shares the OTP rate limit so
    /// it can't be used to spam a chat. Returns the plaintext (empty when
    /// rate-limited).</summary>
    public string GenerateTelegramLinkCode(Guid userId, string chatId)
    {
        CleanupExpired();
        if (!CheckRateLimit(userId))
        {
            _logger.LogWarning("[2FA] Telegram link-code rate limit exceeded for {UserId}", userId);
            return string.Empty;
        }

        var code = RandomNumberGenerator.GetInt32(100_000, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
        _telegramLinkCodes[userId] = new TelegramLinkPending
        {
            CodeHash = HashOtp(code),
            ChatId = chatId,
            ExpiresAt = DateTime.UtcNow.AddSeconds(300),
        };
        RecordSend(userId, DateTime.UtcNow);
        return code;
    }

    /// <summary>[#285] Validate + consume a Telegram link code. Constant-time,
    /// single-use. Returns the bound chat ID on success (so the caller stores
    /// exactly the chat the code was sent to), or null on any mismatch/expiry.</summary>
    public string? ConfirmTelegramLinkCode(Guid userId, string code)
    {
        if (!_telegramLinkCodes.TryGetValue(userId, out var entry)) return null;
        if (DateTime.UtcNow > entry.ExpiresAt)
        {
            _telegramLinkCodes.TryRemove(userId, out _);
            return null;
        }

        var submitted = HashOtp(code ?? string.Empty);
        if (!CryptographicOperations.FixedTimeEquals(entry.CodeHash, submitted)) return null;
        return _telegramLinkCodes.TryRemove(userId, out var confirmed) ? confirmed.ChatId : null;
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

    /// <summary>[#259] True when the SMTP host and from address are set, the
    /// two settings every email this plugin sends needs.</summary>
    internal static bool IsSmtpConfigured(Configuration.PluginConfiguration config)
        => !string.IsNullOrEmpty(config.SmtpHost) && !string.IsNullOrEmpty(config.SmtpFromAddress);

    /// <summary>[#259] Email one security alert, the same title and message the
    /// other notification channels get, to each admin address: one message per
    /// address, so they do not see each other, over one SMTP connection, so a
    /// server that does not answer costs one timeout instead of one per
    /// address. Returns the addresses that failed, with the reason; if the
    /// session runs out of time, what already went out stays delivered and the
    /// rest are returned as failed. Throws when SMTP is not configured or the
    /// connection or sign-in fails, in which case nothing went out.</summary>
    public async Task<IReadOnlyList<(string Address, Exception Error)>> SendAlertEmailsAsync(
        IReadOnlyList<string> toAddresses, string subject, string body)
    {
        var config = _configAccessor() ?? throw new InvalidOperationException("Plugin not initialized");
        if (!IsSmtpConfigured(config))
        {
            throw new InvalidOperationException("SMTP host and from address must be set in plugin settings.");
        }

        var fromName = string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName;
        var failed = new List<(string Address, Exception Error)>();
        await WithSmtpConnectionAsync(config, AlertSessionBudget, async (smtp, ct) =>
        {
            for (var i = 0; i < toAddresses.Count; i++)
            {
                try
                {
                    var msg = BuildMimeMessage(config.SmtpFromAddress, fromName, toAddresses[i], subject, body);
                    await smtp.SendAsync(msg, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // A refused or malformed address leaves the session usable.
                    // A dropped connection or a session out of time does not:
                    // the rest fail for the same reason, and what already went
                    // out stays delivered.
                    failed.Add((toAddresses[i], ex));
                    if (!smtp.IsConnected || ct.IsCancellationRequested)
                    {
                        for (var j = i + 1; j < toAddresses.Count; j++)
                        {
                            failed.Add((toAddresses[j], ex));
                        }

                        break;
                    }
                }
            }
        }).ConfigureAwait(false);
        return failed;
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

    /// <summary>[#271] Welcome a user when their email is first registered for
    /// MFA: confirms the address is reachable (so a typo surfaces now, not at a
    /// locked-out sign-in) and tells them how to finish setting up. No-ops when
    /// SMTP is not configured or there is no address; never throws, so a dead
    /// mail server can't fail the "save my email" request that triggered it.</summary>
    public async Task SendWelcomeEmailAsync(string email, string username)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null || string.IsNullOrEmpty(email) || !IsSmtpConfigured(config))
        {
            return;
        }

        var serverName = string.IsNullOrWhiteSpace(config.SmtpFromName) ? "Jellyfin" : config.SmtpFromName;
        try
        {
            var msg = BuildMimeMessage(
                config.SmtpFromAddress,
                string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName,
                email,
                $"You're set up for {serverName} two-factor authentication",
                $"Hi {username},\n\nThis email address has been registered for two-factor authentication on {serverName}.\n\nWhat this means:\n  - When you sign in, you may be asked for a one-time code. If email codes are enabled for your account, the code is sent to this address.\n  - You can also set up an authenticator app (TOTP) or a passkey from your account's Two-Factor Auth settings for a faster, offline second factor.\n\nIf you didn't expect this, or you don't recognise {serverName}, let your administrator know — no code has been sent and your account is unchanged by this message.\n\n— {serverName} Security");

            await SendMimeMessageAsync(config, msg).ConfigureAwait(false);
            // Identify by username only — the address, even masked, is PII we
            // don't need in the log to triage a send.
            _logger.LogInformation("[2FA] Welcome email sent for {User}", username);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Welcome email for {User} failed", username);
        }
    }

    /// <summary>[#270] Email a one-time device sign-in code (a single-use,
    /// expiring app password) for a limited client that can't show the 2FA
    /// challenge. Returns true only when the mail was accepted. No-ops without
    /// SMTP or an address; never throws.</summary>
    public async Task<bool> SendDeviceCodeEmailAsync(string email, string username, string code, int ttlMinutes)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null || string.IsNullOrEmpty(email) || !IsSmtpConfigured(config))
        {
            return false;
        }

        var serverName = string.IsNullOrWhiteSpace(config.SmtpFromName) ? "Jellyfin" : config.SmtpFromName;
        try
        {
            var msg = BuildMimeMessage(
                config.SmtpFromAddress,
                string.IsNullOrEmpty(config.SmtpFromName) ? "Jellyfin 2FA" : config.SmtpFromName,
                email,
                $"Your one-time sign-in code for {serverName}",
                $"Hi {username},\n\nHere is a one-time sign-in code for a device that can't show the two-factor prompt (a TV app, Fire TV, etc.):\n\n    {code}\n\nType it as the PASSWORD in that app. It works once and expires in about {ttlMinutes} minutes. If you didn't request it, ignore this email and the code stays unused.\n\n— {serverName} Security");

            await SendMimeMessageAsync(config, msg).ConfigureAwait(false);
            _logger.LogInformation("[2FA] One-time device code emailed for {User}", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] One-time device code email for {User} failed", username);
            return false;
        }
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

    private static Task SendMimeMessageAsync(Configuration.PluginConfiguration config, MimeMessage msg)
        => WithSmtpConnectionAsync(config, TimeSpan.FromSeconds(30), (smtp, ct) => smtp.SendAsync(msg, ct));

    /// <summary>Connects and signs in to the configured SMTP server, runs
    /// <paramref name="use"/> on that connection, then sends QUIT.
    /// [#259] Shared by the single emails and by an alert that goes to several
    /// addresses over one connection.</summary>
    private static async Task WithSmtpConnectionAsync(
        Configuration.PluginConfiguration config,
        TimeSpan budget,
        Func<SmtpClient, CancellationToken, Task> use)
    {
        using var smtp = new SmtpClient
        {
            // 10s connect/handshake budget, same as the old SmtpClient.Timeout.
            Timeout = 10_000,
        };

        var options = PickSocketOptions(config.SmtpPort, config.SmtpUseSsl);
        using var cts = new CancellationTokenSource(budget);
        try
        {
            await smtp.ConnectAsync(config.SmtpHost, config.SmtpPort, options, cts.Token).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(config.SmtpUsername))
            {
                await smtp.AuthenticateAsync(config.SmtpUsername, config.SmtpPassword, cts.Token).ConfigureAwait(false);
            }
            await use(smtp, cts.Token).ConfigureAwait(false);
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

        // [#285] Same sweep for pending Telegram link codes.
        foreach (var kvp in _telegramLinkCodes)
        {
            if (kvp.Value.ExpiresAt < now)
            {
                _telegramLinkCodes.TryRemove(kvp.Key, out _);
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

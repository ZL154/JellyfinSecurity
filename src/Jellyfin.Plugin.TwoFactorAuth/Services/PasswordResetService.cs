using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [v2.5.11] (issue #71, ZEROX7) Self-service password recovery by email.
///
/// Premium reset-link flow: a request emails a one-time, expiring, single-use
/// link; the user sets a new password on the reset page. Designed to be safe:
/// <list type="bullet">
/// <item>No account/email enumeration — <see cref="RequestResetAsync"/> always
/// completes the same way whether or not the account exists or has an email.</item>
/// <item>Rate-limited per source IP and per identifier to stop email bombing.</item>
/// <item>SMTP-gated — does nothing unless the admin enabled it AND SMTP is set.</item>
/// <item>Tokens are 256-bit random, stored only as a SHA-256 hash, single-use,
/// and expire after <see cref="TokenTtlMinutes"/> minutes. In-memory only — a
/// restart invalidating pending resets is acceptable and safer than persisting
/// password-reset tokens to disk.</item>
/// </list>
/// </summary>
public class PasswordResetService
{
    private const int TokenTtlMinutes = 30;
    private const int TokenBytes = 32; // 256-bit

    private readonly IUserManager _userManager;
    private readonly EmailOtpService _email;
    private readonly ILogger<PasswordResetService> _logger;

    // tokenHash(hex) -> entry.
    private readonly ConcurrentDictionary<string, Entry> _tokens = new(StringComparer.Ordinal);
    private readonly RateLimiter _ipLimiter = new();
    private readonly RateLimiter _idLimiter = new();

    public PasswordResetService(IUserManager userManager, EmailOtpService email, ILogger<PasswordResetService> logger)
    {
        _userManager = userManager;
        _email = email;
        _logger = logger;
    }

    private sealed class Entry
    {
        public Guid UserId;
        public DateTime ExpiresAt;
    }

    /// <summary>True only when the admin enabled recovery AND SMTP is configured.
    /// Also gates the login-page "Forgot password?" link via public-config.</summary>
    public bool IsEnabled()
    {
        var c = Plugin.Instance?.Configuration;
        return c is { EnablePasswordRecovery: true }
            && !string.IsNullOrEmpty(c.SmtpHost)
            && !string.IsNullOrEmpty(c.SmtpFromAddress);
    }

    /// <summary>Request a reset link. Always returns without revealing whether
    /// the account exists or has an email (anti-enumeration). <paramref name="rateKey"/>
    /// is the client IP.</summary>
    public async Task RequestResetAsync(string? usernameOrEmail, string origin, string rateKey)
    {
        if (!IsEnabled() || string.IsNullOrWhiteSpace(usernameOrEmail))
        {
            return;
        }

        // Rate limit: 5 per 15 min per IP, 3 per 15 min per identifier. Both
        // independent so one user can't exhaust the whole IP budget and an
        // attacker can't bomb one inbox.
        if (!_ipLimiter.CheckAndRecord("pwreset-ip:" + rateKey, 5, TimeSpan.FromMinutes(15)).allowed)
        {
            return;
        }

        if (!_idLimiter.CheckAndRecord("pwreset-id:" + usernameOrEmail.Trim().ToLowerInvariant(), 3, TimeSpan.FromMinutes(15)).allowed)
        {
            return;
        }

        try
        {
            var user = ResolveUser(usernameOrEmail.Trim());
            if (user is null)
            {
                return; // generic — no enumeration
            }

            var cfg = Plugin.Instance?.Configuration;
            var email = cfg?.GetUserEmail(user.Id.ToString("N"));
            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogInformation("[2FA] Password-reset requested for {User} but no email is on file — skipping.", user.Username);
                return;
            }

            var raw = GenerateToken();
            _tokens[Hash(raw)] = new Entry { UserId = user.Id, ExpiresAt = DateTime.UtcNow.AddMinutes(TokenTtlMinutes) };
            PruneExpired();

            var link = origin.TrimEnd('/') + "/TwoFactorAuth/PasswordReset?token=" + Uri.EscapeDataString(raw);
            await _email.SendPasswordResetAsync(email!, user.Username, link, TokenTtlMinutes).ConfigureAwait(false);
            _logger.LogInformation("[2FA] Password-reset link emailed for {User}", user.Username);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] Password-reset request failed");
        }
    }

    /// <summary>Validate a token without consuming it (the reset page GET uses
    /// this to decide whether to show the form or an "expired link" message).</summary>
    public bool ValidateToken(string? rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return false;
        }

        return _tokens.TryGetValue(Hash(rawToken), out var e) && e.ExpiresAt > DateTime.UtcNow;
    }

    /// <summary>Complete a reset: set the new password and consume the token.
    /// Returns false on an invalid/expired token or unknown user.</summary>
    public async Task<bool> CompleteResetAsync(string? rawToken, string newPassword)
    {
        if (!IsEnabled() || string.IsNullOrWhiteSpace(rawToken) || string.IsNullOrEmpty(newPassword))
        {
            return false;
        }

        var hash = Hash(rawToken);
        if (!_tokens.TryGetValue(hash, out var e) || e.ExpiresAt <= DateTime.UtcNow)
        {
            _tokens.TryRemove(hash, out _);
            return false;
        }

        // Single-use: consume up-front so a double-submit can't reuse it.
        _tokens.TryRemove(hash, out _);

        var user = _userManager.GetUserById(e.UserId);
        if (user is null)
        {
            return false;
        }

        await _userManager.ChangePassword(user.Id, newPassword).ConfigureAwait(false);
        _logger.LogInformation("[2FA] Password reset completed for {User}", user.Username);
        return true;
    }

    /// <summary>Resolve by username first, then by the plugin's per-user email
    /// map (avoids the version-sensitive IUserManager.Users enumeration).</summary>
    private User? ResolveUser(string identifier)
    {
        try
        {
            var byName = _userManager.GetUserByName(identifier);
            if (byName is not null)
            {
                return byName;
            }

            if (identifier.Contains('@', StringComparison.Ordinal))
            {
                var cfg = Plugin.Instance?.Configuration;
                var entry = cfg?.UserEmails.FirstOrDefault(e =>
                    string.Equals(e.Email, identifier, StringComparison.OrdinalIgnoreCase));
                if (entry is not null && Guid.TryParseExact(entry.UserId, "N", out var uid))
                {
                    return _userManager.GetUserById(uid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] password-reset user resolve failed (treated as no-match)");
        }

        return null;
    }

    private static string GenerateToken()
        => Convert.ToHexString(RandomNumberGenerator.GetBytes(TokenBytes)).ToLowerInvariant();

    private static string Hash(string raw)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();

    private void PruneExpired()
    {
        if (_tokens.Count < 256)
        {
            return;
        }

        var now = DateTime.UtcNow;
        foreach (var kv in _tokens)
        {
            if (kv.Value.ExpiresAt <= now)
            {
                _tokens.TryRemove(kv.Key, out _);
            }
        }
    }
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#313] Sign-in codes for apps that can't show the 2FA challenge. When such
/// an app signs in with the right password and gets the challenge
/// (TwoFactorEnforcementMiddleware), the account's email address and linked
/// Telegram chat get an 8-digit code bound to that attempt: the account, the
/// device, the app, the stored password hash, the client address and the
/// challenge. CodeAfterPasswordMiddleware redeems it on the next attempt,
/// typed after the password or, when the admin allows it, alone.
///
/// Sending has its own limits (3 per account per 15 minutes, 1 per device
/// per minute), apart from the challenge page's and the step-up's, so someone
/// who knows the password can't use those up. Only an HMAC of each code is
/// kept, under a key that dies with the process, as in EmailOtpService.
/// </summary>
public class AppSignInCodeService
{
    /// <summary>Digits in a code, as in the challenge page's emailed codes.</summary>
    internal const int CodeLength = 8;

    /// <summary>Audit method of a sign-in with the code typed after the password.
    /// The name leaves "password" out: CodeQL takes any member named so for a
    /// password, and this value is logged.</summary>
    internal const string AuditMethodAppended = "email_after_password";

    /// <summary>Audit method of a sign-in with the code alone.</summary>
    internal const string AuditMethodAlone = "email_code_alone";

    private const int MaxWrongGuesses = 5;
    private const int MaxPending = 10_000;

    private static readonly byte[] HmacKey = RandomNumberGenerator.GetBytes(32);

    private readonly ConcurrentDictionary<Binding, PendingCode> _pending = new();
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly IApplicationHost _appHost;
    private readonly EmailOtpService _email;
    private readonly NotificationService _notifications;
    private readonly RateLimiter _rateLimiter;
    private readonly ChallengeStore _challenges;
    private readonly PendingPairingService _pendingPairings;
    private readonly SignInObserver _signInObserver;
    private readonly IpBanService _ipBans;
    private readonly ILogger<AppSignInCodeService> _logger;
    private readonly Func<PluginConfiguration?> _config;

    public AppSignInCodeService(
        UserTwoFactorStore store,
        IUserManager userManager,
        IApplicationHost appHost,
        EmailOtpService email,
        NotificationService notifications,
        RateLimiter rateLimiter,
        ChallengeStore challenges,
        PendingPairingService pendingPairings,
        SignInObserver signInObserver,
        IpBanService ipBans,
        ILogger<AppSignInCodeService> logger)
        : this(store, userManager, appHost, email, notifications, rateLimiter, challenges, pendingPairings, signInObserver, ipBans, logger, () => Plugin.Instance?.Configuration)
    {
    }

    // Test seam, as in EmailOtpService.
    internal AppSignInCodeService(
        UserTwoFactorStore store,
        IUserManager userManager,
        IApplicationHost appHost,
        EmailOtpService email,
        NotificationService notifications,
        RateLimiter rateLimiter,
        ChallengeStore challenges,
        PendingPairingService pendingPairings,
        SignInObserver signInObserver,
        IpBanService ipBans,
        ILogger<AppSignInCodeService> logger,
        Func<PluginConfiguration?> config)
    {
        _store = store;
        _userManager = userManager;
        _appHost = appHost;
        _email = email;
        _notifications = notifications;
        _rateLimiter = rateLimiter;
        _challenges = challenges;
        _pendingPairings = pendingPairings;
        _signInObserver = signInObserver;
        _ipBans = ipBans;
        _logger = logger;
        _config = config;
    }

    internal enum Outcome
    {
        /// <summary>No code for this account, device and app, or it expired.</summary>
        NoCode,

        /// <summary>A code exists and this one isn't it.</summary>
        Wrong,

        /// <summary>The attempt doesn't match the first one (address, or a
        /// password changed since).</summary>
        Refused,

        /// <summary>The right code, now spent.</summary>
        Accepted,
    }

    /// <summary>Test seam: a new code.</summary>
    internal Func<string> NewCode { get; set; } =
        () => RandomNumberGenerator.GetInt32(10_000_000, 100_000_000).ToString("D8", CultureInfo.InvariantCulture);

    /// <summary>Test seam: the clock.</summary>
    internal Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

    /// <summary>The first attempt, read while its request is alive: the code
    /// goes out after the response.</summary>
    internal sealed record SignInAttempt(
        Guid UserId,
        string Username,
        string? DeviceId,
        string? Client,
        string? DeviceName,
        string? ClientIp,
        bool ClientIpKnown,
        string ChallengeToken);

    internal static SignInAttempt Capture(HttpContext context, PluginConfiguration? config, Guid userId, string username, string challengeToken)
    {
        var (address, known) = ClientAddress(config, context.Connection.RemoteIpAddress?.ToString(), context.Request.Headers);
        var deviceName = TwoFactorAuthProvider.ResolveDeviceHeaderValue(
            context.Request.Headers["X-Emby-Device-Name"].FirstOrDefault(),
            context.Request.Headers["X-Emby-Authorization"].FirstOrDefault(),
            context.Request.Headers["Authorization"].FirstOrDefault(),
            "Device");
        return new SignInAttempt(
            userId,
            username,
            DeviceOf(context.Request),
            ClientOf(context.Request),
            deviceName is null ? null : WebUtility.UrlDecode(deviceName),
            address,
            known,
            challengeToken);
    }

    /// <summary>The DeviceId the request claims, read the same way on both
    /// attempts.</summary>
    internal static string? DeviceOf(HttpRequest request)
        => TwoFactorAuthProvider.ResolveDeviceHeaderValue(
            request.Headers["X-Emby-Device-Id"].FirstOrDefault(),
            request.Headers["X-Emby-Authorization"].FirstOrDefault(),
            request.Headers["Authorization"].FirstOrDefault(),
            "DeviceId");

    /// <summary>The app's name as Jellyfin records it (see AppPasswordClientPolicy).</summary>
    internal static string? ClientOf(HttpRequest request)
        => AppPasswordClientPolicy.ResolveClientName(
            request.Headers["Authorization"].FirstOrDefault(),
            request.Headers["X-Emby-Authorization"].FirstOrDefault(),
            request.Headers["X-Emby-Client"].FirstOrDefault());

    /// <summary>The client's own address, and whether the plugin can see it.
    /// A request with no forwarding header comes straight from the client. One
    /// that has a forwarding header came through a proxy, and the address is
    /// only known when the plugin trusts that proxy and finds a client in the
    /// chain; behind a proxy it doesn't trust, every client shows up with the
    /// proxy's address.</summary>
    internal static (string? Address, bool Known) ClientAddress(PluginConfiguration? config, string? peer, IHeaderDictionary headers)
    {
        if (string.IsNullOrWhiteSpace(peer))
        {
            return (null, false);
        }

        if (!headers.ContainsKey("X-Forwarded-For") && !headers.ContainsKey("X-Real-IP") && !headers.ContainsKey("Forwarded"))
        {
            return (peer, true);
        }

        if (config is not { TrustForwardedFor: true } || config.TrustedProxyCidrs.Length == 0
            || !config.TrustedProxyCidrs.Any(cidr => BypassEvaluator.IsIpInCidr(peer, cidr)))
        {
            return (peer, false);
        }

        var client = BypassEvaluator.PickRealClientIp(headers["X-Forwarded-For"].ToString(), config.TrustedProxyCidrs);
        return client is null ? (peer, false) : (client, true);
    }

    /// <summary>Sends the code for this attempt when it qualifies. Never
    /// throws. Returns whether a code was issued.</summary>
    internal async Task<bool> SendAsync(SignInAttempt attempt, bool enrollmentRequired)
    {
        try
        {
            var config = _config();
            if (config is not { Enabled: true, SendSignInCodeToApps: true, EmailOtpEnabled: true } || enrollmentRequired
                || string.IsNullOrWhiteSpace(attempt.DeviceId) || string.IsNullOrWhiteSpace(attempt.Client)
                || AppPasswordClientPolicy.IsRefused(attempt.Client, config.AppPasswordRefusedClients))
            {
                // The web interface and the apps the admin listed show the
                // challenge themselves.
                return false;
            }

            var user = _userManager.GetUserById(attempt.UserId);
            if (user is null || string.IsNullOrEmpty(user.Password) || !ChecksPasswordHere(user))
            {
                return false;
            }

            var email = config.GetUserEmail(attempt.UserId.ToString("N"));
            var chat = (await _store.GetUserDataAsync(attempt.UserId).ConfigureAwait(false)).TelegramChatId;
            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(chat))
            {
                return false;
            }

            if (!_rateLimiter.CheckAndRecord($"app_code:device:{attempt.UserId:N}|{attempt.DeviceId}", 1, TimeSpan.FromMinutes(1)).allowed
                || !_rateLimiter.CheckAndRecord($"app_code:user:{attempt.UserId:N}", 3, TimeSpan.FromMinutes(15)).allowed)
            {
                _logger.LogInformation("[2FA] Sign-in code for an app not sent to '{User}': send limit reached", attempt.Username);
                return false;
            }

            // Never longer than the challenge it can complete.
            var ttlSeconds = Math.Clamp(Math.Min(config.EmailOtpTtlSeconds, config.ChallengeTokenTtlSeconds), 60, 900);
            var code = NewCode();
            Prune();
            _pending[new Binding(attempt.UserId, attempt.DeviceId, attempt.Client)] = new PendingCode
            {
                CodeHash = Hash(code),
                PasswordFingerprint = Fingerprint(user.Password),
                ClientIp = attempt.ClientIp,
                ClientIpKnown = attempt.ClientIpKnown,
                ChallengeToken = attempt.ChallengeToken,
                ExpiresAt = UtcNow().AddSeconds(ttlSeconds),
            };

            var app = TwoFactorEnforcementMiddleware.SanitizeLabel(attempt.Client);
            var device = TwoFactorEnforcementMiddleware.SanitizeLabel(attempt.DeviceName);
            if (string.IsNullOrEmpty(device))
            {
                device = "a device";
            }

            var minutes = Math.Max(1, ttlSeconds / 60);
            var alone = config.AcceptSignInCodeAlone;
            var emailSent = !string.IsNullOrEmpty(email)
                && await _email.SendAppSignInCodeEmailAsync(email, attempt.Username, code, minutes, app, device, alone).ConfigureAwait(false);
            var telegramSent = false;
            if (!string.IsNullOrEmpty(chat))
            {
                var how = alone ? ", or the code alone in place of the password" : string.Empty;
                (telegramSent, _) = await _notifications.SendTelegramDirectAsync(
                    chat,
                    $"{app} on {device} signed in with your password. Your sign-in code is: {code}\n\nType your password followed by the code, with no space, in that app{how}. It works once and expires in about {minutes} minute(s). If this wasn't you, change your password.").ConfigureAwait(false);
            }

            // The log names the channels instead of carrying the senders'
            // results: CodeQL takes any value from a method or variable named
            // like "email" for private data.
            var channels = (emailSent, telegramSent) switch
            {
                (true, true) => "email and Telegram",
                (true, false) => "email",
                (false, true) => "Telegram",
                _ => null,
            };
            if (channels is null)
            {
                _logger.LogWarning("[2FA] Sign-in code for {App} could not be sent to '{User}' by email or Telegram", app, attempt.Username);
            }
            else
            {
                _logger.LogInformation("[2FA] Sign-in code for {App} sent to '{User}' by {Channels}", app, attempt.Username, channels);
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Sign-in code for an app: sending failed for '{User}'", attempt.Username);
            return false;
        }
    }

    /// <summary>A code is waiting for this account, device and app.</summary>
    internal bool HasPending(Guid userId, string? deviceId, string? client)
        => TryBinding(userId, deviceId, client, out var binding)
           && _pending.TryGetValue(binding, out var pending)
           && pending.ExpiresAt > UtcNow();

    /// <summary>Spends the code when it is the one sent to this account,
    /// device and app, the stored password hash is the one it was sent
    /// under, and, for the code alone (<paramref name="alone"/>), the client
    /// address is known and is the first attempt's. Five wrong guesses void
    /// the code. On success the first attempt's challenge token comes back.</summary>
    internal (Outcome Outcome, string ChallengeToken) Redeem(
        Guid userId,
        string? deviceId,
        string? client,
        string code,
        string? storedPasswordHash,
        (string? Address, bool Known)? alone = null)
    {
        if (!TryBinding(userId, deviceId, client, out var binding) || !_pending.TryGetValue(binding, out var pending))
        {
            return (Outcome.NoCode, string.Empty);
        }

        var entry = KeyValuePair.Create(binding, pending);
        if (pending.ExpiresAt <= UtcNow())
        {
            _pending.TryRemove(entry);
            return (Outcome.NoCode, string.Empty);
        }

        if (alone is { } address
            && (!pending.ClientIpKnown || !address.Known || !string.Equals(pending.ClientIp, address.Address, StringComparison.Ordinal)))
        {
            return (Outcome.Refused, string.Empty);
        }

        if (!CryptographicOperations.FixedTimeEquals(pending.PasswordFingerprint, Fingerprint(storedPasswordHash)))
        {
            // The password changed since the code went out.
            _pending.TryRemove(entry);
            return (Outcome.Refused, string.Empty);
        }

        if (!CryptographicOperations.FixedTimeEquals(pending.CodeHash, Hash(code)))
        {
            if (Interlocked.Increment(ref pending.WrongGuesses) >= MaxWrongGuesses)
            {
                _pending.TryRemove(entry);
            }

            return (Outcome.Wrong, string.Empty);
        }

        // Only the value that was checked: a newer code for the same app stays.
        return _pending.TryRemove(entry)
            ? (Outcome.Accepted, pending.ChallengeToken)
            : (Outcome.NoCode, string.Empty);
    }

    /// <summary>Completes the first attempt's challenge for the code alone,
    /// as TwoFactorAuthController.Verify does after a right code: the challenge
    /// is spent, Jellyfin's token from that attempt is unblocked and marked
    /// verified, and its stashed response comes back for the app. Null when
    /// that challenge is gone.</summary>
    internal async Task<string?> CompleteChallengeAsync(string challengeToken, User user, string? clientIp)
    {
        var challenge = _challenges.GetChallenge(challengeToken);
        if (challenge is null || challenge.UserId != user.Id || string.IsNullOrEmpty(challenge.PendingAuthResponse)
            || AccessTokenOf(challenge.PendingAuthResponse) is not { } token
            || !_challenges.ConsumeChallenge(challengeToken))
        {
            return null;
        }

        _challenges.UnblockToken(token);
        _challenges.MarkTokenVerified(token);
        if (!string.IsNullOrEmpty(challenge.DeviceId))
        {
            _challenges.MarkDevicePreVerified(user.Id, challenge.DeviceId);
            _pendingPairings.Remove(user.Id, challenge.DeviceId);
        }

        _ipBans.RecordSuccess(clientIp ?? string.Empty);
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = user.Id,
            Username = user.Username,
            RemoteIp = clientIp ?? string.Empty,
            DeviceId = challenge.DeviceId ?? string.Empty,
            DeviceName = challenge.DeviceName ?? string.Empty,
            Result = AuditResult.Success,
            Method = AuditMethodAlone,
        }).ConfigureAwait(false);
        _signInObserver.Observe(user.Id, user.Username, clientIp);
        _logger.LogInformation("[2FA] Sign-in code alone accepted for '{User}'", user.Username);
        return challenge.PendingAuthResponse;
    }

    private bool ChecksPasswordHere(User user)
    {
        var providers = _appHost.GetExports<IAuthenticationProvider>(false)
            .Select(p => (p.GetType().FullName, p.IsEnabled))
            .ToList();
        return CodeAfterPasswordMiddleware.PasswordProviderIndex(user.AuthenticationProviderId, providers) >= 0;
    }

    private void Prune()
    {
        var now = UtcNow();
        foreach (var entry in _pending)
        {
            if (entry.Value.ExpiresAt <= now)
            {
                _pending.TryRemove(entry);
            }
        }

        while (_pending.Count >= MaxPending)
        {
            var oldest = _pending.MinBy(e => e.Value.ExpiresAt);
            _pending.TryRemove(oldest);
        }
    }

    private static string? AccessTokenOf(string authResponse)
    {
        try
        {
            using var doc = JsonDocument.Parse(authResponse);
            return doc.RootElement.TryGetProperty("AccessToken", out var token) && token.ValueKind == JsonValueKind.String
                ? token.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool TryBinding(Guid userId, string? deviceId, string? client, out Binding binding)
    {
        binding = default;
        if (userId == Guid.Empty || string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(client))
        {
            return false;
        }

        binding = new Binding(userId, deviceId, client);
        return true;
    }

    private static byte[] Hash(string code) => HMACSHA256.HashData(HmacKey, Encoding.UTF8.GetBytes(code));

    // Of the stored hash, not of anything typed: a password change voids the code.
    private static byte[] Fingerprint(string? storedPasswordHash)
        => HMACSHA256.HashData(HmacKey, Encoding.UTF8.GetBytes("password:" + (storedPasswordHash ?? string.Empty)));

    private readonly record struct Binding(Guid UserId, string DeviceId, string Client);

    private sealed class PendingCode
    {
        public byte[] CodeHash { get; init; } = Array.Empty<byte>();

        public byte[] PasswordFingerprint { get; init; } = Array.Empty<byte>();

        public string? ClientIp { get; init; }

        public bool ClientIpKnown { get; init; }

        public string ChallengeToken { get; init; } = string.Empty;

        public DateTime ExpiresAt { get; init; }

        // A field, so Interlocked.Increment can take it by ref.
        public int WrongGuesses;
    }
}

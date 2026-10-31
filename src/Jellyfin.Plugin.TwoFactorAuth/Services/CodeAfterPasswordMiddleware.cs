using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
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
/// [#312] Lets an app that can't show the 2FA challenge sign in with the
/// authenticator code typed right after the password, with no space:
/// "MyPassword123456". Off by default
/// (<see cref="Configuration.PluginConfiguration.AcceptCodeAfterPassword"/>).
///
/// It runs right after LockoutMessageMiddleware, so the empty-password and
/// Disable password sign-in gates and the lockout pre-check see what was
/// typed, and the outcome counts toward the lockout like any other sign-in.
/// When the part before the last six digits is the account's password and the
/// six digits are its current code, only the password goes on to Jellyfin, and
/// the request carries a mark that the three paths deciding a sign-in honour
/// (TwoFactorAuthProvider, AuthenticationEventHandler and
/// TwoFactorEnforcementMiddleware), so the new token isn't held for the
/// challenge. HttpContext.Items holds the mark, which no client can set.
///
/// In every other case the request goes on as typed: a password that ends in
/// digits keeps working, and a wrong code reaches Jellyfin as a wrong
/// password, so it gets the same 401 after the same work. The code is only
/// looked at once the password part is right, so only someone who knows the
/// password can spend the per-account attempt limit, which covers
/// administrators too.
///
/// [#313] With <see cref="Configuration.PluginConfiguration.SendSignInCodeToApps"/>
/// on, it also redeems the 8-digit code AppSignInCodeService sent to an app on
/// its last attempt: typed after the password, the same way, or, with
/// <see cref="Configuration.PluginConfiguration.AcceptSignInCodeAlone"/> on,
/// alone, which completes the first attempt's challenge here and answers the
/// request with that attempt's response.
/// </summary>
public class CodeAfterPasswordMiddleware
{
    /// <summary>HttpContext.Items key holding the id of the account whose code
    /// this request carried and passed.</summary>
    internal const string VerifiedUserItemKey = "TwoFactorAuth.CodeAfterPassword.VerifiedUser";

    /// <summary>[#313] HttpContext.Items key holding the audit method of the
    /// code that was accepted.</summary>
    internal const string VerifiedMethodItemKey = "TwoFactorAuth.CodeAfterPassword.Method";

    /// <summary>Audit method of a sign-in with the code after the password.</summary>
    internal const string AuditMethod = "totp_after_password";

    private const int CodeLength = 6;

    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly IApplicationHost _appHost;
    private readonly TotpService _totp;
    private readonly RateLimiter _rateLimiter;
    private readonly IpBanService _ipBans;
    private readonly AppSignInCodeService _appCodes;
    private readonly ILogger<CodeAfterPasswordMiddleware> _logger;

    public CodeAfterPasswordMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        IUserManager userManager,
        IApplicationHost appHost,
        TotpService totp,
        RateLimiter rateLimiter,
        IpBanService ipBans,
        AppSignInCodeService appCodes,
        ILogger<CodeAfterPasswordMiddleware> logger)
    {
        _next = next;
        _store = store;
        _userManager = userManager;
        _appHost = appHost;
        _totp = totp;
        _rateLimiter = rateLimiter;
        _ipBans = ipBans;
        _appCodes = appCodes;
        _logger = logger;
    }

    /// <summary>What a sign-in request became.</summary>
    internal enum Acceptance
    {
        /// <summary>It goes on as typed.</summary>
        None,

        /// <summary>It goes on with the password alone and the mark.</summary>
        PasswordAlone,

        /// <summary>[#313] Answered here: the code alone completed the first
        /// attempt's challenge.</summary>
        Answered,
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is { Enabled: true } && (config.AcceptCodeAfterPassword || config.SendSignInCodeToApps) && IsHandledEndpoint(context))
        {
            try
            {
                if (await TryAcceptAsync(context, config).ConfigureAwait(false) == Acceptance.Answered)
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                // The sign-in goes on as typed and meets the challenge, as it
                // would with the setting off.
                _logger.LogWarning(ex, "[2FA] Code after password: the check failed; the sign-in goes on as typed");
            }

            if (context.Response.HasStarted)
            {
                return;
            }
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>Checks what was typed against the codes this request may
    /// carry: [#313] a code sent to this app on its last attempt, alone or
    /// after the password, then the authenticator code. On success the body
    /// carries the password alone and the request the mark, or, for the code
    /// alone, the response is written; otherwise nothing changes.</summary>
    internal async Task<Acceptance> TryAcceptAsync(HttpContext context, PluginConfiguration config)
    {
        var (username, typed) = await LockoutMessageMiddleware.PeekCredentialsAsync(context.Request).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(typed))
        {
            return Acceptance.None;
        }

        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            return Acceptance.None;
        }

        if (config.SendSignInCodeToApps)
        {
            var device = AppSignInCodeService.DeviceOf(context.Request);
            var client = AppSignInCodeService.ClientOf(context.Request);
            if (_appCodes.HasPending(user.Id, device, client))
            {
                if (config.AcceptSignInCodeAlone && IsCodeAlone(typed))
                {
                    return await TryCodeAloneAsync(context, config, user, typed, device, client).ConfigureAwait(false);
                }

                if (Split(typed, AppSignInCodeService.CodeLength, out var sentPassword, out var sentCode)
                    && await TrySentCodeAsync(context, user, username, sentPassword, sentCode, device, client).ConfigureAwait(false))
                {
                    return Acceptance.PasswordAlone;
                }
            }
        }

        return config.AcceptCodeAfterPassword
               && TrySplit(typed, out var password, out var code)
               && await TryAuthenticatorCodeAsync(context, user, username, password, code).ConfigureAwait(false)
            ? Acceptance.PasswordAlone
            : Acceptance.None;
    }

    /// <summary>[#312] The authenticator code after the password.</summary>
    private async Task<bool> TryAuthenticatorCodeAsync(HttpContext context, User user, string username, string password, string code)
    {
        var data = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);
        if (!AppliesTo(data)
            || !await PasswordPartMatchesAsync(user, password).ConfigureAwait(false)
            || !WithinAttemptLimit(user, out var attemptsKey))
        {
            return false;
        }

        var secret = _totp.DecryptSecret(data.EncryptedTotpSecret!, user.Id);
        if (!_totp.ValidateCode(secret, code, user.Id.ToString(), data.LastUsedTotpStep, out var acceptedStep))
        {
            await RecordWrongCodeAsync(context, user, AuditMethod, "wrong authenticator code after the right password").ConfigureAwait(false);
            return false;
        }

        // Spent before Jellyfin signs in: if Jellyfin then refuses (a disabled
        // account, say), the next code works.
        await _store.MutateAsync(user.Id, ud => UserDataUpdates.RaiseReplayFloor(ud, acceptedStep)).ConfigureAwait(false);
        Accept(context, user, username, password, AuditMethod, attemptsKey);
        return true;
    }

    /// <summary>[#313] The code sent to this app, after the password.</summary>
    private async Task<bool> TrySentCodeAsync(HttpContext context, User user, string username, string password, string code, string? device, string? client)
    {
        if (!await PasswordPartMatchesAsync(user, password).ConfigureAwait(false)
            || !WithinAttemptLimit(user, out var attemptsKey))
        {
            return false;
        }

        var (outcome, _) = _appCodes.Redeem(user.Id, device, client, code, user.Password);
        if (outcome != AppSignInCodeService.Outcome.Accepted)
        {
            if (outcome != AppSignInCodeService.Outcome.NoCode)
            {
                await RecordWrongCodeAsync(
                    context,
                    user,
                    AppSignInCodeService.AuditMethodAppended,
                    outcome == AppSignInCodeService.Outcome.Wrong
                        ? "wrong sign-in code after the right password"
                        : "sign-in code sent before the password changed").ConfigureAwait(false);
            }

            return false;
        }

        Accept(context, user, username, password, AppSignInCodeService.AuditMethodAppended, attemptsKey);
        return true;
    }

    /// <summary>[#313] The code sent to this app, alone in place of the
    /// password. It completes the first attempt's challenge, whose response
    /// answers this request.</summary>
    private async Task<Acceptance> TryCodeAloneAsync(HttpContext context, PluginConfiguration config, User user, string code, string? device, string? client)
    {
        var address = AppSignInCodeService.ClientAddress(config, context.Connection.RemoteIpAddress?.ToString(), context.Request.Headers);
        if (!address.Known)
        {
            _logger.LogInformation("[2FA] Sign-in code alone refused for '{User}': the client's own address isn't known", user.Username);
            return Acceptance.None;
        }

        if (_ipBans.CheckBanned(address.Address!) is not null || !WithinAttemptLimit(user, out var attemptsKey))
        {
            return Acceptance.None;
        }

        var (outcome, challengeToken) = _appCodes.Redeem(user.Id, device, client, code, user.Password, address);
        if (outcome == AppSignInCodeService.Outcome.Wrong)
        {
            await RecordWrongCodeAsync(context, user, AppSignInCodeService.AuditMethodAlone, "wrong sign-in code alone").ConfigureAwait(false);
        }
        else if (outcome == AppSignInCodeService.Outcome.Refused)
        {
            _logger.LogInformation("[2FA] Sign-in code alone refused for '{User}': another address than the first attempt's, or the password changed", user.Username);
        }

        if (outcome != AppSignInCodeService.Outcome.Accepted)
        {
            return Acceptance.None;
        }

        var authResponse = await _appCodes.CompleteChallengeAsync(challengeToken, user, address.Address).ConfigureAwait(false);
        if (authResponse is null)
        {
            // The first attempt's challenge is gone; the app signs in again
            // with the password.
            return Acceptance.None;
        }

        _rateLimiter.Reset(attemptsKey);
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(authResponse).ConfigureAwait(false);
        return Acceptance.Answered;
    }

    private async Task<bool> PasswordPartMatchesAsync(User user, string password)
    {
        var provider = FindPasswordProvider(user);
        if (provider is null)
        {
            _logger.LogDebug("[2FA] Code after password: '{User}' signs in through another authentication provider; left to the challenge", user.Username);
            return false;
        }

        // When it isn't the password, Jellyfin checks the whole string as the
        // password, so a password that itself ends in digits keeps working.
        return await PasswordMatchesAsync(provider, user, password).ConfigureAwait(false);
    }

    /// <summary>The same per-account bucket as /TwoFactorAuth/Verify
    /// (TwoFactorAuthController), so the challenge page and these paths share
    /// one allowance of wrong codes. Spent only once the password part is
    /// right or, for the code alone, once the attempt matches the first.</summary>
    private bool WithinAttemptLimit(User user, out string attemptsKey)
    {
        attemptsKey = "verify_user:" + user.Id.ToString("N");
        if (_rateLimiter.CheckAndRecord(attemptsKey, 15, TimeSpan.FromMinutes(15)).allowed)
        {
            return true;
        }

        _logger.LogWarning("[2FA] Code after password: too many attempts for '{User}'; the sign-in goes on as typed", user.Username);
        return false;
    }

    private async Task RecordWrongCodeAsync(HttpContext context, User user, string method, string details)
    {
        var clientIp = BypassEvaluator.ResolveClientIp(context) ?? string.Empty;
        _ipBans.RecordFailure(clientIp);
        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = user.Id,
            Username = user.Username,
            RemoteIp = clientIp,
            DeviceId = DeviceHeader(context.Request, "X-Emby-Device-Id", "DeviceId") ?? string.Empty,
            DeviceName = DeviceHeader(context.Request, "X-Emby-Device-Name", "Device") ?? string.Empty,
            Result = AuditResult.Failed,
            Method = method,
            Details = details,
        }).ConfigureAwait(false);
        _logger.LogWarning("[2FA] Code after password: {Details} for '{User}' from {Ip}", details, user.Username, clientIp);
    }

    private void Accept(HttpContext context, User user, string username, string password, string method, string attemptsKey)
    {
        _rateLimiter.Reset(attemptsKey);
        RewriteCredentials(context.Request, username, password);
        context.Items[VerifiedUserItemKey] = user.Id;
        context.Items[VerifiedMethodItemKey] = method;
        _logger.LogInformation("[2FA] Code after password accepted for '{User}' ({Method})", user.Username, method);
    }

    /// <summary>Jellyfin's sign-in by name. The obsolete by-id form is left
    /// alone: apps sign in by name.</summary>
    internal static bool IsHandledEndpoint(HttpContext context)
        => LockoutMessageMiddleware.TryMatchPasswordAuthEndpoint(context, out var routeUserId)
           && routeUserId == Guid.Empty;

    /// <summary>Splits what was typed into the password and the six-digit
    /// code at its end. ASCII digits only, and the password part can't be
    /// blank: the code alone never signs anyone in, and an account without a
    /// password stays behind the empty-password gate.</summary>
    internal static bool TrySplit(string? typed, out string password, out string code)
        => Split(typed, CodeLength, out password, out code);

    /// <summary>The same split for a code of <paramref name="codeLength"/>
    /// digits ([#313] the 8-digit sign-in code).</summary>
    internal static bool Split(string? typed, int codeLength, out string password, out string code)
    {
        password = string.Empty;
        code = string.Empty;
        if (typed is null || typed.Length <= codeLength)
        {
            return false;
        }

        var start = typed.Length - codeLength;
        for (var i = start; i < typed.Length; i++)
        {
            if (typed[i] is < '0' or > '9')
            {
                return false;
            }
        }

        if (string.IsNullOrWhiteSpace(typed[..start]))
        {
            return false;
        }

        password = typed[..start];
        code = typed[start..];
        return true;
    }

    /// <summary>The account has a confirmed authenticator, and isn't held to
    /// recovery and emailed codes by an emergency lockout, which the challenge
    /// enforces too.</summary>
    internal static bool AppliesTo(UserTwoFactorData data)
        => data.TotpEnabled
           && data.TotpVerified
           && !string.IsNullOrEmpty(data.EncryptedTotpSecret)
           && !data.ForceRecoveryOnNextLogin;

    /// <summary>The provider that checks this account's password: the one
    /// Jellyfin picks by the account's provider id, or, for an account moved
    /// onto the plugin, the first other enabled one, which is where
    /// TwoFactorAuthProvider hands the password. -1 unless that is Jellyfin's
    /// own password provider: another one (LDAP and the like) would be asked
    /// twice per sign-in, here and by Jellyfin, and a directory server counts
    /// both failures.</summary>
    internal static int PasswordProviderIndex(string? accountProviderId, IReadOnlyList<(string? TypeName, bool Enabled)> providers)
    {
        if (string.IsNullOrEmpty(accountProviderId))
        {
            return -1;
        }

        var ownAccount = string.Equals(accountProviderId, SignInProviderRestore.PluginProviderId, StringComparison.OrdinalIgnoreCase);
        for (var i = 0; i < providers.Count; i++)
        {
            var (typeName, enabled) = providers[i];
            if (!enabled)
            {
                continue;
            }

            var picked = ownAccount
                ? !string.Equals(typeName, SignInProviderRestore.PluginProviderId, StringComparison.Ordinal)
                : string.Equals(typeName, accountProviderId, StringComparison.OrdinalIgnoreCase);
            if (picked)
            {
                return string.Equals(typeName, SignInProviderRestore.JellyfinDefaultProviderId, StringComparison.Ordinal) ? i : -1;
            }
        }

        return -1;
    }

    /// <summary>Replaces the body with the name and the password alone. A
    /// fresh body, so nothing else in the original (a second "pw", say) can
    /// reach Jellyfin next to the password that was checked.</summary>
    internal static void RewriteCredentials(HttpRequest request, string username, string password)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new { Username = username, Pw = password });
        request.Body = new MemoryStream(body, writable: false);
        request.ContentLength = body.Length;
    }

    /// <summary>The account this request's code was accepted for, or
    /// Guid.Empty.</summary>
    internal static Guid VerifiedUser(HttpContext? context)
        => context is not null
           && context.Items.TryGetValue(VerifiedUserItemKey, out var value)
           && value is Guid userId
            ? userId
            : Guid.Empty;

    /// <summary>[#313] The audit method of the code this request was accepted
    /// with.</summary>
    internal static string VerifiedMethod(HttpContext? context)
        => context is not null
           && context.Items.TryGetValue(VerifiedMethodItemKey, out var value)
           && value is string method
            ? method
            : AuditMethod;

    /// <summary>[#313] Exactly a sign-in code's digits, which can only be the
    /// code alone.</summary>
    internal static bool IsCodeAlone(string typed)
        => typed.Length == AppSignInCodeService.CodeLength && typed.All(c => c is >= '0' and <= '9');

    /// <summary>This request carried the code after the password, and it was
    /// accepted for <paramref name="userId"/>.</summary>
    internal static bool WasVerifiedFor(HttpContext? context, Guid userId)
        => userId != Guid.Empty && VerifiedUser(context) == userId;

    private IAuthenticationProvider? FindPasswordProvider(User user)
    {
        var providers = _appHost.GetExports<IAuthenticationProvider>(false).ToList();
        var index = PasswordProviderIndex(
            user.AuthenticationProviderId,
            providers.Select(p => (p.GetType().FullName, p.IsEnabled)).ToList());
        return index < 0 ? null : providers[index];
    }

    private static async Task<bool> PasswordMatchesAsync(IAuthenticationProvider provider, User user, string password)
    {
        try
        {
            // Jellyfin's own provider only implements the overload that takes
            // the resolved user (see TwoFactorAuthProvider).
            if (provider is IRequiresResolvedUser resolved)
            {
                await resolved.Authenticate(user.Username, password, user).ConfigureAwait(false);
            }
            else
            {
                await provider.Authenticate(user.Username, password).ConfigureAwait(false);
            }

            return true;
        }
        catch (AuthenticationException)
        {
            return false;
        }
    }

    private static string? DeviceHeader(HttpRequest request, string dedicatedHeader, string authKey)
        => TwoFactorAuthProvider.ResolveDeviceHeaderValue(
            request.Headers[dedicatedHeader].FirstOrDefault(),
            request.Headers["X-Emby-Authorization"].FirstOrDefault(),
            request.Headers["Authorization"].FirstOrDefault(),
            authKey);
}

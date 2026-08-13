using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>OIDC sign-in implementation. Handles the authorization-code flow
/// with PKCE for every configured provider. Each call:
///  1. Build /authorize URL → user redirected to IdP
///  2. IdP redirects back to /Callback with code
///  3. We POST the code (+ PKCE verifier) to /token to get id_token + access_token
///  4. Verify id_token signature against the IdP's JWKs
///  5. Extract claims (sub, email, groups), match to a Jellyfin user, sign them in
///
/// Discovery + JWKs are cached for 1h. PKCE verifier + state are stored in
/// short-lived (10min) memory entries keyed by the random state nonce.</summary>
public class OidcService : IDisposable
{
    private record Discovery(
        string AuthorizationEndpoint,
        string TokenEndpoint,
        string UserInfoEndpoint,
        string JwksUri,
        string Issuer,
        DateTime CachedAt,
        // [#134] RP-Initiated Logout 1.0. Optional in the discovery document
        // and absent from plenty of OPs, so empty is a normal value: every
        // caller has to read it as "this provider cannot do RP logout", never
        // as an error. Trailing optional parameter so the existing positional
        // construction below stays untouched.
        string EndSessionEndpoint = "");

    private record PendingFlow(
        string ProviderId,
        string CodeVerifier,
        string Nonce,
        string ReturnUrl,
        DateTime ExpiresAt);

    // [v2.5.7] (deferred OIDC step-up): parallel to PendingFlow but for the
    // user-step-up modal. Carries the user id that the IdP-returned subject
    // must match; the popup callback enforces that match before minting the
    // step-up token. Separated from _pendingFlows so a regular login state
    // can't accidentally satisfy a step-up callback and vice versa.
    private record PendingUserStepUp(
        string ProviderId,
        Guid UserId,
        string CodeVerifier,
        string Nonce,
        DateTime ExpiresAt);

    private record PendingOnboardingValidation(
        string ProviderId,
        Guid UserId,
        string Subject,
        string AccessToken,
        string CodeVerifier,
        string Nonce,
        DateTime ExpiresAt);

    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly ILogger<OidcService> _logger;
    // [v2.5.10] (#66) avatar sync + (#65) role→library access.
    private readonly IProviderManager _providerManager;
    private readonly IServerConfigurationManager _serverConfig;
    private readonly ILibraryManager _libraryManager;
    // SECURITY [v2.5.9] (audit medium): AllowAutoRedirect=false. The
    // EnsureSafeOutboundAsync egress filter validates only the CONFIGURED
    // URL's host/IP; with auto-redirect on (the default), a malicious or
    // compromised IdP could 302 the discovery/token/jwks/userinfo request to
    // 169.254.169.254 (cloud metadata) or an RFC1918 address and the client
    // would follow it WITHOUT re-validating — defeating the SSRF guard on the
    // redirect leg. Legit OIDC endpoints never redirect these requests, so
    // refusing to follow redirects is safe and closes the bypass.
    private static readonly HttpClient _http = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    // SEC-M1: JWKs are cached with the same 1h TTL as discovery. IdPs rotate
    // signing keys (Google ~every few weeks); without a TTL the cache could
    // (a) reject valid tokens after rotation since the new kid isn't present,
    // or (b) keep trusting a retired key past its lifetime. GetJwksAsync also
    // forces a refresh when the requested kid is missing from the cache.
    private record JwksCacheEntry(JsonWebKeySet Keys, DateTime FetchedAt);

    // SECURITY [v2.5.5] (N-A2): shorter cache TTLs to narrow the DNS-rebind
    // window. A 1h cache let an attacker who passed the initial
    // EnsureSafeOutboundAsync DNS check then re-point DNS at private IPs for
    // up to 1h. Shorter TTL forces re-validation more often. 5min for JWKs
    // and 10min for discovery is a sane production trade-off — IdP key
    // rotation is rare enough that the extra fetches are negligible.
    private static readonly TimeSpan _jwksTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan _discoveryTtl = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, Discovery> _discoveryCache = new();
    private readonly ConcurrentDictionary<string, JwksCacheEntry> _jwksCache = new();
    private readonly ConcurrentDictionary<string, PendingFlow> _pendingFlows = new();
    private readonly ConcurrentDictionary<string, PendingUserStepUp> _pendingUserStepUps = new();
    private readonly ConcurrentDictionary<string, PendingOnboardingValidation> _pendingOnboardingValidations = new();

    // [v2.5.13] (#95) Pending EXPLICIT account-link flows (Setup → "Link a new
    // provider"). Separate from step-up so the callback can tell the two intents
    // apart. Reuses the PendingUserStepUp shape (provider + bound user + PKCE).
    private readonly ConcurrentDictionary<string, PendingUserStepUp> _pendingUserLinks = new();

    // SECURITY [v2.5.9]: hard cap on the in-memory pending maps. TTL + rate
    // limits already bound them, but a global cap makes DoS resistance
    // explicit: on insert we prune expired entries, then if still at the cap
    // evict the oldest, so a flood of un-completed Begin() / step-up calls
    // can't grow memory without bound. 2000 is far above any real concurrent
    // login volume on a self-hosted instance.
    private const int MaxPendingEntries = 2000;
    private static void PruneAndCap<T>(ConcurrentDictionary<string, T> map, Func<T, DateTime> expiry)
    {
        if (map.Count < MaxPendingEntries) return;
        var now = DateTime.UtcNow;
        foreach (var kv in map)
        {
            if (expiry(kv.Value) <= now) map.TryRemove(kv.Key, out _);
        }
        while (map.Count >= MaxPendingEntries)
        {
            string? oldestKey = null;
            var oldestExp = DateTime.MaxValue;
            foreach (var kv in map)
            {
                var e = expiry(kv.Value);
                if (e < oldestExp) { oldestExp = e; oldestKey = kv.Key; }
            }
            if (oldestKey is null) break;
            map.TryRemove(oldestKey, out _);
        }
    }
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    public OidcService(
        UserTwoFactorStore store,
        IUserManager userManager,
        ILogger<OidcService> logger,
        IProviderManager providerManager,
        IServerConfigurationManager serverConfig,
        ILibraryManager libraryManager)
    {
        _store = store;
        _userManager = userManager;
        _logger = logger;
        _providerManager = providerManager;
        _serverConfig = serverConfig;
        _libraryManager = libraryManager;
        _cleanupTimer = new Timer(_ => SweepPending(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing) _cleanupTimer.Dispose();
        _disposed = true;
    }

    /// <summary>Build the full /authorize redirect URL the user's browser is
    /// pointed at to start sign-in. Returns the URL + the state nonce the
    /// callback will echo back.</summary>
    public async Task<(string AuthUrl, string State)> BeginAsync(
        OidcProvider provider, string redirectUri, string returnUrl)
    {
        // SECURITY [v2.5.9] (audit medium): coerce returnUrl to a safe
        // site-relative path BEFORE storing it in the pending flow. An
        // attacker-supplied absolute or protocol-relative URL would otherwise
        // round-trip through the callback and become an open redirect
        // (phishing, or leaking the freshly-minted bridge token to an
        // external origin).
        returnUrl = SanitizeReturnUrl(returnUrl);

        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        // PKCE: random 43-char verifier, S256 challenge.
        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

        var state = Base64Url(RandomNumberGenerator.GetBytes(24));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(24));

        PruneAndCap(_pendingFlows, p => p.ExpiresAt);
        _pendingFlows[state] = new PendingFlow(
            provider.Id, codeVerifier, nonce, returnUrl,
            DateTime.UtcNow.AddMinutes(10));

        var qs = new List<(string, string)>
        {
            ("client_id", provider.ClientId),
            ("response_type", "code"),
            ("scope", provider.Scopes),
            ("redirect_uri", redirectUri),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
        };
        if (!string.IsNullOrWhiteSpace(provider.AcrValues))
            qs.Add(("acr_values", provider.AcrValues));

        // [v2.5.10] Force the IdP account chooser on the main sign-in flow.
        // Without this, an IdP with an active browser session (e.g. Google)
        // silently returns the already-signed-in account and skips the picker,
        // so on a shared machine you can't switch accounts. Opt-in per provider
        // (single-account setups prefer one-click). Deliberately NOT applied to
        // the step-up flow, where re-using the same account is what we want.
        if (provider.PromptSelectAccount)
            qs.Add(("prompt", "select_account"));

        var url = disc.AuthorizationEndpoint + "?" +
            string.Join("&", qs.Select(kv => $"{Uri.EscapeDataString(kv.Item1)}={Uri.EscapeDataString(kv.Item2)}"));
        return (url, state);
    }

    public record CallbackResult(
        bool Success,
        string? Error,
        Guid? UserId,
        string? Username,
        string? ReturnUrl,
        SsoLink? Link);

    /// <summary>Process the callback from the IdP. Returns a CallbackResult
    /// describing what happened — success links the user, failure has an
    /// error string for the controller to surface.</summary>
    public async Task<CallbackResult> CompleteAsync(
        OidcProvider provider, string code, string state, string redirectUri)
    {
        if (!_pendingFlows.TryRemove(state, out var pending))
        {
            return new CallbackResult(false, "State token not found or expired", null, null, null, null);
        }
        if (pending.ProviderId != provider.Id)
        {
            return new CallbackResult(false, "State token belongs to a different provider", null, null, null, null);
        }
        if (pending.ExpiresAt <= DateTime.UtcNow)
        {
            return new CallbackResult(false, "Sign-in flow timed out — try again", null, null, null, null);
        }

        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        // Exchange code for tokens. FormUrlEncodedContent is IDisposable —
        // wrap in `using` so the request body is released deterministically
        // after the HttpClient call instead of waiting on the finalizer.
        using var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = provider.ClientId,
            ["client_secret"] = provider.ClientSecret,
            ["code_verifier"] = pending.CodeVerifier,
        });
        // SECURITY [v2.5.6] (ext review #6): re-validate the token endpoint
        // before every use, not just at discovery time. The discovery cache
        // holds the URL string for up to _discoveryTtl; in that window an
        // attacker controlling DNS for the IdP host could flip A records to
        // 127.0.0.1 / 169.254.169.254 / a private IP and the cached URL would
        // happily POST credentials there. GetJwksAsync already does this; the
        // token + userinfo paths were the gap.
        await EnsureSafeOutboundAsync(disc.TokenEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        var tokenResp = await _http.PostAsync(disc.TokenEndpoint, tokenForm).ConfigureAwait(false);

        if (!tokenResp.IsSuccessStatusCode)
        {
            var body = await tokenResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogWarning("[2FA] OIDC token exchange failed: {Status} {Body}", tokenResp.StatusCode, body);
            return new CallbackResult(false, "Token exchange failed (" + tokenResp.StatusCode + ")", null, null, null, null);
        }

        var tokenJson = await tokenResp.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(false);
        if (!tokenJson.TryGetProperty("id_token", out var idTokenEl) || idTokenEl.ValueKind != JsonValueKind.String)
        {
            return new CallbackResult(false, "IdP returned no id_token", null, null, null, null);
        }
        var idToken = idTokenEl.GetString()!;
        // Issue #29: access_token is needed to fetch /userinfo for IdPs that
        // emit `groups` only there (Authelia default, Keycloak realms, etc.).
        string? accessToken = null;
        if (tokenJson.TryGetProperty("access_token", out var atEl) && atEl.ValueKind == JsonValueKind.String)
        {
            accessToken = atEl.GetString();
        }

        // Verify id_token signature against the IdP's JWKs + check nonce/issuer.
        ClaimsBundle claims;
        try
        {
            claims = await VerifyIdTokenAsync(provider, disc, idToken, pending.Nonce).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] OIDC id_token verification failed");
            return new CallbackResult(false, "Token verification failed: " + ex.Message, null, null, null, null);
        }

        return await FinalizeSignInAsync(provider, disc, claims, accessToken, pending.ReturnUrl).ConfigureAwait(false);
    }

    // ---------------------------------------------------------------------
    // [v2.5.7] OIDC step-up: a user already signed in via this plugin can
    // re-authenticate to an IdP they have linked, and the matching subject
    // mints a user step-up token. Used when the user has no TOTP / passkey
    // / recovery code / email OTP to satisfy SelfServiceStepUpMode=Forced.
    // ---------------------------------------------------------------------

    /// <summary>Non-consuming peek so the shared /Oidc/Callback endpoint can
    /// route a callback to <see cref="CompleteUserStepUpAsync"/> vs the
    /// regular login completion without burning the state token on the
    /// wrong path.</summary>
    public bool IsUserStepUpState(string state)
        => !string.IsNullOrEmpty(state) && _pendingUserStepUps.ContainsKey(state);

    /// <summary>Begin an OIDC step-up flow. The returned authorize URL is
    /// opened in a popup. State is single-use and bound to <paramref name="userId"/>;
    /// the callback enforces the subject match before minting a token.</summary>
    public async Task<(string AuthUrl, string State)> BeginUserStepUpAsync(
        OidcProvider provider, Guid userId, string redirectUri)
    {
        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var state = Base64Url(RandomNumberGenerator.GetBytes(24));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(24));

        PruneAndCap(_pendingUserStepUps, p => p.ExpiresAt);
        _pendingUserStepUps[state] = new PendingUserStepUp(
            provider.Id, userId, codeVerifier, nonce,
            DateTime.UtcNow.AddMinutes(10));

        var qs = new List<(string, string)>
        {
            ("client_id", provider.ClientId),
            ("response_type", "code"),
            ("scope", provider.Scopes),
            ("redirect_uri", redirectUri),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
        };
        // Force the IdP to actually re-authenticate even if there's an active
        // SSO session. Without prompt=login a clever attacker who hijacked a
        // browser session could click "Sign in with X" and have the IdP
        // silently confirm. prompt=login closes that. [#119] Suppressible
        // per-provider (OmitPromptLogin) for IdPs that mishandle it — notably
        // Authentik (upstream bug #18507 returns a 404 on the authorize
        // redirect when prompt=login is present).
        if (!provider.OmitPromptLogin)
            qs.Add(("prompt", "login"));
        if (!string.IsNullOrWhiteSpace(provider.AcrValues))
            qs.Add(("acr_values", provider.AcrValues));

        var url = disc.AuthorizationEndpoint + "?" +
            string.Join("&", qs.Select(kv => $"{Uri.EscapeDataString(kv.Item1)}={Uri.EscapeDataString(kv.Item2)}"));
        return (url, state);
    }

    public record StepUpResult(bool Success, string? Error, Guid? UserId);

    public record OnboardingValidationResult(
        bool Success,
        string? Error,
        Guid? UserId,
        string? Proof,
        string? AccessToken);

    public bool IsOnboardingValidationState(string state)
        => !string.IsNullOrEmpty(state) && _pendingOnboardingValidations.ContainsKey(state);

    /// <summary>
    /// Begin a non-interactive OIDC session check for issue #135. prompt=none
    /// means an existing IdP browser session succeeds without UI; a logged-out
    /// IdP returns login_required/interaction_required and the callback fails
    /// closed to Jellyfin's stock login page.
    /// </summary>
    public async Task<(string AuthUrl, string State)> BeginOnboardingValidationAsync(
        OidcProvider provider,
        Guid userId,
        string subject,
        string redirectUri,
        string accessToken)
    {
        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);
        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var state = Base64Url(RandomNumberGenerator.GetBytes(24));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(24));

        PruneAndCap(_pendingOnboardingValidations, p => p.ExpiresAt);
        _pendingOnboardingValidations[state] = new PendingOnboardingValidation(
            provider.Id,
            userId,
            subject,
            accessToken,
            codeVerifier,
            nonce,
            DateTime.UtcNow.AddMinutes(5));

        var qs = new List<(string, string)>
        {
            ("client_id", provider.ClientId),
            ("response_type", "code"),
            ("scope", provider.Scopes),
            ("redirect_uri", redirectUri),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
            ("prompt", "none"),
        };

        var url = disc.AuthorizationEndpoint + "?"
            + string.Join("&", qs.Select(kv =>
                $"{Uri.EscapeDataString(kv.Item1)}={Uri.EscapeDataString(kv.Item2)}"));
        return (url, state);
    }

    public OnboardingValidationResult RejectOnboardingValidation(
        string state,
        string error)
    {
        if (!_pendingOnboardingValidations.TryRemove(state, out var pending))
        {
            return new OnboardingValidationResult(false, "Validation state expired", null, null, null);
        }
        return new OnboardingValidationResult(false, error, pending.UserId, null, pending.AccessToken);
    }

    public async Task<OnboardingValidationResult> CompleteOnboardingValidationAsync(
        OidcProvider provider,
        string code,
        string state,
        string redirectUri,
        OnboardingSessionProofStore proofStore)
    {
        if (!_pendingOnboardingValidations.TryRemove(state, out var pending))
        {
            return new OnboardingValidationResult(false, "Validation state expired", null, null, null);
        }
        if (pending.ProviderId != provider.Id || pending.ExpiresAt <= DateTime.UtcNow)
        {
            return new OnboardingValidationResult(false, "Validation state is invalid", pending.UserId, null, pending.AccessToken);
        }

        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);
        using var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = provider.ClientId,
            ["client_secret"] = provider.ClientSecret,
            ["code_verifier"] = pending.CodeVerifier,
        });
        await EnsureSafeOutboundAsync(
            disc.TokenEndpoint,
            provider.AllowPrivateNetworks,
            provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        var tokenResp = await _http.PostAsync(disc.TokenEndpoint, tokenForm).ConfigureAwait(false);
        if (!tokenResp.IsSuccessStatusCode)
        {
            return new OnboardingValidationResult(false, "IdP token exchange failed", pending.UserId, null, pending.AccessToken);
        }

        using var tokenStream = await tokenResp.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var tokenJson = await JsonSerializer.DeserializeAsync<JsonElement>(tokenStream).ConfigureAwait(false);
        if (!tokenJson.TryGetProperty("id_token", out var idTokenElement))
        {
            return new OnboardingValidationResult(false, "IdP response missing id_token", pending.UserId, null, pending.AccessToken);
        }

        ClaimsBundle claims;
        try
        {
            claims = await VerifyIdTokenAsync(
                provider,
                disc,
                idTokenElement.GetString() ?? string.Empty,
                pending.Nonce).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] OIDC onboarding-session validation failed");
            return new OnboardingValidationResult(false, "Token verification failed", pending.UserId, null, pending.AccessToken);
        }

        if (!string.Equals(claims.Subject, pending.Subject, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "[2FA] OIDC onboarding validation subject mismatch for user {UserId}",
                pending.UserId);
            return new OnboardingValidationResult(false, "The active IdP account does not match", pending.UserId, null, pending.AccessToken);
        }

        var data = await _store.GetUserDataAsync(pending.UserId).ConfigureAwait(false);
        if (!data.MustSetPassword
            || !data.SsoLinks.Any(link =>
                string.Equals(link.ProviderId, provider.Id, StringComparison.Ordinal)
                && string.Equals(link.Subject, pending.Subject, StringComparison.Ordinal)))
        {
            return new OnboardingValidationResult(false, "Password onboarding is no longer pending", pending.UserId, null, pending.AccessToken);
        }

        return new OnboardingValidationResult(
            true,
            null,
            pending.UserId,
            proofStore.Mint(pending.UserId),
            pending.AccessToken);
    }

    /// <summary>Process the OIDC step-up callback. Validates state + nonce,
    /// exchanges the code, verifies the id_token, and confirms the returned
    /// subject matches the user's stored <c>SsoLink</c> for this provider.
    /// Does NOT sign anyone in — the caller is already authenticated; this
    /// is purely a fresh-factor proof to gate a sensitive action.</summary>
    public async Task<StepUpResult> CompleteUserStepUpAsync(
        OidcProvider provider, string code, string state, string redirectUri)
    {
        if (!_pendingUserStepUps.TryRemove(state, out var pending))
        {
            return new StepUpResult(false, "Step-up state token not found or expired", null);
        }
        if (pending.ProviderId != provider.Id)
        {
            return new StepUpResult(false, "Step-up state belongs to a different provider", null);
        }
        if (pending.ExpiresAt <= DateTime.UtcNow)
        {
            return new StepUpResult(false, "Step-up flow timed out — try again", null);
        }

        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        using var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = provider.ClientId,
            ["client_secret"] = provider.ClientSecret,
            ["code_verifier"] = pending.CodeVerifier,
        });
        await EnsureSafeOutboundAsync(disc.TokenEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        var tokenResp = await _http.PostAsync(disc.TokenEndpoint, tokenForm).ConfigureAwait(false);
        if (!tokenResp.IsSuccessStatusCode)
        {
            var body = await tokenResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogWarning("[2FA] OIDC step-up token exchange failed: {Status} {Body}", tokenResp.StatusCode, body);
            return new StepUpResult(false, "IdP token exchange failed", null);
        }

        using var tokenStream = await tokenResp.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var tokenJson = await JsonSerializer.DeserializeAsync<JsonElement>(tokenStream).ConfigureAwait(false);
        if (!tokenJson.TryGetProperty("id_token", out var idTokenEl))
        {
            return new StepUpResult(false, "IdP response missing id_token", null);
        }
        var idToken = idTokenEl.GetString() ?? string.Empty;

        ClaimsBundle claims;
        try
        {
            claims = await VerifyIdTokenAsync(provider, disc, idToken, pending.Nonce).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] OIDC step-up id_token verification failed");
            return new StepUpResult(false, "Token verification failed: " + ex.Message, null);
        }

        // Subject-match check. The current Jellyfin user must have an
        // SsoLink for this provider whose Subject == the IdP-returned sub.
        // Without this, signing into Google as ANY account would step-up
        // ANY plugin user — the entire point of step-up is gone.
        var userData = await _store.GetUserDataAsync(pending.UserId).ConfigureAwait(false);
        var link = userData.SsoLinks.FirstOrDefault(l =>
            string.Equals(l.ProviderId, provider.Id, StringComparison.Ordinal)
            && string.Equals(l.Subject, claims.Subject, StringComparison.Ordinal));
        if (link is null)
        {
            _logger.LogWarning(
                "[2FA] OIDC step-up subject mismatch: user {UserId} has no link to {ProviderId} subject {Subject}",
                pending.UserId, provider.Id, claims.Subject);
            return new StepUpResult(false, "This IdP account is not linked to your Jellyfin user", null);
        }

        // Update LastUsedAt for audit/UI display.
        await _store.MutateAsync(pending.UserId, ud =>
        {
            var l = ud.SsoLinks.FirstOrDefault(x =>
                string.Equals(x.ProviderId, provider.Id, StringComparison.Ordinal)
                && string.Equals(x.Subject, claims.Subject, StringComparison.Ordinal));
            if (l is not null) l.LastUsedAt = DateTime.UtcNow;
        }).ConfigureAwait(false);

        return new StepUpResult(true, null, pending.UserId);
    }

    /// <summary>[v2.5.13] (#95) Non-consuming peek so the shared /Oidc/Callback
    /// can route an explicit-link callback here. Distinct dictionary from step-up
    /// so the two intents never collide on a state token.</summary>
    public bool IsUserLinkState(string state)
        => !string.IsNullOrEmpty(state) && _pendingUserLinks.ContainsKey(state);

    /// <summary>[v2.5.13] (#95, yannolerobot) Begin an EXPLICIT account-link for an
    /// already-authenticated user (Setup → "Link a new provider"). The Jellyfin
    /// user is fixed up-front and bound into single-use, server-side state, so the
    /// callback can link by the IdP-returned <c>sub</c> WITHOUT the sign-in
    /// resolver — which refuses admin email/username matches as an anti-takeover
    /// measure and is exactly why admins couldn't link. prompt=login forces a
    /// fresh authentication at the IdP.</summary>
    public async Task<(string AuthUrl, string State)> BeginUserLinkAsync(
        OidcProvider provider, Guid userId, string redirectUri)
    {
        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var state = Base64Url(RandomNumberGenerator.GetBytes(24));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(24));

        PruneAndCap(_pendingUserLinks, p => p.ExpiresAt);
        // [v2.5.14] (#95) 15-min window (was 10). prompt=login forces a fresh IdP
        // authentication, and an admin re-entering credentials / completing the
        // IdP's own MFA can easily exceed 10 minutes; an expired link state silently
        // falls the callback through to the sign-in resolver, which then refuses
        // the admin (the exact symptom chrisbehectik reported).
        _pendingUserLinks[state] = new PendingUserStepUp(
            provider.Id, userId, codeVerifier, nonce,
            DateTime.UtcNow.AddMinutes(15));
        _logger.LogInformation(
            "[2FA] OIDC explicit-link flow started for user {UserId} via provider {Provider} (state bound server-side, 15-min TTL)",
            userId, provider.Id);

        var qs = new List<(string, string)>
        {
            ("client_id", provider.ClientId),
            ("response_type", "code"),
            ("scope", provider.Scopes),
            ("redirect_uri", redirectUri),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
        };
        // [#119] prompt=login forces a fresh IdP auth for the link flow too;
        // suppressible per-provider (OmitPromptLogin) for IdPs like Authentik
        // that 404 on it (upstream bug #18507).
        if (!provider.OmitPromptLogin)
            qs.Add(("prompt", "login"));
        if (!string.IsNullOrWhiteSpace(provider.AcrValues))
            qs.Add(("acr_values", provider.AcrValues));

        var url = disc.AuthorizationEndpoint + "?" +
            string.Join("&", qs.Select(kv => $"{Uri.EscapeDataString(kv.Item1)}={Uri.EscapeDataString(kv.Item2)}"));
        return (url, state);
    }

    /// <summary>[v2.5.13] (#95) Complete an explicit account-link: token exchange,
    /// id_token verification, then create the SsoLink for the bound (authenticated)
    /// user by the returned subject. Refuses if that provider+subject is already
    /// linked to a DIFFERENT Jellyfin user (one IdP identity → one account). This
    /// is the sanctioned path for an admin to link OIDC from Setup.</summary>
    public async Task<StepUpResult> CompleteUserLinkAsync(
        OidcProvider provider, string code, string state, string redirectUri)
    {
        if (!_pendingUserLinks.TryRemove(state, out var pending))
        {
            return new StepUpResult(false, "Link state token not found or expired", null);
        }
        if (pending.ProviderId != provider.Id)
        {
            return new StepUpResult(false, "Link state belongs to a different provider", null);
        }
        if (pending.ExpiresAt <= DateTime.UtcNow)
        {
            return new StepUpResult(false, "Link flow timed out — try again", null);
        }

        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);
        using var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = provider.ClientId,
            ["client_secret"] = provider.ClientSecret,
            ["code_verifier"] = pending.CodeVerifier,
        });
        await EnsureSafeOutboundAsync(disc.TokenEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        var tokenResp = await _http.PostAsync(disc.TokenEndpoint, tokenForm).ConfigureAwait(false);
        if (!tokenResp.IsSuccessStatusCode)
        {
            var body = await tokenResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogWarning("[2FA] OIDC link token exchange failed: {Status} {Body}", tokenResp.StatusCode, body);
            return new StepUpResult(false, "IdP token exchange failed", null);
        }

        using var tokenStream = await tokenResp.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var tokenJson = await JsonSerializer.DeserializeAsync<JsonElement>(tokenStream).ConfigureAwait(false);
        if (!tokenJson.TryGetProperty("id_token", out var idTokenEl))
        {
            return new StepUpResult(false, "IdP response missing id_token", null);
        }

        ClaimsBundle claims;
        try
        {
            claims = await VerifyIdTokenAsync(provider, disc, idTokenEl.GetString() ?? string.Empty, pending.Nonce).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] OIDC link id_token verification failed");
            return new StepUpResult(false, "Token verification failed: " + ex.Message, null);
        }

        // The IdP identity must not already belong to a DIFFERENT Jellyfin user.
        var allUsers = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var ownedByOther = allUsers.Any(d => d.UserId != pending.UserId
            && d.SsoLinks.Any(l => string.Equals(l.ProviderId, provider.Id, StringComparison.Ordinal)
                && string.Equals(l.Subject, claims.Subject, StringComparison.Ordinal)));
        if (ownedByOther)
        {
            _logger.LogWarning(
                "[2FA] OIDC explicit link refused: {Provider} subject is already linked to a different Jellyfin user",
                provider.Id);
            return new StepUpResult(false, "That identity-provider account is already linked to another Jellyfin user", null);
        }

        await _store.MutateAsync(pending.UserId, ud =>
        {
            var existing = ud.SsoLinks.FirstOrDefault(l =>
                string.Equals(l.ProviderId, provider.Id, StringComparison.Ordinal)
                && string.Equals(l.Subject, claims.Subject, StringComparison.Ordinal));
            if (existing is null)
            {
                ud.SsoLinks.Add(new SsoLink
                {
                    ProviderId = provider.Id,
                    Subject = claims.Subject,
                    Email = claims.Email,
                    LinkedAt = DateTime.UtcNow,
                    LastUsedAt = DateTime.UtcNow,
                });
            }
            else
            {
                existing.Email = claims.Email;
                existing.LastUsedAt = DateTime.UtcNow;
            }
        }).ConfigureAwait(false);

        _logger.LogInformation("[2FA] OIDC explicit link created: user {UserId} linked to {Provider} (sub={Sub})",
            pending.UserId, provider.Id, claims.Subject);
        return new StepUpResult(true, null, pending.UserId);
    }

    /// <summary>v2.5.1: RFC 8693-style token-exchange entry point for native
    /// clients (Swiftfin, Findroid, Tizen apps, …) that performed their own
    /// OIDC auth-code+PKCE flow at the IdP and now hold an id_token issued
    /// for OUR ClientId. We re-verify the id_token (signature, issuer,
    /// audience=ClientId, expiry — NOT nonce, since we didn't issue one) and
    /// run the same post-verification pipeline as CompleteAsync. The
    /// controller then mints a one-shot bridge token the client posts to
    /// /Users/AuthenticateByName, identical to the browser flow.</summary>
    public async Task<CallbackResult> ExchangeIdTokenAsync(
        OidcProvider provider, string idToken, string? accessToken)
    {
        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        ClaimsBundle claims;
        try
        {
            // expectedNonce=null deliberately — see VerifyIdTokenAsync comment.
            claims = await VerifyIdTokenAsync(provider, disc, idToken, expectedNonce: null).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] OIDC token-exchange id_token verification failed");
            return new CallbackResult(false, "Token verification failed: " + ex.Message, null, null, null, null);
        }

        // SECURITY [v2.5.9] (audit medium): bind the supplied access_token to
        // the verified id_token via at_hash. Without this, a caller could
        // pair a valid id_token (sub=X, aud=ourClientId) with a DIFFERENT
        // user's access_token (sub=Y); the /userinfo fetch in
        // FinalizeSignInAsync would then merge Y's groups + email into X's
        // session — crossing the identity boundary the verified id_token was
        // supposed to establish (group-allowlist satisfaction, email-based
        // user resolution). Reject on explicit mismatch; a missing at_hash
        // can't be validated and is allowed (some IdPs omit it).
        if (!string.IsNullOrEmpty(accessToken) && !AtHashMatches(idToken, accessToken))
        {
            _logger.LogWarning("[2FA] OIDC token-exchange refused: at_hash in id_token does not match the supplied access_token (possible token mix-up).");
            return new CallbackResult(false, "Token verification failed: the access token does not match the id token.", null, null, null, null);
        }

        return await FinalizeSignInAsync(provider, disc, claims, accessToken, returnUrl: string.Empty).ConfigureAwait(false);
    }

    /// <summary>SECURITY [v2.5.9] (audit medium): validate the id_token's
    /// at_hash against the access_token. at_hash = base64url(left-half(HASH(
    /// access_token))) where HASH matches the id_token's signing alg. Returns
    /// false ONLY on an explicit mismatch; a missing at_hash returns true
    /// (can't bind, but don't break IdPs that omit it).</summary>
    private static bool AtHashMatches(string idToken, string accessToken)
    {
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
            var atHash = jwt.Claims.FirstOrDefault(c => c.Type == "at_hash")?.Value;
            if (string.IsNullOrEmpty(atHash)) return true; // not asserted → cannot validate
            var alg = jwt.Header.Alg ?? "RS256";
            var atBytes = Encoding.ASCII.GetBytes(accessToken);
            byte[] hash = alg switch
            {
                "RS384" or "ES384" or "PS384" or "HS384" => SHA384.HashData(atBytes),
                "RS512" or "ES512" or "PS512" or "HS512" => SHA512.HashData(atBytes),
                _ => SHA256.HashData(atBytes),
            };
            var half = new byte[hash.Length / 2];
            Array.Copy(hash, half, half.Length);
            var computed = Base64Url(half);
            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(computed),
                Encoding.ASCII.GetBytes(atHash));
        }
        catch
        {
            // id_token already passed full signature verification before this
            // is called, so a parse failure here is unexpected; don't hard-
            // fail the exchange on a best-effort binding check.
            return true;
        }
    }

    /// <summary>[#134] Builds this provider's RP-Initiated Logout URL, or null
    /// when the feature is off for the provider, the OP publishes no
    /// end_session_endpoint, or the published value is not an absolute https
    /// URL. Never throws: a logout must degrade to today's behaviour rather
    /// than fail, so every problem here returns null.
    ///
    /// Deliberately does NOT send id_token_hint. The plugin never retains an
    /// id_token past verification, and persisting one purely to hint a logout
    /// would mean holding a credential-shaped artifact at rest for the life of
    /// every SSO session, keyed by access token, invalidated by nothing. RP-
    /// Initiated Logout 1.0 s2 makes id_token_hint RECOMMENDED, not REQUIRED,
    /// and allows client_id alongside post_logout_redirect_uri instead;
    /// Keycloak (>= 18) and Authentik both accept that form. An OP that
    /// mandates id_token_hint will ignore post_logout_redirect_uri and land the
    /// user on its own generic sign-out page, which is still strictly better
    /// than the current behaviour of never reaching the OP at all.</summary>
    public async Task<string?> TryBuildEndSessionUrlAsync(OidcProvider provider, string? postLogoutRedirectUri)
    {
        try
        {
            if (provider is null || !provider.Enabled || !provider.RpInitiatedLogoutEnabled)
            {
                return null;
            }

            var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);
            return BuildEndSessionUrl(disc.EndSessionEndpoint, provider.ClientId, postLogoutRedirectUri);
        }
        catch (Exception ex)
        {
            // Discovery can throw (IdP down, cert expired, DNS). Logging out
            // must not depend on the IdP being reachable.
            _logger.LogDebug(ex, "[2FA] RP logout URL unavailable for provider {Id}; falling back to local sign-out", provider?.Id);
            return null;
        }
    }

    /// <summary>[#134] Pure URL composition for RP-initiated logout, split out
    /// so it can be tested without a discovery round-trip. Returns null when
    /// the OP published nothing usable.</summary>
    internal static string? BuildEndSessionUrl(
        string? endSessionEndpoint,
        string? clientId,
        string? postLogoutRedirectUri)
    {
        // An absolute https URL is the only shape we will ever send a browser
        // to. This rejects a relative path, a javascript: or data: value, and
        // anything unparseable, so a malformed or hostile discovery document
        // cannot turn the logout redirect into something that is not a
        // navigation to the IdP.
        if (string.IsNullOrWhiteSpace(endSessionEndpoint)
            || !Uri.TryCreate(endSessionEndpoint, UriKind.Absolute, out var endSessionUri)
            || !endSessionUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Preserve any query the OP already publishes on the endpoint, which a
        // few tenanted OPs do, instead of clobbering it.
        var sb = new StringBuilder(endSessionEndpoint);
        sb.Append(string.IsNullOrEmpty(endSessionUri.Query) ? '?' : '&');
        sb.Append("client_id=").Append(Uri.EscapeDataString(clientId ?? string.Empty));

        // https-only here too, independently of the controller's sanitiser: a
        // config imported through ConfigExportService never passes through it.
        if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri)
            && Uri.TryCreate(postLogoutRedirectUri, UriKind.Absolute, out var plUri)
            && plUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            sb.Append("&post_logout_redirect_uri=").Append(Uri.EscapeDataString(postLogoutRedirectUri));
        }

        return sb.ToString();
    }

    /// <summary>Shared pipeline that runs after an id_token has been verified:
    /// merge /userinfo claims, enforce IdP-MFA + group allowlist, resolve to a
    /// Jellyfin user, persist the SsoLink, and route auth via our provider so
    /// bridge tokens work. Called by both <see cref="CompleteAsync"/> (browser
    /// callback) and <see cref="ExchangeIdTokenAsync"/> (native token exchange).</summary>
    private async Task<CallbackResult> FinalizeSignInAsync(
        OidcProvider provider,
        Discovery disc,
        ClaimsBundle claims,
        string? accessToken,
        string returnUrl)
    {
        // Issue #29: many IdPs (Authelia default, Keycloak default realms,
        // Authentik) emit `groups`/`roles` ONLY in the /userinfo response, not
        // in the id_token JWT. Without this, the AllowedGroups allowlist would
        // reject every user regardless of what scopes were requested. Fetch
        // userinfo and merge any group claims so the allowlist works against
        // the full set.
        if (!string.IsNullOrWhiteSpace(disc.UserInfoEndpoint) && !string.IsNullOrEmpty(accessToken))
        {
            try
            {
                // SECURITY [v2.5.6] (ext review #6): re-validate userinfo
                // endpoint before each fetch — same DNS-rebind window as the
                // token endpoint. See GetJwksAsync for the same pattern.
                await EnsureSafeOutboundAsync(disc.UserInfoEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
                var extra = await FetchUserInfoClaimsAsync(disc.UserInfoEndpoint, accessToken, provider.EmailClaim).ConfigureAwait(false);
                if (extra.Groups.Length > 0)
                {
                    var merged = claims.Groups
                        .Concat(extra.Groups)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    claims = claims with { Groups = merged };
                    _logger.LogDebug("[2FA] OIDC merged {N} group(s) from /userinfo", extra.Groups.Length);
                }
                // Issue #29 follow-up: many IdPs (Authelia 4.39 default) also
                // emit email/email_verified ONLY at /userinfo. Without merging
                // them here, the ResolveUserAsync email-match path can never
                // find an existing Jellyfin user, and the flow falls through to
                // auto-create which collides with same-named existing users.
                //
                // SECURITY [v2.5.5] (N-A20): the userinfo email is trusted on
                // the strength of (1) a valid OIDC access_token from the
                // token-exchange path that was bound to a signed id_token,
                // and (2) the HTTPS+IP-validated userinfo_endpoint URL
                // (EnsureSafeOutboundAsync). Implicit threat model: a fully
                // compromised IdP (one that can return arbitrary userinfo
                // for any access_token) can claim any email for the
                // authenticated user, and that email is then used for
                // UserEmails mapping. This is the standard OIDC trust
                // boundary — the IdP is the source of truth for identity.
                // If a future feature uses the email for elevation rather
                // than lookup, re-verification at Jellyfin level should be
                // added.
                if (string.IsNullOrEmpty(claims.Email) && !string.IsNullOrEmpty(extra.Email))
                {
                    claims = claims with { Email = extra.Email, EmailVerified = extra.EmailVerified };
                    _logger.LogDebug("[2FA] OIDC merged email from /userinfo (verified={V})", extra.EmailVerified);
                }
                // Username from userinfo when id_token didn't provide one
                // under the configured UsernameClaim. Authelia's
                // preferred_username is also typically userinfo-only.
                if (string.IsNullOrEmpty(claims.Username) && !string.IsNullOrEmpty(extra.Username))
                {
                    claims = claims with { Username = extra.Username };
                    _logger.LogDebug("[2FA] OIDC merged username from /userinfo");
                }
                // [v2.5.10] (#66) avatar URL: many IdPs only return `picture`
                // at /userinfo, not in the id_token. Merge it when missing.
                if (string.IsNullOrEmpty(claims.Picture) && !string.IsNullOrEmpty(extra.Picture))
                {
                    claims = claims with { Picture = extra.Picture };
                    _logger.LogDebug("[2FA] OIDC merged picture from /userinfo");
                }
            }
            catch (Exception ex)
            {
                // Userinfo is a best-effort supplement. id_token claims already
                // verified the identity; failure here just means we don't
                // augment claims. Log at Debug so it doesn't spam logs for
                // IdPs that don't expose /userinfo at all.
                _logger.LogDebug(ex, "[2FA] OIDC /userinfo fetch failed — continuing with id_token claims only");
            }
        }

        // Optional: enforce IdP MFA via amr claim.
        if (provider.RequireIdpMfa && !claims.Amr.Any(a =>
            a.Equals("mfa", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("hwk", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("otp", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("sca", StringComparison.OrdinalIgnoreCase)))
        {
            return new CallbackResult(false, "Provider requires MFA at the IdP — enable 2FA on your IdP account", null, null, null, null);
        }

        // Optional: enforce group allowlist.
        if (!string.IsNullOrWhiteSpace(provider.AllowedGroups))
        {
            var allowed = provider.AllowedGroups.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (!claims.Groups.Any(g => allowed.Any(a => a.Equals(g, StringComparison.OrdinalIgnoreCase))))
            {
                return new CallbackResult(false, "Account is not in an allowed group", null, null, null, null);
            }
        }

        // Resolve to a Jellyfin user: first by existing SsoLink (sub), then
        // by email-match against email-OTP config, then optionally auto-create.
        var matchedUser = await ResolveUserAsync(provider, claims).ConfigureAwait(false);
        if (matchedUser is null)
        {
            return new CallbackResult(false,
                provider.AutoCreateUsers
                    ? "Auto-create failed — see server log"
                    : "No Jellyfin user matched the IdP identity. Sign in with your password once and link this account from Setup.",
                null, null, null, null);
        }

        // Persist / update the SsoLink so future sign-ins match by sub.
        var link = new SsoLink
        {
            ProviderId = provider.Id,
            Subject = claims.Subject,
            Email = claims.Email,
            LinkedAt = DateTime.UtcNow,
            LastUsedAt = DateTime.UtcNow,
        };
        await _store.MutateAsync(matchedUser.Id, ud =>
        {
            var existing = ud.SsoLinks.FirstOrDefault(l =>
                l.ProviderId == provider.Id && l.Subject == claims.Subject);
            if (existing is null)
            {
                ud.SsoLinks.Add(link);
            }
            else
            {
                existing.Email = claims.Email;
                existing.LastUsedAt = DateTime.UtcNow;
            }
        }).ConfigureAwait(false);

        // [v2.5.11] (#70, ZEROX7) Fill the user's plugin email (used for email
        // OTP and shown in the admin Users tab) from the IdP email claim when
        // it isn't already set. Never overwrites an admin-entered address.
        // Best-effort: a failure must never block a sign-in.
        // [v2.5.12] (#80, ZEROX7): explain WHY the auto-fill no-ops, so "email
        // claim didn't work" is diagnosable from the log instead of being silent.
        if (!provider.SyncEmailFromClaim)
        {
            _logger.LogDebug("[2FA] OIDC email auto-fill OFF for provider {Provider} (enable 'sync email from claim')", provider.Id);
        }
        else if (string.IsNullOrWhiteSpace(claims.Email))
        {
            _logger.LogInformation(
                "[2FA] OIDC email auto-fill: no email in claims for {User} — IdP sent nothing under claim '{Claim}' (or /userinfo). Check the 'email' scope is requested and the claim name matches.",
                matchedUser.Username, string.IsNullOrWhiteSpace(provider.EmailClaim) ? "email" : provider.EmailClaim);
        }
        else
        {
            try
            {
                var cfg = Plugin.Instance?.Configuration;
                var userKey = matchedUser.Id.ToString("N");
                if (cfg is not null && string.IsNullOrWhiteSpace(cfg.GetUserEmail(userKey)))
                {
                    cfg.SetUserEmail(userKey, claims.Email);
                    Plugin.Instance!.SaveConfiguration();
                    _logger.LogInformation("[2FA] OIDC filled email for {User} from IdP claim '{Claim}'", matchedUser.Username, provider.EmailClaim);
                }
                else
                {
                    _logger.LogDebug("[2FA] OIDC email auto-fill skipped for {User} — a plugin email is already set (never overwrites a manual address)", matchedUser.Username);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] OIDC email auto-fill failed for {User}", matchedUser.Username);
            }
        }

        // [v2.5.13] (#96, raffaeletani) Grant Jellyfin admin from IdP admin-group
        // claims. Runs BEFORE the role→library step so a user promoted to admin is
        // then skipped by the (admin-exempt) library restriction below. Grant-only
        // by design — we never auto-revoke admin here, to avoid demoting or locking
        // out an admin who isn't represented in the IdP group.
        // Best-effort: a failure must never block a sign-in. Requires BOTH the
        // explicit opt-in toggle AND a configured group list (defence in depth).
        if (provider.AllowAdminGroupElevation && !string.IsNullOrWhiteSpace(provider.AdminGroups))
        {
            try
            {
                await ApplyAdminGroupAsync(matchedUser, provider, claims.Groups).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] OIDC admin-group sync failed for {User}", matchedUser.Username);
            }
        }

        // [v2.5.10] (#65) Apply role→library access from the IdP group claims.
        // Best-effort: a failure must never block a sign-in.
        if (provider.ApplyRoleLibraryAccess)
        {
            try
            {
                await ApplyRoleLibraryAccessAsync(matchedUser, provider, claims.Groups).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] OIDC role→library access sync failed for {User}", matchedUser.Username);
            }
        }

        // [v2.5.10] (#66) Sync the IdP profile picture into the Jellyfin avatar.
        // Best-effort: a failure must never block a sign-in.
        if (provider.SyncProfilePicture && !string.IsNullOrWhiteSpace(claims.Picture))
        {
            try
            {
                await ApplyProfilePictureAsync(matchedUser, provider, claims.Picture).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] OIDC profile-picture sync failed for {User}", matchedUser.Username);
            }
        }

        // Route this user's auth through our provider so bridge tokens work.
        // Our Authenticate delegates to the default provider for normal
        // passwords, so flipping this is additive — password login still
        // works identically.
        try
        {
            var ourProviderId = typeof(TwoFactorAuthProvider).FullName!;
            // CORRECTNESS [v2.5.14] (#65/#96): this is the LAST UpdateUserAsync of
            // the sign-in, and it must not clobber the EnabledFolders / admin
            // elevation the apply-steps above just persisted. Operate on a fresh
            // DB-tracked fetch so persisting it writes back the just-saved policy
            // rather than the stale (possibly detached) `matchedUser` whose
            // Preferences/Permissions collections predate those grants.
            var freshForProvider = _userManager.GetUserById(matchedUser.Id) ?? matchedUser;
            if (!string.Equals(freshForProvider.AuthenticationProviderId, ourProviderId, StringComparison.Ordinal))
            {
                freshForProvider.AuthenticationProviderId = ourProviderId;
                await _userManager.UpdateUserAsync(freshForProvider).ConfigureAwait(false);
                _logger.LogInformation("[2FA] Reassigned {User} AuthenticationProviderId to TwoFactorAuthProvider for OIDC bridge", matchedUser.Username);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Could not reassign AuthenticationProviderId for {User}", matchedUser.Username);
        }

        return new CallbackResult(true, null, matchedUser.Id, matchedUser.Username, returnUrl, link);
    }

    /// <summary>[v2.5.10] (issue #65, Bgabor997): set the user's Jellyfin
    /// library access from their IdP role/group claims. The union of libraries
    /// granted by every role the user holds becomes their EnabledFolders;
    /// EnableAllFolders is turned off. Administrators are never restricted.
    /// If no mappings are configured we leave the user untouched rather than
    /// stripping all access (defensive — avoids locking everyone out the
    /// moment the toggle is flipped before mappings exist).</summary>
    private async Task ApplyRoleLibraryAccessAsync(User user, OidcProvider provider, string[] groups)
    {
        // Admins implicitly see everything — never restrict an administrator.
        if (user.HasPermission(PermissionKind.IsAdministrator))
        {
            return;
        }

        if (provider.RoleLibraryMappings is null || provider.RoleLibraryMappings.Count == 0)
        {
            _logger.LogWarning(
                "[2FA] OIDC role→library access enabled for provider {Provider} but no mappings configured; leaving {User}'s library access unchanged",
                provider.Id, user.Username);
            return;
        }

        // Validate against libraries that actually exist so a stale mapping ID
        // can't poison the policy with a dangling GUID.
        var existing = _libraryManager.GetVirtualFolders()
            .Select(v => v.ItemId)
            .Where(id => !string.IsNullOrEmpty(id))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var finalIds = ComputeGrantedLibraryIds(provider.RoleLibraryMappings, groups, existing);

        // CORRECTNESS [v2.5.14] (#65, Bgabor997): persist library access via the
        // USER POLICY API, not SetPreference + UpdateUserAsync. Verified live on
        // Jellyfin 10.11.11: SetPreference(EnabledFolders)/SetPermission(...) +
        // UpdateUserAsync does NOT persist policy fields at all (a fresh read-back
        // shows them empty) — UpdateUserAsync only saves the User's scalar columns,
        // not the Permissions/Preferences that back the policy. That is the true
        // cause of #65 (the user's log showed the right GUIDs because it read them
        // straight off the in-memory object, never from the DB). Jellyfin's own
        // dashboard sets library access through IUserManager.UpdatePolicyAsync, and
        // that round-trips correctly. So: take the user's CURRENT policy (preserves
        // every other field), set just EnableAllFolders + EnabledFolders, and
        // persist via UpdatePolicyAsync.
        var policy = _userManager.GetUserDto(user).Policy;
        policy.EnableAllFolders = false;
        // UserPolicy.EnabledFolders is Guid[]; finalIds are library ItemIds in
        // "N" (32-hex) form already validated to exist, so parse them to Guids.
        policy.EnabledFolders = finalIds
            .Select(s => Guid.TryParse(s, out var g) ? (Guid?)g : null)
            .Where(g => g.HasValue)
            .Select(g => g!.Value)
            .ToArray();
        await _userManager.UpdatePolicyAsync(user.Id, policy).ConfigureAwait(false);

        // Read the policy BACK from a fresh DTO so the log is conclusive (this read
        // goes through the same DTO mapping the dashboard uses, so it reflects what
        // actually persisted — not an in-memory object).
        var persistedPolicy = _userManager.GetUserDto(_userManager.GetUserById(user.Id) ?? user).Policy;
        var readBack = (persistedPolicy.EnabledFolders ?? Array.Empty<Guid>())
            .Select(g => g.ToString("N")).ToArray();
        var enableAll = persistedPolicy.EnableAllFolders;
        _logger.LogInformation(
            "[2FA] OIDC set {Count} librar(ies) for {User} from {GroupCount} IdP group claim(s) via provider {Provider}; granted=[{Granted}] persisted=[{Persisted}] enableAllFolders={EnableAll}",
            finalIds.Length, user.Username, groups.Length, provider.Id,
            string.Join(",", finalIds), string.Join(",", readBack), enableAll);

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            var avail = _libraryManager.GetVirtualFolders()
                .Select(v => (v.Name ?? "(unnamed)") + ":" + (v.ItemId ?? "(no-id)"));
            _logger.LogDebug("[2FA] OIDC available libraries (name:itemId) for #65 diagnosis: [{Libraries}]",
                string.Join(" | ", avail));
        }
    }

    /// <summary>[v2.5.13] (#96, raffaeletani) Grant Jellyfin administrator rights
    /// when the user's IdP group claims contain one of the provider's configured
    /// AdminGroups. Grant-only by design (never auto-revokes) so an admin who isn't
    /// in the IdP group is not silently demoted or locked out.</summary>
    private async Task ApplyAdminGroupAsync(User user, OidcProvider provider, string[] groups)
    {
        var adminGroups = (provider.AdminGroups ?? string.Empty)
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (adminGroups.Length == 0 || groups is null || groups.Length == 0)
        {
            return;
        }

        var inAdminGroup = groups.Any(g => g != null
            && adminGroups.Any(a => a.Equals(g, StringComparison.OrdinalIgnoreCase)));
        if (!inAdminGroup)
        {
            _logger.LogDebug(
                "[2FA] OIDC admin-group: {User} is in none of the configured admin groups; leaving admin status unchanged",
                user.Username);
            return;
        }

        if (user.HasPermission(PermissionKind.IsAdministrator))
        {
            _logger.LogDebug("[2FA] OIDC admin-group: {User} is already an administrator", user.Username);
            return;
        }

        // CORRECTNESS [v2.5.14] (#96, raffaeletani): elevate via the USER POLICY
        // API. Same root cause as #65 — SetPermission(IsAdministrator) +
        // UpdateUserAsync does NOT persist on Jellyfin 10.11.11 (UpdateUserAsync
        // doesn't save the policy-backing Permissions), so the elevation silently
        // no-opped. That is why "admin group without effect" was reported even with
        // the toggle on. Set IsAdministrator on the current policy and persist via
        // UpdatePolicyAsync (what the dashboard's "Administrator" checkbox uses).
        var policy = _userManager.GetUserDto(user).Policy;
        policy.IsAdministrator = true;
        await _userManager.UpdatePolicyAsync(user.Id, policy).ConfigureAwait(false);
        var elevated = _userManager.GetUserDto(_userManager.GetUserById(user.Id) ?? user).Policy.IsAdministrator;
        if (!elevated)
        {
            _logger.LogWarning(
                "[2FA] OIDC admin-group: elevation of {User} did NOT persist (read-back still non-admin) — please report against #96",
                user.Username);
        }
        // [v2.5.13] Logged at WARN per the N-A13 security note on OidcProvider.AdminGroups:
        // admin elevation is driven by an IdP-asserted group claim, so a compromised IdP
        // that controls that claim could elevate. The admin opts in by configuring the
        // group; surfacing every elevation makes it auditable.
        _logger.LogWarning(
            "[2FA] OIDC ELEVATED {User} to administrator via admin-group match (provider {Provider}). " +
            "Driven by the IdP groups claim — ensure that claim is trustworthy.",
            user.Username, provider.Id);
    }

    /// <summary>[v2.5.13] (#93, Re4mstr) Copy a template user's permissions and
    /// preferences onto a freshly auto-created OIDC user, so new SSO users inherit
    /// a chosen reference account's access instead of Jellyfin's broad defaults.
    /// Iterates every PermissionKind/PreferenceKind with a per-item try/catch so an
    /// enum value unknown to a given Jellyfin build can't abort the whole copy.</summary>
    private async Task CopyUserPolicyAsync(Guid templateId, User target)
    {
        var template = _userManager.GetUserById(templateId);
        if (template is null)
        {
            _logger.LogWarning("[2FA] OIDC template user {Id} not found — new user keeps Jellyfin defaults", templateId);
            return;
        }
        if (template.Id == target.Id)
        {
            return;
        }

        // CORRECTNESS [v2.5.14] (#93): copy via the USER POLICY API. The old
        // SetPermission/SetPreference + UpdateUserAsync loop did NOT persist on
        // Jellyfin 10.11.11 (UpdateUserAsync doesn't save the policy-backing
        // Permissions/Preferences — same root cause as #65/#96), so template users
        // silently inherited Jellyfin defaults instead of the template's policy.
        // Copying the template's whole UserPolicy and persisting it via
        // UpdatePolicyAsync is both correct AND simpler than the per-enum loop.
        var templatePolicy = _userManager.GetUserDto(template).Policy;
        await _userManager.UpdatePolicyAsync(target.Id, templatePolicy).ConfigureAwait(false);
        _logger.LogInformation("[2FA] OIDC seeded new user {New} permissions from template user {Tpl}",
            target.Username, template.Username);
    }

    /// <summary>[v2.5.10] (issue #65) Pure mapping: given the user's IdP
    /// group/role claims and the provider's role→library mappings, return the
    /// distinct set of library IDs to grant — the UNION across every mapping
    /// whose Role matches one of the user's groups (case-insensitive), filtered
    /// to libraries that actually exist. Extracted as a static, dependency-free
    /// method so the role-matching logic is unit-testable without a live IdP or
    /// Jellyfin host. Returns an empty array when no role matches (caller turns
    /// EnableAllFolders off, so the user then sees no libraries).</summary>
    internal static string[] ComputeGrantedLibraryIds(
        System.Collections.Generic.IReadOnlyList<OidcRoleLibraryMapping> mappings,
        string[] groups,
        System.Collections.Generic.ISet<string> existingLibraryIds)
    {
        var grantedIds = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (mappings is null || groups is null)
        {
            return Array.Empty<string>();
        }

        foreach (var map in mappings)
        {
            if (map is null || string.IsNullOrWhiteSpace(map.Role))
            {
                continue;
            }

            if (!groups.Any(g => g != null && g.Equals(map.Role, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            foreach (var id in (map.LibraryIds ?? string.Empty)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                grantedIds.Add(id);
            }
        }

        return grantedIds
            .Where(id => existingLibraryIds is null || existingLibraryIds.Contains(id))
            .ToArray();
    }

    /// <summary>[v2.5.10] (issue #66, ZEROX7): download the IdP-provided avatar
    /// and set it as the Jellyfin user's profile picture. Mirrors Jellyfin's
    /// own ImageController (ClearProfileImage → ImageInfo → IProviderManager
    /// .SaveImage → UpdateUserAsync). The fetch is SSRF-guarded by the same
    /// egress policy as the other IdP calls, content-type-restricted to common
    /// image types, and size-capped. Skips work when the URL is unchanged from
    /// the last sync recorded on the SsoLink.</summary>
    private async Task ApplyProfilePictureAsync(User user, OidcProvider provider, string pictureUrl)
    {
        // Skip if we already synced this exact URL for this provider link.
        var data = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);
        var link = data.SsoLinks.FirstOrDefault(l => l.ProviderId == provider.Id);
        if (link is not null && string.Equals(link.SyncedPictureUrl, pictureUrl, StringComparison.Ordinal))
        {
            return;
        }

        // SSRF guard — same egress policy as discovery/token/userinfo fetches.
        await EnsureSafeOutboundAsync(pictureUrl, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);

        using var resp = await _http.GetAsync(pictureUrl, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        var mime = resp.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? string.Empty;
        var ext = mime switch
        {
            "image/jpeg" or "image/jpg" => ".jpg",
            "image/png" => ".png",
            "image/webp" => ".webp",
            "image/gif" => ".gif",
            _ => null,
        };
        if (ext is null)
        {
            _logger.LogWarning("[2FA] OIDC picture sync skipped for {User}: unsupported content-type '{Mime}'", user.Username, mime);
            return;
        }

        const long maxBytes = 10 * 1024 * 1024;
        if (resp.Content.Headers.ContentLength is long len && len > maxBytes)
        {
            _logger.LogWarning("[2FA] OIDC picture sync skipped for {User}: image too large ({Len} bytes)", user.Username, len);
            return;
        }

        var bytes = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        if (bytes.Length == 0 || bytes.Length > maxBytes)
        {
            _logger.LogWarning("[2FA] OIDC picture sync skipped for {User}: empty or oversized image ({Len} bytes)", user.Username, bytes.Length);
            return;
        }

        var userDataPath = Path.Combine(_serverConfig.ApplicationPaths.UserConfigurationDirectoryPath, user.Username);
        Directory.CreateDirectory(userDataPath);

        if (user.ProfileImage is not null)
        {
            await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
        }

        user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile" + ext));

        using (var ms = new MemoryStream(bytes))
        {
            await _providerManager.SaveImage(ms, mime, user.ProfileImage.Path).ConfigureAwait(false);
        }

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        // Record the synced URL so the next sign-in skips an unchanged avatar.
        await _store.MutateAsync(user.Id, ud =>
        {
            var l = ud.SsoLinks.FirstOrDefault(x => x.ProviderId == provider.Id);
            if (l is not null) l.SyncedPictureUrl = pictureUrl;
        }).ConfigureAwait(false);

        _logger.LogInformation("[2FA] OIDC synced profile picture for {User} from provider {Provider}", user.Username, provider.Id);
    }

    /// <summary>Try to find a Jellyfin user matching the IdP claims. Order:
    /// (1) existing SsoLink, (2) email match against UserEmails config,
    /// (3) auto-create if provider allows.</summary>
    private async Task<Jellyfin.Database.Implementations.Entities.User?> ResolveUserAsync(OidcProvider provider, ClaimsBundle claims)
    {
        // 1. Existing link by sub
        var allUsers = await _store.GetAllUsersAsync().ConfigureAwait(false);
        foreach (var data in allUsers)
        {
            if (data.SsoLinks.Any(l => l.ProviderId == provider.Id && l.Subject == claims.Subject))
            {
                var u = _userManager.GetUserById(data.UserId);
                if (u is not null) return u;
            }
        }

        // 2. Email match (verified emails only)
        if (!string.IsNullOrEmpty(claims.Email) && claims.EmailVerified)
        {
            var config = Plugin.Instance?.Configuration;
            if (config is not null)
            {
                // Resolve each configured-email match to a LIVE Jellyfin user.
                // [v2.5.11] (ZEROX7): drop entries whose UserId no longer
                // resolves. A stale UserEmails row left behind by a DELETED
                // account would otherwise count as a phantom duplicate and
                // wrongly trip the ambiguity guard below, locking the surviving
                // real user out of OIDC sign-in. Distinct by id so the same
                // user listed twice doesn't read as ambiguous either.
                var liveMatches = config.UserEmails
                    .Where(e => string.Equals(e.Email, claims.Email, StringComparison.OrdinalIgnoreCase))
                    .Select(e => Guid.TryParse(e.UserId, out var g) ? g : Guid.Empty)
                    .Where(g => g != Guid.Empty)
                    .Distinct()
                    .Select(g => _userManager.GetUserById(g))
                    .Where(u => u is not null)
                    .Cast<Jellyfin.Database.Implementations.Entities.User>()
                    .ToList();

                // SECURITY [v2.5.10]: refuse an AMBIGUOUS email match. If more
                // than one EXISTING Jellyfin user has this email configured, we
                // cannot know which account the IdP identity belongs to —
                // silently taking the first could attach the external account
                // to, and sign the caller in as, the WRONG user (e.g. the
                // admin). Refuse and make the admin give each user a unique
                // email or link explicitly from Setup.
                if (liveMatches.Count > 1)
                {
                    _logger.LogWarning(
                        "[2FA] OIDC email-match refused: {Count} Jellyfin users share email '{Email}'. Give each user a unique email or link the account explicitly from Setup.",
                        liveMatches.Count, claims.Email);
                }
                else if (liveMatches.Count == 1)
                {
                    var u = liveMatches[0];
                    var linkedData = allUsers.FirstOrDefault(d => d.UserId == u.Id);
                    if (HasConflictingProviderLink(linkedData, provider.Id, claims.Subject))
                    {
                        _logger.LogWarning(
                            "[2FA] OIDC email-match refused: Jellyfin user '{User}' is already linked to a different {Provider} subject. Possible takeover attempt.",
                            u.Username,
                            provider.Id);
                        return null;
                    }
                    // SECURITY [v2.5.10]: never resolve/auto-link an
                    // ADMINISTRATOR via the email fallback. An IdP-asserted
                    // email (which the user controls on open-registration
                    // IdPs) matching the admin's configured address would
                    // otherwise hand out a Jellyfin admin session. Admins
                    // must link OIDC explicitly from their Setup page, which
                    // creates an SsoLink matched by the immutable `sub`
                    // (step 1 above). Mirrors the username-match admin guard.
                    if (u.HasPermission(PermissionKind.IsAdministrator))
                    {
                        _logger.LogWarning(
                            "[2FA] OIDC email-match refused for administrator '{User}': admins must link OIDC explicitly from Setup, not via IdP-asserted email.",
                            u.Username);
                    }
                    else
                    {
                        return u;
                    }
                }
            }
        }

        // 2b. Link-on-first-use for a pre-existing Jellyfin user (Issue #48).
        // If a Jellyfin user with this preferred_username already exists but
        // has no SsoLink yet (typical when the plugin was installed AFTER
        // the user was created, or when the admin is just enabling OIDC for
        // existing accounts), CreateUserAsync would throw "user already
        // exists" and the sign-in would dead-end. Treat the username match
        // as an implicit link request, subject to two guardrails:
        //   (a) The provider must explicitly allow existing-account username
        //       linking, or AutoCreateUsers must be enabled for compatibility
        //       with the pre-#133 behaviour.
        //   (b) The pre-existing Jellyfin user must NOT already have an
        //       SsoLink for THIS provider with a different subject. That
        //       case means another IdP identity already claimed this user
        //       and we're seeing a second IdP account trying to take over.
        //       Refuse and let the admin reconcile.
        if (AllowsExistingUsernameLink(provider) && !string.IsNullOrEmpty(claims.Username))
        {
                var existing = _userManager.GetUserByName(claims.Username);
            if (existing is not null)
            {
                var existingData = allUsers.FirstOrDefault(d => d.UserId == existing.Id);
                var conflicting = HasConflictingProviderLink(
                    existingData,
                    provider.Id,
                    claims.Subject);
                if (conflicting)
                {
                    _logger.LogWarning(
                        "[2FA] OIDC sign-in refused: Jellyfin user '{User}' already linked to a different {Provider} identity. Possible takeover attempt — admin must reconcile.",
                        claims.Username, provider.Id);
                    return null;
                }
                // SECURITY [v2.5.9] (audit top-tier #1): NEVER implicitly link
                // an IdP-asserted username to a pre-existing ADMINISTRATOR
                // account. On IdPs where the user controls their own
                // preferred_username (open registration, shared tenants), an
                // attacker could register username "admin", sign in, and be
                // auto-linked to — and authenticated as — the real Jellyfin
                // admin. Admin OIDC links must be created explicitly by an
                // admin (pre-existing SsoLink), never auto-linked here.
                if (existing.HasPermission(PermissionKind.IsAdministrator))
                {
                    _logger.LogWarning(
                        "[2FA] OIDC sign-in refused: '{User}' matches an existing ADMINISTRATOR with no pre-existing link to {Provider}. Refusing implicit link-on-first-use for an admin account (possible takeover). An admin must create the SSO link explicitly.",
                        claims.Username, provider.Id);
                    return null;
                }
                _logger.LogInformation(
                    "[2FA] OIDC linking pre-existing Jellyfin user '{User}' to provider {Provider} (sub={Sub})",
                    claims.Username, provider.Id, claims.Subject);
                return existing;
            }
        }

        // 3. Auto-create
        if (provider.AutoCreateUsers && !string.IsNullOrEmpty(claims.Username))
        {
            try
            {
                var u = await _userManager.CreateUserAsync(claims.Username).ConfigureAwait(false);

                // SECURITY [v2.5.5]: CreateUserAsync leaves the password hash
                // null, which makes Jellyfin's DefaultAuthenticationProvider
                // treat any submitted password (including empty) as valid for
                // this user. Anyone who learns the UPN can then sign in via
                // /Users/AuthenticateByName without ever going near the IdP.
                // Set a high-entropy random password immediately so the only
                // viable sign-in path for an OIDC-provisioned user is the
                // OIDC flow itself.
                await HardenNewUserPasswordAsync(u).ConfigureAwait(false);

                // SECURITY [v2.5.10] (issue #68, CWabbity): re-fetch the user.
                // On Jellyfin 10.11.9+ ChangePassword(Guid,…) sets the PBKDF2
                // hash on a DB-fetched User instance, NOT on this `u` reference,
                // so `u` stays stale (null hash) in memory. The caller
                // (FinalizeSignInAsync) then UpdateUserAsync's this entity to
                // reassign AuthenticationProviderId (and for picture/role sync)
                // — persisting the stale entity CLOBBERS the freshly-set hash
                // back to null, recreating the empty-password backdoor the
                // hardening exists to close. Returning the fresh entity (which
                // carries the hash) makes those later writes preserve it.
                u = _userManager.GetUserById(u.Id) ?? u;

                // [v2.5.13] (#93, Re4mstr) Seed the brand-new user's permissions and
                // preferences from a configured template user instead of Jellyfin's
                // defaults. Best-effort: a copy failure must not abort the sign-in.
                if (!string.IsNullOrWhiteSpace(provider.TemplateUserId)
                    && Guid.TryParse(provider.TemplateUserId, out var templateUserId))
                {
                    try
                    {
                        await CopyUserPolicyAsync(templateUserId, u).ConfigureAwait(false);
                        u = _userManager.GetUserById(u.Id) ?? u;
                    }
                    catch (Exception cpe)
                    {
                        _logger.LogWarning(cpe, "[2FA] OIDC template-policy copy failed for new user {User}", u.Username);
                    }
                }

                // [v2.5.14] (#100, Re4mstr) Flag the new user to set their own local
                // Jellyfin password on first sign-in, when the provider opts in. The
                // account currently has only a random hardened password (unusable for
                // 3rd-party integrations that authenticate against the Jellyfin
                // password); this lets the user choose a real one. Enforced at the
                // bridge redirect (SecurityController) — best-effort, never blocks.
                if (provider.ForcePasswordSetup)
                {
                    try
                    {
                        await _store.MutateAsync(u.Id, ud =>
                        {
                            ud.MustSetPassword = true;
                            // #134: only auto-created users receive this marker.
                            // It lets Cancel abort this creation without putting
                            // any pre-existing or admin-re-armed account at risk.
                            ud.PendingOidcUserCreation = true;
                            ud.PendingOidcProviderId = provider.Id;
                            ud.PendingOidcSubject = claims.Subject;
                        }).ConfigureAwait(false);
                        _logger.LogInformation("[2FA] OIDC new user '{Username}' flagged to set a Jellyfin password on first sign-in (#100)", claims.Username);
                    }
                    catch (Exception fpe)
                    {
                        _logger.LogWarning(fpe, "[2FA] Could not set MustSetPassword flag for new OIDC user '{Username}'", claims.Username);
                    }
                }

                _logger.LogInformation("[2FA] Auto-created Jellyfin user '{Username}' from OIDC provider {Provider} (password hardened)",
                    claims.Username, provider.Id);
                return u;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] OIDC auto-create user failed");
            }
        }

        return null;
    }

    /// <summary>
    /// Existing-account linking is a separate trust decision from account
    /// creation. AutoCreateUsers continues to imply it for upgrade
    /// compatibility; installations that prohibit provisioning can opt into
    /// only the narrower exact-username link path.
    /// </summary>
    internal static bool AllowsExistingUsernameLink(OidcProvider provider)
        => provider.AutoCreateUsers || provider.LinkExistingUsersByUsername;

    internal static bool HasConflictingProviderLink(
        UserTwoFactorData? data,
        string providerId,
        string subject)
        => data?.SsoLinks.Any(link =>
            string.Equals(link.ProviderId, providerId, StringComparison.Ordinal)
            && !string.Equals(link.Subject, subject, StringComparison.Ordinal)) == true;

    /// <summary>Set a 256-bit random password on a freshly-created OIDC user
    /// so the account is never in the "no stored hash" state that Jellyfin's
    /// default auth provider treats as "empty password matches". The password
    /// itself is never persisted by us and never returned to the IdP or the
    /// user — only Jellyfin's PBKDF2 hash of it ends up in the user store. The
    /// user signs in via OIDC going forward; if local password sign-in is
    /// ever needed for this account, an admin must explicitly reset.</summary>
    private async Task HardenNewUserPasswordAsync(Jellyfin.Database.Implementations.Entities.User u)
    {
        var entropy = new byte[32];
        RandomNumberGenerator.Fill(entropy);
        var pw = Convert.ToBase64String(entropy);

        try
        {
            await _userManager.ChangePassword(u.Id, pw).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // If hardening fails, we must NOT leave a vulnerable user behind.
            // Best effort: delete the just-created user so the OIDC flow
            // surfaces a clean error and the next attempt re-runs cleanly.
            _logger.LogError(ex, "[2FA] CRITICAL: failed to harden newly-created OIDC user {UserId} ({Username}) — deleting the account to avoid an empty-password backdoor. Admin should investigate.",
                u.Id, u.Username);
            try
            {
                await _userManager.DeleteUserAsync(u.Id).ConfigureAwait(false);
            }
            catch (Exception delEx)
            {
                // SECURITY [v2.5.6] (F5-A3): if BOTH ChangePassword AND
                // DeleteUserAsync fail, the prior code left a ghost user
                // with null password hash — exploitable via the empty-
                // password path on installations where BlockEmptyPasswordLogin
                // is off (default). Last-ditch attempt: try ChangePassword
                // ONE more time with a fresh random password before
                // giving up. Even an unencrypted retry beats leaving
                // the null-hash backdoor open.
                _logger.LogCritical(delEx, "[2FA] CRITICAL: also failed to delete unhardened user {UserId} ({Username}) — attempting last-ditch password set as fallback before giving up.",
                    u.Id, u.Username);
                try
                {
                    var fallbackEntropy = new byte[32];
                    RandomNumberGenerator.Fill(fallbackEntropy);
                    await _userManager.ChangePassword(u.Id, Convert.ToBase64String(fallbackEntropy)).ConfigureAwait(false);
                    _logger.LogWarning("[2FA] Last-ditch password set succeeded for user {UserId} after hardening + deletion failures. Account is no longer null-hash-vulnerable but may be otherwise broken — admin should review.",
                        u.Id);
                }
                catch (Exception lastEx)
                {
                    _logger.LogCritical(lastEx, "[2FA] CRITICAL: last-ditch password set ALSO failed for user {UserId} ({Username}). MANUAL ADMIN ACTION REQUIRED: delete user or set a password on it immediately to close the empty-password backdoor.",
                        u.Id, u.Username);
                }
            }
            throw;
        }
    }

    private record ClaimsBundle(
        string Subject,
        string Email,
        bool EmailVerified,
        string Username,
        string[] Groups,
        string[] Amr,
        string Picture);

    /// <summary>[v2.5.21] (#142, jmbenevise) Turn an id_token validation failure
    /// into a message the admin can act on.
    ///
    /// Every verification failure used to collapse into the single opaque string
    /// "Sign-in token could not be verified.", which told nobody anything — #142
    /// and #98 both sat open for weeks because the reporter had no way to tell an
    /// expired IdP certificate from a client-ID typo. The raw
    /// Microsoft.IdentityModel message must NOT be echoed to the browser (it
    /// fingerprints the library version, the configured issuer and the JWK
    /// matching logic — that was finding N-A9), so we match on the stable IDX
    /// code and return CONFIGURATION ADVICE only. No issuer, no key material, no
    /// library internals cross the boundary. Same precedent as the v2.5.11
    /// no-account-match / not-in-group messages.
    ///
    /// Returns null when the failure isn't one we recognise, so the caller keeps
    /// its generic fallback. The full message is always logged server-side.</summary>
    internal static string? DescribeVerificationFailure(string? error)
    {
        if (string.IsNullOrEmpty(error)) return null;

        // Signing key mismatch. Overwhelmingly a rotated/changed signing
        // certificate at the IdP, or a discovery URL pointing at a different
        // realm/application than the one that issued the token.
        if (error.Contains("IDX10500", StringComparison.Ordinal)
            || error.Contains("IDX10501", StringComparison.Ordinal)
            || error.Contains("IDX10503", StringComparison.Ordinal)
            || error.Contains("IDX10511", StringComparison.Ordinal))
        {
            return "The identity provider's signing key doesn't match the keys it publishes. "
                + "If you changed or rotated the signing certificate, restart Jellyfin so the key cache refreshes, "
                + "then try again.";
        }

        // X509 signing certificate expired. Should no longer reach us now that
        // ValidateIssuerSigningKey is off, but an IdP can also surface this via
        // its own metadata, so keep the mapping.
        if (error.Contains("IDX10249", StringComparison.Ordinal))
        {
            return "The identity provider's signing certificate has expired. Renew it at your identity provider "
                + "(in authentik: System → Certificates), then try again.";
        }

        // Audience mismatch — the token's `aud` isn't our configured Client ID.
        if (error.Contains("IDX10214", StringComparison.Ordinal))
        {
            return "The sign-in token was issued for a different application. "
                + "Check that the Client ID in this provider matches the one at your identity provider.";
        }

        // Issuer mismatch — usually a discovery URL for the wrong realm/app.
        if (error.Contains("IDX10205", StringComparison.Ordinal))
        {
            return "The sign-in token came from a different issuer than the discovery URL advertises. "
                + "Check the provider's discovery / issuer URL.";
        }

        // Lifetime problems — nearly always server clock drift.
        if (error.Contains("IDX10223", StringComparison.Ordinal)
            || error.Contains("IDX10225", StringComparison.Ordinal)
            || error.Contains("IDX10222", StringComparison.Ordinal)
            || error.Contains("is older than", StringComparison.Ordinal)
            || error.Contains("is in the future", StringComparison.Ordinal))
        {
            return "The sign-in token was rejected as expired or not yet valid. "
                + "This is almost always clock drift — check that the Jellyfin server and the identity provider "
                + "both have accurate time (NTP).";
        }

        // Algorithm not in our asymmetric allowlist. Most often an IdP provider
        // configured with no signing key at all, which makes it fall back to
        // HMAC (HS256) using the client secret.
        if (error.Contains("is not permitted", StringComparison.Ordinal)
            || error.Contains("IDX10517", StringComparison.Ordinal)
            || error.Contains("IDX10518", StringComparison.Ordinal))
        {
            return "The identity provider signed the token with an algorithm this plugin doesn't accept. "
                + "Select an RSA signing key/certificate on the provider (RS256) — in authentik this is the "
                + "provider's \"Signing Key\" field — then try again.";
        }

        if (error.Contains("Nonce mismatch", StringComparison.Ordinal))
        {
            return "Your sign-in session didn't match. Start the sign-in again from the login page "
                + "(don't reuse an old or bookmarked callback URL).";
        }

        return null;
    }

    private async Task<ClaimsBundle> VerifyIdTokenAsync(OidcProvider provider, Discovery disc, string idToken, string? expectedNonce)
    {
        // SEC-M1: peek the unverified header to extract `kid`, then ask the
        // JWKs cache for a fresh fetch if that kid isn't already cached.
        // ValidateToken below still does full crypto verification — the kid
        // is only used as a cache-miss hint, never as authority.
        string? requiredKid = null;
        try
        {
            var peekHandler = new JwtSecurityTokenHandler();
            if (peekHandler.CanReadToken(idToken))
            {
                var unverified = peekHandler.ReadJwtToken(idToken);
                requiredKid = unverified.Header.Kid;
            }
        }
        catch { /* malformed — ValidateToken below will reject */ }

        var jwks = await GetJwksAsync(provider, disc, requiredKid).ConfigureAwait(false);

        // SECURITY [v2.5.5]: explicit asymmetric-algorithm allowlist closes
        // the RS256→HS256 algorithm-confusion attack class. Without an
        // explicit list, Microsoft.IdentityModel.Tokens accepts any algorithm
        // the token header declares as long as a matching key resolves —
        // including HMAC variants where an attacker submits a token signed
        // with the IdP's RSA *public* key as the HMAC secret. With this list,
        // a token whose header says `alg: HS256` or `alg: none` is rejected
        // before any signing-key lookup happens.
        //
        // Allowlist covers every algorithm an OpenID-conformant IdP would
        // realistically issue (RFC 7518 §3 asymmetric set, no HS*, no none).
        // Reject pre-validation when the unverified header asserts an
        // algorithm outside the allowlist, so we don't even feed unsigned
        // / HMAC tokens to ValidateToken in the first place.
        var allowedAlgs = new[]
        {
            SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
            SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
            SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        };
        try
        {
            var peekHandler = new JwtSecurityTokenHandler();
            if (peekHandler.CanReadToken(idToken))
            {
                var unverified = peekHandler.ReadJwtToken(idToken);
                var declaredAlg = unverified.Header.Alg ?? string.Empty;
                if (!allowedAlgs.Contains(declaredAlg, StringComparer.Ordinal))
                {
                    _logger.LogWarning("[2FA] OIDC token rejected: disallowed alg '{Alg}' from provider {Provider}",
                        declaredAlg, provider.Id);
                    throw new SecurityTokenInvalidAlgorithmException(
                        $"Algorithm '{declaredAlg}' is not permitted. Only RS*, ES*, PS* are accepted.");
                }
            }
        }
        catch (SecurityTokenException)
        {
            throw;
        }
        catch (Exception)
        {
            // malformed token — let ValidateToken below produce the canonical error
        }

        var handler = new JwtSecurityTokenHandler();
        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = disc.Issuer,
            ValidateIssuer = true,
            ValidAudience = provider.ClientId,
            ValidateAudience = true,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            // [v2.5.21] (#142, jmbenevise; #98, HumnResources) Do NOT validate
            // the signing KEY's own X509 certificate lifetime.
            //
            // This flag does not control signature verification — that is
            // ValidateSignature/RequireSignedTokens, both still on, and the
            // token is still cryptographically verified against the JWKS below.
            // All ValidateIssuerSigningKey adds is
            // Validators.ValidateIssuerSecurityKey, which for an X509SecurityKey
            // rejects the key when the embedded certificate's NotAfter has
            // passed (IDX10249).
            //
            // authentik ships a self-signed signing certificate that expires
            // after one year and does not auto-rotate it. Once it lapses, every
            // sign-in died with "Sign-in token could not be verified" even
            // though the signature was perfectly valid and the JWKS was fetched
            // over TLS from the issuer's own discovery-advertised endpoint —
            // which is the actual trust anchor here, not the certificate's
            // validity window. The old SSO-Auth plugin worked against the same
            // IdP for exactly this reason. Dropping the check removes a
            // false-negative outage and costs no real security: an attacker
            // still cannot produce a token that verifies against the IdP's
            // published keys.
            ValidateIssuerSigningKey = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
            ValidAlgorithms = allowedAlgs,
        };
        handler.ValidateToken(idToken, validationParams, out var validated);
        var jwt = (JwtSecurityToken)validated;

        // SECURITY [v2.5.6] (A7): explicit `iat` validation in addition to
        // the framework's `exp` check. ValidateLifetime checks exp + nbf
        // but NOT iat — a very long-lived id_token with a far-past iat
        // would still pass under the lifetime check alone. Reject tokens
        // issued more than 10 minutes ago to bound the token-age window
        // independently of exp. Especially relevant on the token-exchange
        // path (native clients), where the IdP-issued token may carry a
        // much longer exp than browser-flow tokens.
        var iatClaim = jwt.Claims.FirstOrDefault(c => c.Type == "iat")?.Value;
        if (long.TryParse(iatClaim, out var iatUnix))
        {
            var iat = DateTimeOffset.FromUnixTimeSeconds(iatUnix).UtcDateTime;
            var maxAge = TimeSpan.FromMinutes(10);
            var skew = TimeSpan.FromMinutes(2);
            if (iat > DateTime.UtcNow + skew)
            {
                throw new SecurityTokenInvalidLifetimeException(
                    $"id_token iat ({iat:O}) is in the future beyond clock skew tolerance.");
            }
            if (iat < DateTime.UtcNow - maxAge - skew)
            {
                throw new SecurityTokenInvalidLifetimeException(
                    $"id_token iat ({iat:O}) is older than {maxAge.TotalMinutes} minutes.");
            }
        }

        // Nonce check — protects against replayed callbacks in the
        // browser-redirect flow. v2.5.1: skipped when expectedNonce is null,
        // because the Token Exchange path doesn't drive a redirect — the
        // native client ran its own OIDC flow against the IdP with its own
        // nonce, so we have nothing to compare against. The other id_token
        // protections (signature, issuer, audience=our.ClientId, expiry,
        // ClockSkew) still apply on every path.
        if (expectedNonce is not null)
        {
            var nonceClaim = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
            if (nonceClaim != expectedNonce)
            {
                throw new SecurityTokenException("Nonce mismatch");
            }
        }

        var sub = jwt.Subject;
        // [v2.5.11] (#70) honor the provider's configured email claim name,
        // falling back to the standard OIDC `email` claim.
        var emailClaimName = string.IsNullOrWhiteSpace(provider.EmailClaim) ? "email" : provider.EmailClaim;
        var email = jwt.Claims.FirstOrDefault(c => c.Type == emailClaimName)?.Value
            ?? jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value ?? string.Empty;
        // [v2.5.17] (#95, chrisbehectik) A JSON boolean `email_verified: true` in
        // an id_token is surfaced by the JWT handler as the C# string "True"
        // (capital T), NOT "true" — so the old exact "== true" check read Google
        // (and others) as UNVERIFIED, skipping the whole email-match step and
        // producing "no email account match". Compare case-insensitively.
        var emailVerified = string.Equals(
            jwt.Claims.FirstOrDefault(c => c.Type == "email_verified")?.Value,
            "true", StringComparison.OrdinalIgnoreCase);
        var username = jwt.Claims.FirstOrDefault(c => c.Type == provider.UsernameClaim)?.Value
            ?? jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
            ?? (email.Contains('@') ? email.Split('@')[0] : email);

        // Groups can come as "groups" array or comma-separated string. Roles too.
        var groupList = jwt.Claims
            .Where(c => c.Type == "groups" || c.Type == "roles")
            .SelectMany(c => c.Value.Contains(',') ? c.Value.Split(',') : new[] { c.Value })
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();
        // [v2.5.17] (#95, BoBeR182) Keycloak nests roles under realm_access.roles
        // and resource_access.{client}.roles rather than a flat "groups"/"roles"
        // claim, so group->admin / group->library mapping silently found nothing.
        // Read those too. (In Keycloak, request the built-in `roles` scope — NOT
        // `groups`, which isn't a valid Keycloak scope — to have these emitted.)
        AddNestedRealmRoles(jwt.Claims, groupList);
        var groups = groupList.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        var amr = jwt.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToArray();

        // [v2.5.10] (#66) avatar URL. Honor the provider's configured claim
        // name, falling back to the standard OIDC `picture` claim.
        var pictureClaimName = string.IsNullOrWhiteSpace(provider.PictureClaim) ? "picture" : provider.PictureClaim;
        var picture = jwt.Claims.FirstOrDefault(c => c.Type == pictureClaimName)?.Value
            ?? jwt.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
            ?? string.Empty;

        return new ClaimsBundle(sub, email, emailVerified, username, groups, amr, picture);
    }

    // Issue #29: fetch /userinfo and extract groups/email/username claims.
    // Called from CompleteAsync to supplement id_token claims for IdPs that
    // (by default) emit some or all of these only at /userinfo — Authelia,
    // Keycloak, Authentik. Returns an empty bundle on any failure; userinfo
    // is best-effort and must never block sign-in for a verified id_token.
    private async Task<UserInfoExtract> FetchUserInfoClaimsAsync(string endpoint, string accessToken, string emailClaimName = "email")
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, endpoint);
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using var resp = await _http.SendAsync(req).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            _logger.LogDebug("[2FA] OIDC /userinfo returned {Status}", resp.StatusCode);
            return UserInfoExtract.Empty;
        }
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(false);
        return ExtractClaimsFromUserInfo(json, emailClaimName);
    }

    internal record UserInfoExtract(string[] Groups, string Email, bool EmailVerified, string Username, string Picture)
    {
        public static UserInfoExtract Empty { get; } = new(Array.Empty<string>(), string.Empty, false, string.Empty, string.Empty);
    }

    /// <summary>Extract groups+roles+email+username claims from a userinfo
    /// JSON document. Handles both JSON-array and comma-separated-string
    /// representations for groups. Internal for direct testing via
    /// InternalsVisibleTo.</summary>
    // [v2.5.17] (#95, BoBeR182) Keycloak nests roles as realm_access={"roles":[…]}
    // and resource_access={"client":{"roles":[…]}}. In a raw JWT the whole object
    // is the claim's Value (JSON text); parse defensively and skip non-JSON.
    private static void AddNestedRealmRoles(IEnumerable<System.Security.Claims.Claim> claims, List<string> into)
    {
        foreach (var c in claims)
        {
            if (c.Type != "realm_access" && c.Type != "resource_access") continue;
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(c.Value);
                AddRolesFromAccessObject(c.Type, doc.RootElement, into);
            }
            catch (System.Text.Json.JsonException)
            {
                // Not JSON (some IdPs flatten it) — ignore.
            }
        }
    }

    // Same, from a parsed userinfo/JSON object carrying realm_access/resource_access.
    private static void AddNestedRealmRolesFromJson(JsonElement obj, List<string> into)
    {
        if (obj.ValueKind != JsonValueKind.Object) return;
        if (obj.TryGetProperty("realm_access", out var ra)) AddRolesFromAccessObject("realm_access", ra, into);
        if (obj.TryGetProperty("resource_access", out var resa)) AddRolesFromAccessObject("resource_access", resa, into);
    }

    private static void AddRolesFromAccessObject(string kind, JsonElement el, List<string> into)
    {
        if (el.ValueKind != JsonValueKind.Object) return;
        if (kind == "realm_access")
        {
            if (el.TryGetProperty("roles", out var rr)) AddStringArray(rr, into);
        }
        else
        {
            // resource_access: { "<client>": { "roles": [ … ] }, … }
            foreach (var client in el.EnumerateObject())
            {
                if (client.Value.ValueKind == JsonValueKind.Object
                    && client.Value.TryGetProperty("roles", out var cr))
                {
                    AddStringArray(cr, into);
                }
            }
        }
    }

    private static void AddStringArray(JsonElement arr, List<string> into)
    {
        if (arr.ValueKind != JsonValueKind.Array) return;
        foreach (var r in arr.EnumerateArray())
        {
            if (r.ValueKind == JsonValueKind.String)
            {
                var v = r.GetString();
                if (!string.IsNullOrWhiteSpace(v)) into.Add(v.Trim());
            }
        }
    }

    internal static UserInfoExtract ExtractClaimsFromUserInfo(JsonElement json, string emailClaimName = "email")
    {
        if (json.ValueKind != JsonValueKind.Object) return UserInfoExtract.Empty;

        var groups = new List<string>();
        foreach (var key in new[] { "groups", "roles" })
        {
            if (!json.TryGetProperty(key, out var prop)) continue;
            switch (prop.ValueKind)
            {
                case JsonValueKind.Array:
                    foreach (var item in prop.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var v = item.GetString();
                            if (!string.IsNullOrWhiteSpace(v)) groups.Add(v.Trim());
                        }
                    }
                    break;
                case JsonValueKind.String:
                    var raw = prop.GetString();
                    if (!string.IsNullOrWhiteSpace(raw))
                    {
                        foreach (var v in raw.Split(','))
                        {
                            var t = v.Trim();
                            if (t.Length > 0) groups.Add(t);
                        }
                    }
                    break;
            }
        }

        // [v2.5.17] (#95, BoBeR182) Keycloak nested roles at realm_access.roles /
        // resource_access.{client}.roles (userinfo can carry these when a roles
        // mapper is added). Merge them into the group list.
        AddNestedRealmRolesFromJson(json, groups);

        // [v2.5.11] (#70) honor the configured email claim name, falling back
        // to the standard OIDC `email` claim.
        var emailKey = string.IsNullOrWhiteSpace(emailClaimName) ? "email" : emailClaimName;
        string email = string.Empty;
        if (json.TryGetProperty(emailKey, out var em) && em.ValueKind == JsonValueKind.String)
        {
            email = em.GetString() ?? string.Empty;
        }
        else if (json.TryGetProperty("email", out var em2) && em2.ValueKind == JsonValueKind.String)
        {
            email = em2.GetString() ?? string.Empty;
        }

        // email_verified can be bool true, bool false, or the strings "true"/"false".
        var emailVerified = false;
        if (json.TryGetProperty("email_verified", out var ev))
        {
            emailVerified = ev.ValueKind == JsonValueKind.True
                || (ev.ValueKind == JsonValueKind.String
                    && string.Equals(ev.GetString(), "true", StringComparison.OrdinalIgnoreCase));
        }

        // preferred_username is the standard OIDC claim; fall back to "name"
        // if absent. The provider's UsernameClaim setting (handled in
        // VerifyIdTokenAsync) wins for the id_token; here we just need ANY
        // sensible username so auto-create has a label if it fires.
        var username = string.Empty;
        if (json.TryGetProperty("preferred_username", out var pu) && pu.ValueKind == JsonValueKind.String)
        {
            username = pu.GetString() ?? string.Empty;
        }
        else if (json.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String)
        {
            username = n.GetString() ?? string.Empty;
        }

        // [v2.5.10] (#66) avatar URL from userinfo (standard `picture` claim).
        var picture = json.TryGetProperty("picture", out var pic) && pic.ValueKind == JsonValueKind.String
            ? pic.GetString() ?? string.Empty
            : string.Empty;

        return new UserInfoExtract(groups.ToArray(), email, emailVerified, username, picture);
    }

    // Back-compat shim — earlier test files call ExtractGroupsFromJson.
    // Keeps the test interface stable while widening internals.
    internal static string[] ExtractGroupsFromJson(JsonElement json) => ExtractClaimsFromUserInfo(json).Groups;

    private async Task<Discovery> GetDiscoveryAsync(OidcProvider provider)
    {
        if (_discoveryCache.TryGetValue(provider.Id, out var cached)
            && (DateTime.UtcNow - cached.CachedAt) < _discoveryTtl)
        {
            return cached;
        }
        // SECURITY [v2.5.5] (Finding 3): validate outbound URL is HTTPS to a
        // public host before issuing the request. Closes SSRF: an admin (or
        // an attacker who compromised the admin) could otherwise point
        // DiscoveryUrl at http://169.254.169.254/latest/meta-data (AWS IMDS)
        // or http://10.0.0.1:8080/internal-api or file:// and exfiltrate
        // those targets via the Discovery response shape.
        await EnsureSafeOutboundAsync(provider.DiscoveryUrl, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);

        var discoveryUrl = provider.DiscoveryUrl;
        var resp = await _http.GetFromJsonAsync<JsonElement>(discoveryUrl).ConfigureAwait(false);

        // [#120] Admins commonly paste the issuer / realm root (e.g. Keycloak
        // ".../realms/master") instead of the discovery document. That returns
        // valid-but-wrong JSON with no "authorization_endpoint", which used to
        // surface as a bare KeyNotFoundException in the logs. If the required
        // key is absent and the URL isn't already a well-known path, retry once
        // with the standard discovery suffix appended before giving up.
        if (NeedsStandardDiscoveryRetry(resp, discoveryUrl))
        {
            var normalized = BuildStandardDiscoveryUrl(discoveryUrl);
            await EnsureSafeOutboundAsync(normalized, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
            try
            {
                var retry = await _http.GetFromJsonAsync<JsonElement>(normalized).ConfigureAwait(false);
                if (retry.ValueKind == JsonValueKind.Object && retry.TryGetProperty("authorization_endpoint", out _))
                {
                    _logger.LogInformation(
                        "[2FA] OIDC Discovery URL for provider {Id} looked like an issuer/realm root; auto-resolved via {Url}. Update the provider's Discovery URL to the full openid-configuration path to silence this.",
                        provider.Id, normalized);
                    resp = retry;
                    discoveryUrl = normalized;
                }
            }
            catch
            {
                // Fall through to the clear, actionable error below (raised
                // against the ORIGINAL url the admin actually configured).
            }
        }

        // [#120] Validate each required endpoint with an actionable message
        // instead of letting GetProperty throw a bare KeyNotFoundException.
        var disc = new Discovery(
            RequireDiscoveryEndpoint(resp, "authorization_endpoint", discoveryUrl),
            RequireDiscoveryEndpoint(resp, "token_endpoint", discoveryUrl),
            resp.TryGetProperty("userinfo_endpoint", out var ui) ? ui.GetString() ?? "" : "",
            RequireDiscoveryEndpoint(resp, "jwks_uri", discoveryUrl),
            RequireDiscoveryEndpoint(resp, "issuer", discoveryUrl),
            DateTime.UtcNow,
            // [#134] Optional, exactly like userinfo_endpoint above: an OP that
            // omits it simply cannot do RP-initiated logout, which is not an
            // error and must not fail discovery for every other flow.
            resp.TryGetProperty("end_session_endpoint", out var es) ? es.GetString() ?? "" : "");

        // Also validate the IdP-supplied endpoint URLs from the discovery
        // response. The DiscoveryUrl could be a perfectly fine public IdP
        // (e.g. accounts.google.com/.well-known/openid-configuration) but
        // a malicious or compromised IdP could still return jwks_uri /
        // token_endpoint pointing at private IPs to pivot SSRF.
        await EnsureSafeOutboundAsync(disc.AuthorizationEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        await EnsureSafeOutboundAsync(disc.TokenEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        await EnsureSafeOutboundAsync(disc.JwksUri, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(disc.UserInfoEndpoint))
        {
            await EnsureSafeOutboundAsync(disc.UserInfoEndpoint, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        }

        _discoveryCache[provider.Id] = disc;
        return disc;
    }

    internal static bool NeedsStandardDiscoveryRetry(JsonElement document, string discoveryUrl)
        => (document.ValueKind != JsonValueKind.Object
                || !document.TryGetProperty("authorization_endpoint", out _))
            && discoveryUrl.IndexOf(".well-known", StringComparison.OrdinalIgnoreCase) < 0;

    internal static string BuildStandardDiscoveryUrl(string discoveryUrl)
        => discoveryUrl.TrimEnd('/') + "/.well-known/openid-configuration";

    internal static string RequireDiscoveryEndpoint(
        JsonElement document,
        string key,
        string discoveryUrl)
        => document.ValueKind == JsonValueKind.Object
            && document.TryGetProperty(key, out var value)
            && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrEmpty(value.GetString())
                ? value.GetString()!
                : throw new InvalidOperationException(
                    $"OpenID discovery document at '{discoveryUrl}' is missing the required '{key}' field. "
                    + "Verify the provider's Discovery URL points to the OpenID configuration document "
                    + "(it usually ends with '/.well-known/openid-configuration'), not the issuer / realm root.");

    /// <summary>SECURITY [v2.5.5] (Finding 3): refuse to fetch a URL unless
    /// it is HTTPS and resolves to a public unicast IP address. Blocks the
    /// SSRF class: private RFC1918, loopback, link-local (incl. AWS IMDS
    /// 169.254.169.254), multicast, and IPv6 equivalents. Caller is
    /// responsible for handling the OidcDiscoveryException by surfacing a
    /// useful error to the admin (the discovery cache stays unpopulated so
    /// subsequent retries will re-validate when config changes).
    /// [v2.5.7] (issue #54): callers may pass <paramref name="allowPrivate"/>
    /// = true to opt out of the HTTPS-only + public-unicast-IP checks for
    /// providers whose <c>AllowPrivateNetworks</c> is set (LAN/VPN IdPs).
    /// The URL syntax check still runs; the safety filters are skipped.</summary>
    // [v2.5.15] (#103): returns true when <paramref name="addr"/> falls within
    // any of the operator-listed CIDRs in <paramref name="additionalCidrs"/>
    // (comma-separated). Malformed entries are skipped and logged rather than
    // throwing, so a typo in one CIDR can't block all outbound calls. Returns
    // false when the list is null/empty (no change in behaviour for existing
    // providers that haven't set the field).
    private bool IsInAllowlist(IPAddress addr, string? additionalCidrs)
    {
        if (string.IsNullOrWhiteSpace(additionalCidrs)) return false;
        var ipStr = addr.IsIPv4MappedToIPv6 ? addr.MapToIPv4().ToString() : addr.ToString();
        foreach (var raw in additionalCidrs.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            // [v2.5.15] (#103): BypassEvaluator.IsIpInCidr is exception-free (it
            // returns false on unparseable input), so without this pre-check a
            // syntactically malformed entry would be skipped SILENTLY and the
            // operator would never learn their CIDR typo was ignored. Pre-validate
            // so the warning actually fires; a bad entry still can't block the
            // other (valid) entries or the outbound call.
            if (!IsSyntacticallyValidCidr(raw))
            {
                _logger.LogWarning("[2FA] SSRF allowlist: skipping malformed CIDR entry '{Cidr}'", raw);
                continue;
            }
            try
            {
                if (BypassEvaluator.IsIpInCidr(ipStr, raw)) return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] SSRF allowlist: skipping malformed CIDR entry '{Cidr}'", raw);
            }
        }
        return false;
    }

    // [v2.5.15] (#103): a CIDR entry is "ip" (bare host) or "ip/prefix". Valid
    // syntax does NOT guarantee a match (e.g. 0.0.0.0/0 is rejected by
    // IsIpInCidr by design); this only catches genuinely unparseable entries so
    // they can be logged rather than silently ignored.
    private static bool IsSyntacticallyValidCidr(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return false;
        var slash = entry.IndexOf('/');
        var ipPart = slash >= 0 ? entry[..slash] : entry;
        if (!IPAddress.TryParse(ipPart, out var ip)) return false;
        if (slash < 0) return true; // bare host address (treated as /32 or /128)
        if (!int.TryParse(entry[(slash + 1)..], out var prefix)) return false;
        var maxPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return prefix >= 0 && prefix <= maxPrefix;
    }

    private async Task EnsureSafeOutboundAsync(string urlString, bool allowPrivate = false, string? additionalAllowedCidrs = null)
    {
        if (string.IsNullOrWhiteSpace(urlString))
        {
            throw new InvalidOperationException("Outbound URL is empty.");
        }
        if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Outbound URL is malformed: {urlString}");
        }
        // [v2.5.7] (issue #54): when the provider opts into private networks,
        // skip the HTTPS-only + public-IP checks. Still require http or https
        // as the only valid OIDC transports.
        if (allowPrivate)
        {
            if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Outbound URL scheme must be http or https, got '{uri.Scheme}' for host '{uri.Host}'.");
            }
            // SECURITY [v2.5.9]: AllowPrivateNetworks exists for LAN/VPN IdPs
            // (RFC1918 / CGN / IPv6-ULA), NOT for loopback or cloud metadata.
            // Even in this mode we still refuse loopback, link-local / IMDS
            // (169.254.169.254), multicast, and the unspecified address — the
            // classic SSRF pivots. Only genuinely-private unicast is allowed.
            // [v2.5.15] (#103): an address that the operator explicitly listed
            // in AdditionalAllowedCidrs bypasses the dangerous-IP check.
            if (IPAddress.TryParse(uri.Host, out var litPriv))
            {
                if (!IsInAllowlist(litPriv, additionalAllowedCidrs))
                    EnsureNotDangerousIp(litPriv, uri.Host);
                return;
            }
            IPAddress[] privAddrs;
            try
            {
                privAddrs = await Dns.GetHostAddressesAsync(uri.Host).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Outbound URL host '{uri.Host}' did not resolve: {ex.GetType().Name}.", ex);
            }
            if (privAddrs.Length == 0)
            {
                throw new InvalidOperationException($"Outbound URL host '{uri.Host}' has no DNS records.");
            }
            foreach (var addr in privAddrs)
            {
                if (!IsInAllowlist(addr, additionalAllowedCidrs))
                    EnsureNotDangerousIp(addr, uri.Host);
            }
            return;
        }
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            // HTTPS only. OIDC IdPs in production are always HTTPS; the only
            // legitimate http:// case would be local dev, which we don't
            // serve in this plugin. Refusing http:// also closes the cleartext
            // discovery hijack class on hostile networks.
            throw new InvalidOperationException(
                $"Outbound URL must use HTTPS, got '{uri.Scheme}' for host '{uri.Host}'.");
        }
        // If the host is a literal IP, validate directly without DNS.
        // [v2.5.15] (#103): allowlisted addresses bypass EnsurePublicIp too.
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            if (!IsInAllowlist(literal, additionalAllowedCidrs))
                EnsurePublicIp(literal, uri.Host);
            return;
        }
        // Resolve all A/AAAA records and refuse if any is private. This
        // doesn't fully close DNS-rebind (the underlying HttpClient will
        // re-resolve at connect time) but it raises the bar substantially
        // and rejects the obvious mis-/mal-configurations.
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(uri.Host).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Outbound URL host '{uri.Host}' did not resolve: {ex.GetType().Name}.", ex);
        }
        if (addresses.Length == 0)
        {
            throw new InvalidOperationException($"Outbound URL host '{uri.Host}' has no DNS records.");
        }
        foreach (var addr in addresses)
        {
            if (!IsInAllowlist(addr, additionalAllowedCidrs))
                EnsurePublicIp(addr, uri.Host);
        }
    }

    private static void EnsurePublicIp(IPAddress addr, string host)
    {
        // Map IPv4-mapped-IPv6 (::ffff:10.0.0.1) down so the v4 checks apply.
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();

        if (IPAddress.IsLoopback(addr))
        {
            throw new InvalidOperationException($"Outbound URL host '{host}' resolves to loopback.");
        }

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            // RFC 1918 private
            if (b[0] == 10) Reject(host, addr, "RFC1918 10/8");
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) Reject(host, addr, "RFC1918 172.16/12");
            if (b[0] == 192 && b[1] == 168) Reject(host, addr, "RFC1918 192.168/16");
            // Link-local / AWS IMDS / Azure IMDS
            if (b[0] == 169 && b[1] == 254) Reject(host, addr, "link-local / IMDS 169.254/16");
            // CGN
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) Reject(host, addr, "CGN 100.64/10");
            // Multicast / reserved
            if (b[0] >= 224) Reject(host, addr, "multicast/reserved");
            // 0.0.0.0/8
            if (b[0] == 0) Reject(host, addr, "0.0.0.0/8");
        }
        else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // ::, ::1 already caught by IsLoopback. Reject ULA fc00::/7 and link-local fe80::/10
            var b = addr.GetAddressBytes();
            if ((b[0] & 0xfe) == 0xfc) Reject(host, addr, "IPv6 ULA fc00::/7");
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) Reject(host, addr, "IPv6 link-local fe80::/10");
            if (addr.IsIPv6Multicast) Reject(host, addr, "IPv6 multicast");
        }
    }

    private static void Reject(string host, IPAddress addr, string reason)
    {
        throw new InvalidOperationException(
            $"Outbound URL host '{host}' resolved to non-public address {addr} ({reason}). Refusing to fetch.");
    }

    /// <summary>SECURITY [v2.5.9] (audit medium): coerce an OIDC returnUrl to
    /// a safe, same-origin, site-relative path. Rejects absolute URLs
    /// (scheme://), protocol-relative ("//host"), backslash tricks, and any
    /// control characters — all of which enable open redirect. Anything
    /// suspect collapses to "/".</summary>
    private static string SanitizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)) return "/";
        var u = returnUrl.Trim();
        if (!u.StartsWith('/')) return "/";
        if (u.StartsWith("//", StringComparison.Ordinal)) return "/";       // protocol-relative
        if (u.Contains('\\', StringComparison.Ordinal)) return "/";          // backslash → //evil
        if (u.Contains("://", StringComparison.Ordinal)) return "/";         // embedded scheme
        foreach (var ch in u)
        {
            if (char.IsControl(ch)) return "/";                              // CR/LF/etc.
        }
        return u;
    }

    /// <summary>SECURITY [v2.5.9]: the subset of <see cref="EnsurePublicIp"/>
    /// applied when a provider has AllowPrivateNetworks enabled. PERMITS
    /// RFC1918 / CGN / IPv6-ULA private unicast (the LAN/VPN IdP the flag
    /// exists for) but STILL REFUSES loopback, link-local / cloud-metadata
    /// (169.254/16 incl. 169.254.169.254), multicast and the unspecified
    /// address — none of which is ever a legitimate IdP, all of which are
    /// classic SSRF pivots.</summary>
    private static void EnsureNotDangerousIp(IPAddress addr, string host)
    {
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();

        if (IPAddress.IsLoopback(addr))
        {
            throw new InvalidOperationException($"Outbound URL host '{host}' resolves to loopback.");
        }

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            if (b[0] == 169 && b[1] == 254) Reject(host, addr, "link-local / IMDS 169.254/16");
            if (b[0] >= 224) Reject(host, addr, "multicast/reserved");
            if (b[0] == 0) Reject(host, addr, "0.0.0.0/8");
            // RFC1918 10/8, 172.16/12, 192.168/16 and CGN 100.64/10 are
            // intentionally ALLOWED here — that's what the flag is for.
        }
        else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = addr.GetAddressBytes();
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) Reject(host, addr, "IPv6 link-local fe80::/10");
            if (addr.IsIPv6Multicast) Reject(host, addr, "IPv6 multicast");
            if (addr.Equals(IPAddress.IPv6Any)) Reject(host, addr, "IPv6 unspecified ::");
            // IPv6 ULA fc00::/7 is intentionally ALLOWED (private unicast).
        }
    }

    private async Task<JsonWebKeySet> GetJwksAsync(OidcProvider provider, Discovery disc, string? requiredKid = null)
    {
        // SEC-M1: cached entry valid only if (a) within TTL AND (b) the
        // required kid (if any) is present. If the IdP rotated keys and
        // issued a token signed with a kid we don't know, force a refresh
        // — without this, post-rotation tokens fail validation forever
        // until a manual InvalidateCache call or process restart.
        if (_jwksCache.TryGetValue(provider.Id, out var cached)
            && (DateTime.UtcNow - cached.FetchedAt) < _jwksTtl
            && (requiredKid is null || HasKid(cached.Keys, requiredKid)))
        {
            return cached.Keys;
        }
        // SECURITY [v2.5.5] (Finding 3): re-validate even though Discovery
        // also validated — DNS could have changed between cache populate
        // and now, and the cache TTL on Discovery (1h) is independent.
        await EnsureSafeOutboundAsync(disc.JwksUri, provider.AllowPrivateNetworks, provider.AdditionalAllowedCidrs).ConfigureAwait(false);
        var json = await _http.GetStringAsync(disc.JwksUri).ConfigureAwait(false);
        var jwks = new JsonWebKeySet(json);
        _jwksCache[provider.Id] = new JwksCacheEntry(jwks, DateTime.UtcNow);
        return jwks;
    }

    private static bool HasKid(JsonWebKeySet jwks, string kid)
    {
        foreach (var k in jwks.Keys)
        {
            if (string.Equals(k.Kid, kid, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    public void InvalidateCache(string providerId)
    {
        _discoveryCache.TryRemove(providerId, out _);
        _jwksCache.TryRemove(providerId, out _);
    }

    private void SweepPending()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _pendingFlows)
        {
            if (kv.Value.ExpiresAt <= now) _pendingFlows.TryRemove(kv.Key, out _);
        }
        // [v2.5.7] OIDC step-up: matching cleanup for the step-up flow map.
        foreach (var kv in _pendingUserStepUps)
        {
            if (kv.Value.ExpiresAt <= now) _pendingUserStepUps.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _pendingUserLinks)
        {
            if (kv.Value.ExpiresAt <= now) _pendingUserLinks.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _pendingOnboardingValidations)
        {
            if (kv.Value.ExpiresAt <= now) _pendingOnboardingValidations.TryRemove(kv.Key, out _);
        }
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

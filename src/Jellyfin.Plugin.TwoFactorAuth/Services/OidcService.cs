using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using MediaBrowser.Controller.Library;
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
public class OidcService
{
    private record Discovery(
        string AuthorizationEndpoint,
        string TokenEndpoint,
        string UserInfoEndpoint,
        string JwksUri,
        string Issuer,
        DateTime CachedAt);

    private record PendingFlow(
        string ProviderId,
        string CodeVerifier,
        string Nonce,
        string ReturnUrl,
        DateTime ExpiresAt);

    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly ILogger<OidcService> _logger;
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };

    // SEC-M1: JWKs are cached with the same 1h TTL as discovery. IdPs rotate
    // signing keys (Google ~every few weeks); without a TTL the cache could
    // (a) reject valid tokens after rotation since the new kid isn't present,
    // or (b) keep trusting a retired key past its lifetime. GetJwksAsync also
    // forces a refresh when the requested kid is missing from the cache.
    private record JwksCacheEntry(JsonWebKeySet Keys, DateTime FetchedAt);

    private static readonly TimeSpan _jwksTtl = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<string, Discovery> _discoveryCache = new();
    private readonly ConcurrentDictionary<string, JwksCacheEntry> _jwksCache = new();
    private readonly ConcurrentDictionary<string, PendingFlow> _pendingFlows = new();
    private readonly Timer _cleanupTimer;

    public OidcService(UserTwoFactorStore store, IUserManager userManager, ILogger<OidcService> logger)
    {
        _store = store;
        _userManager = userManager;
        _logger = logger;
        _cleanupTimer = new Timer(_ => SweepPending(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    /// <summary>Build the full /authorize redirect URL the user's browser is
    /// pointed at to start sign-in. Returns the URL + the state nonce the
    /// callback will echo back.</summary>
    public async Task<(string AuthUrl, string State)> BeginAsync(
        OidcProvider provider, string redirectUri, string returnUrl)
    {
        var disc = await GetDiscoveryAsync(provider).ConfigureAwait(false);

        // PKCE: random 43-char verifier, S256 challenge.
        var codeVerifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

        var state = Base64Url(RandomNumberGenerator.GetBytes(24));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(24));

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

        // Exchange code for tokens.
        var tokenResp = await _http.PostAsync(disc.TokenEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = provider.ClientId,
                ["client_secret"] = provider.ClientSecret,
                ["code_verifier"] = pending.CodeVerifier,
            })).ConfigureAwait(false);

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

        // Route this user's auth through our provider so bridge tokens work.
        // Our Authenticate delegates to the default provider for normal
        // passwords, so flipping this is additive — password login still
        // works identically.
        try
        {
            var ourProviderId = typeof(TwoFactorAuthProvider).FullName!;
            if (!string.Equals(matchedUser.AuthenticationProviderId, ourProviderId, StringComparison.Ordinal))
            {
                matchedUser.AuthenticationProviderId = ourProviderId;
                await _userManager.UpdateUserAsync(matchedUser).ConfigureAwait(false);
                _logger.LogInformation("[2FA] Reassigned {User} AuthenticationProviderId to TwoFactorAuthProvider for OIDC bridge", matchedUser.Username);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Could not reassign AuthenticationProviderId for {User}", matchedUser.Username);
        }

        return new CallbackResult(true, null, matchedUser.Id, matchedUser.Username, pending.ReturnUrl, link);
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
                var match = config.UserEmails.FirstOrDefault(e =>
                    string.Equals(e.Email, claims.Email, StringComparison.OrdinalIgnoreCase));
                if (match is not null && Guid.TryParse(match.UserId, out var uid))
                {
                    var u = _userManager.GetUserById(uid);
                    if (u is not null) return u;
                }
            }
        }

        // 3. Auto-create
        if (provider.AutoCreateUsers && !string.IsNullOrEmpty(claims.Username))
        {
            try
            {
                var u = await _userManager.CreateUserAsync(claims.Username).ConfigureAwait(false);
                _logger.LogInformation("[2FA] Auto-created Jellyfin user '{Username}' from OIDC provider {Provider}",
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

    private record ClaimsBundle(
        string Subject,
        string Email,
        bool EmailVerified,
        string Username,
        string[] Groups,
        string[] Amr);

    private async Task<ClaimsBundle> VerifyIdTokenAsync(OidcProvider provider, Discovery disc, string idToken, string expectedNonce)
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
        var handler = new JwtSecurityTokenHandler();
        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = disc.Issuer,
            ValidateIssuer = true,
            ValidAudience = provider.ClientId,
            ValidateAudience = true,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
        };
        handler.ValidateToken(idToken, validationParams, out var validated);
        var jwt = (JwtSecurityToken)validated;

        // Nonce check — protects against replayed callbacks.
        var nonceClaim = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
        if (nonceClaim != expectedNonce)
        {
            throw new SecurityTokenException("Nonce mismatch");
        }

        var sub = jwt.Subject;
        var email = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value ?? string.Empty;
        var emailVerified = jwt.Claims.FirstOrDefault(c => c.Type == "email_verified")?.Value == "true";
        var username = jwt.Claims.FirstOrDefault(c => c.Type == provider.UsernameClaim)?.Value
            ?? jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
            ?? (email.Contains('@') ? email.Split('@')[0] : email);

        // Groups can come as "groups" array or comma-separated string. Roles too.
        var groups = jwt.Claims
            .Where(c => c.Type == "groups" || c.Type == "roles")
            .SelectMany(c => c.Value.Contains(',') ? c.Value.Split(',') : new[] { c.Value })
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToArray();

        var amr = jwt.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToArray();

        return new ClaimsBundle(sub, email, emailVerified, username, groups, amr);
    }

    private async Task<Discovery> GetDiscoveryAsync(OidcProvider provider)
    {
        if (_discoveryCache.TryGetValue(provider.Id, out var cached)
            && (DateTime.UtcNow - cached.CachedAt) < TimeSpan.FromHours(1))
        {
            return cached;
        }
        var resp = await _http.GetFromJsonAsync<JsonElement>(provider.DiscoveryUrl).ConfigureAwait(false);
        var disc = new Discovery(
            resp.GetProperty("authorization_endpoint").GetString()!,
            resp.GetProperty("token_endpoint").GetString()!,
            resp.TryGetProperty("userinfo_endpoint", out var ui) ? ui.GetString() ?? "" : "",
            resp.GetProperty("jwks_uri").GetString()!,
            resp.GetProperty("issuer").GetString()!,
            DateTime.UtcNow);
        _discoveryCache[provider.Id] = disc;
        return disc;
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
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

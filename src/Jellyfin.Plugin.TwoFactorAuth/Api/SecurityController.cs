using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Api;

/// <summary>v2.0 endpoints — OIDC providers, IP bans, per-user IP allowlist.
/// Kept in a separate controller so the legacy /TwoFactorAuth surface stays
/// untouched. Routes still live under /TwoFactorAuth/* so the same permissions
/// model and base URL apply.</summary>
[ApiController]
[Route("TwoFactorAuth")]
[Produces(MediaTypeNames.Application.Json)]
public class SecurityController : ControllerBase
{
    private readonly OidcService _oidc;
    private readonly OidcLoginTokenStore _oidcBridge;
    private readonly IpBanService _bans;
    private readonly IpAllowlistService _allowlist;
    private readonly UserTwoFactorStore _store;
    private readonly ILogger<SecurityController> _logger;

    public SecurityController(
        OidcService oidc,
        OidcLoginTokenStore oidcBridge,
        IpBanService bans,
        IpAllowlistService allowlist,
        UserTwoFactorStore store,
        ILogger<SecurityController> logger)
    {
        _oidc = oidc;
        _oidcBridge = oidcBridge;
        _bans = bans;
        _allowlist = allowlist;
        _store = store;
        _logger = logger;
    }

    private Guid GetCurrentUserId()
    {
        var claim = User.FindFirst("Jellyfin-UserId");
        if (claim != null && Guid.TryParse(claim.Value, out var userId)) return userId;
        throw new UnauthorizedAccessException();
    }

    // =========================================================================
    // OIDC PROVIDER CONFIG (admin)
    // =========================================================================

    public class OidcProviderUpsertRequest
    {
        [Required] public string DisplayName { get; set; } = string.Empty;
        public string Preset { get; set; } = "generic";
        public string DiscoveryUrl { get; set; } = string.Empty;
        [Required] public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string Scopes { get; set; } = "openid profile email";
        public string AcrValues { get; set; } = string.Empty;
        public string UsernameClaim { get; set; } = "preferred_username";
        public string AllowedGroups { get; set; } = string.Empty;
        public string AdminGroups { get; set; } = string.Empty;
        public bool AutoCreateUsers { get; set; }
        public bool RequireIdpMfa { get; set; }
        public bool BypassPluginTwoFa { get; set; } = true;
        public bool Enabled { get; set; } = true;
    }

    [HttpGet("Oidc/Presets")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult<IReadOnlyList<OidcProviderPresets.Preset>> GetPresets()
        => Ok(OidcProviderPresets.All);

    /// <summary>Buttons-only listing for the un-authenticated login page.
    /// Returns ONLY id + display name + enabled flag for enabled providers
    /// — never client_id, secret, discovery URL, group lists, or any other
    /// admin-only field. The login-page inject.js reads this to render
    /// "Sign in with X" buttons.</summary>
    [HttpGet("Oidc/PublicProviders")]
    [AllowAnonymous]
    public ActionResult<IReadOnlyList<object>> GetPublicProviders()
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null) return Ok(Array.Empty<object>());
        var safe = config.OidcProviders.Where(p => p.Enabled).Select(p => new
        {
            id = p.Id,
            displayName = p.DisplayName,
            enabled = true,
        }).ToList<object>();
        return Ok(safe);
    }

    [HttpGet("Oidc/Providers")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult<IReadOnlyList<object>> ListProviders()
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null) return Ok(Array.Empty<object>());
        // Never echo client_secret back to the admin UI — show only that it's set.
        // Explicit lowercase keys (shorthand `p.Id` emits PascalCase which
        // Jellyfin's serializer doesn't camelCase for anonymous objects, so
        // the admin JS — which reads p.id/p.displayName — got empty strings).
        var safe = config.OidcProviders.Select(p => new
        {
            id = p.Id,
            displayName = p.DisplayName,
            preset = p.Preset,
            discoveryUrl = p.DiscoveryUrl,
            clientId = p.ClientId,
            clientSecretSet = !string.IsNullOrEmpty(p.ClientSecret),
            scopes = p.Scopes,
            acrValues = p.AcrValues,
            usernameClaim = p.UsernameClaim,
            allowedGroups = p.AllowedGroups,
            adminGroups = p.AdminGroups,
            autoCreateUsers = p.AutoCreateUsers,
            requireIdpMfa = p.RequireIdpMfa,
            bypassPluginTwoFa = p.BypassPluginTwoFa,
            enabled = p.Enabled,
            createdAt = p.CreatedAt,
        }).ToList<object>();
        return Ok(safe);
    }

    [HttpPost("Oidc/Providers")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult<object> CreateProvider([FromBody, Required] OidcProviderUpsertRequest req)
    {
        var plugin = Plugin.Instance ?? throw new InvalidOperationException("Plugin not initialized");
        var config = plugin.Configuration;
        var id = SlugifyId(req.DisplayName);
        if (string.IsNullOrEmpty(id)) return BadRequest(new { message = "Display name produces an empty id." });
        var counter = 1;
        var baseId = id;
        while (config.OidcProviders.Any(p => p.Id == id)) { id = $"{baseId}-{counter++}"; }

        var provider = new OidcProvider
        {
            Id = id,
            DisplayName = req.DisplayName,
            Preset = req.Preset,
            DiscoveryUrl = req.DiscoveryUrl,
            ClientId = req.ClientId,
            ClientSecret = req.ClientSecret,
            Scopes = req.Scopes,
            AcrValues = req.AcrValues,
            UsernameClaim = req.UsernameClaim,
            AllowedGroups = req.AllowedGroups,
            AdminGroups = req.AdminGroups,
            AutoCreateUsers = req.AutoCreateUsers,
            RequireIdpMfa = req.RequireIdpMfa,
            BypassPluginTwoFa = req.BypassPluginTwoFa,
            Enabled = req.Enabled,
            CreatedAt = DateTime.UtcNow,
        };
        config.OidcProviders.Add(provider);
        plugin.SaveConfiguration();
        return Ok(new { id = provider.Id, displayName = provider.DisplayName });
    }

    [HttpPut("Oidc/Providers/{id}")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult UpdateProvider([FromRoute] string id, [FromBody, Required] OidcProviderUpsertRequest req)
    {
        var plugin = Plugin.Instance ?? throw new InvalidOperationException("Plugin not initialized");
        var existing = plugin.Configuration.OidcProviders.FirstOrDefault(p => p.Id == id);
        if (existing is null) return NotFound();
        existing.DisplayName = req.DisplayName;
        existing.Preset = req.Preset;
        existing.DiscoveryUrl = req.DiscoveryUrl;
        existing.ClientId = req.ClientId;
        // Empty secret in the request means "leave existing alone" — admin UI
        // can show a placeholder rather than the real value, and PUTs without
        // the field don't accidentally clobber.
        if (!string.IsNullOrEmpty(req.ClientSecret)) existing.ClientSecret = req.ClientSecret;
        existing.Scopes = req.Scopes;
        existing.AcrValues = req.AcrValues;
        existing.UsernameClaim = req.UsernameClaim;
        existing.AllowedGroups = req.AllowedGroups;
        existing.AdminGroups = req.AdminGroups;
        existing.AutoCreateUsers = req.AutoCreateUsers;
        existing.RequireIdpMfa = req.RequireIdpMfa;
        existing.BypassPluginTwoFa = req.BypassPluginTwoFa;
        existing.Enabled = req.Enabled;
        plugin.SaveConfiguration();
        _oidc.InvalidateCache(id);
        return Ok();
    }

    [HttpDelete("Oidc/Providers/{id}")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult DeleteProvider([FromRoute] string id)
    {
        var plugin = Plugin.Instance ?? throw new InvalidOperationException("Plugin not initialized");
        var removed = plugin.Configuration.OidcProviders.RemoveAll(p => p.Id == id);
        if (removed == 0) return NotFound();
        plugin.SaveConfiguration();
        _oidc.InvalidateCache(id);
        return Ok();
    }

    // =========================================================================
    // OIDC SIGN-IN FLOW (anonymous)
    // =========================================================================

    // In-memory per-IP rate limiter for OIDC begins. Without this an
    // unauthenticated attacker can spam /Oidc/Login/<any-enabled-provider>
    // to inflate PendingFlow entries (memory) and to hammer the IdP's
    // /.well-known endpoint. 20 per 5min per source IP is well above
    // legit use (users click once and complete or abandon).
    private static readonly RateLimiter _oidcRateLimiter = new();

    [HttpGet("Oidc/Login/{providerId}")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromRoute] string providerId, [FromQuery] string? returnUrl = null)
    {
        var ip = RateLimiter.ClientKey(HttpContext);
        var rl = _oidcRateLimiter.CheckAndRecord("oidc_login:" + ip, 20, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString());
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many sign-in attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null) return NotFound(new { message = "Provider not found or disabled." });

        // returnUrl must be a same-origin relative path. Block absolute URLs,
        // protocol-relative, and anything that isn't a plain path — otherwise
        // we could get used as an open redirect.
        var safeReturn = "/web/";
        if (!string.IsNullOrEmpty(returnUrl)
            && returnUrl.StartsWith('/')
            && !returnUrl.StartsWith("//", StringComparison.Ordinal)
            && !returnUrl.Contains(':'))
        {
            safeReturn = returnUrl;
        }

        var redirectUri = BuildRedirectUri(providerId);
        try
        {
            var (authUrl, _) = await _oidc.BeginAsync(provider, redirectUri, safeReturn).ConfigureAwait(false);
            return Redirect(authUrl);
        }
        catch (Exception ex)
        {
            // Never echo exception messages — they can leak discovery URLs,
            // internal hostnames, TLS trust chain detail. Log server-side and
            // return a generic message.
            _logger.LogError(ex, "[2FA] OIDC begin failed for {Provider}", providerId);
            return StatusCode(StatusCodes.Status502BadGateway, new
            {
                message = "Failed to start OIDC sign-in — check server logs.",
            });
        }
    }

    [HttpGet("Oidc/Callback/{providerId}")]
    [AllowAnonymous]
    public async Task<IActionResult> Callback(
        [FromRoute] string providerId,
        [FromQuery] string? code,
        [FromQuery] string? state,
        [FromQuery] string? error)
    {
        _logger.LogInformation("[2FA] OIDC Callback hit: provider={Pid} codeLen={CL} stateLen={SL} error={Err}",
            providerId, code?.Length ?? 0, state?.Length ?? 0, error ?? "(none)");
        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogWarning("[2FA] OIDC provider returned error: {Err}", error);
            return Redirect(LoginErrorUrl("Provider returned: " + error));
        }
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            _logger.LogWarning("[2FA] OIDC callback missing code or state");
            return Redirect(LoginErrorUrl("Missing code or state"));
        }
        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null)
        {
            _logger.LogWarning("[2FA] OIDC provider '{Pid}' not found or disabled", providerId);
            return Redirect(LoginErrorUrl("Provider not found"));
        }

        var redirectUri = BuildRedirectUri(providerId);
        _logger.LogInformation("[2FA] OIDC token exchange redirect_uri={Uri}", redirectUri);
        var result = await _oidc.CompleteAsync(provider, code, state, redirectUri).ConfigureAwait(false);
        if (!result.Success || result.UserId is null || result.Username is null)
        {
            _logger.LogWarning("[2FA] OIDC sign-in failed: {Err}", result.Error);
            return Redirect(LoginErrorUrl(result.Error ?? "Sign-in failed"));
        }

        _logger.LogInformation("[2FA] OIDC success for user {User} ({UserId}) via {Pid}",
            result.Username, result.UserId, providerId);

        // Mint a one-shot bridge token.
        var token = _oidcBridge.Mint(result.UserId.Value, result.Username, providerId);

        // Return a self-contained bridge page that POSTs to Jellyfin's auth
        // endpoint server-side (from the browser, with a real X-Emby-Authorization
        // header), stores credentials in localStorage, then lands on /web/. This
        // avoids depending on inject.js + the SPA router preserving our hash
        // params — an earlier approach that raced the Jellyfin login init.
        //
        // SECURITY: JSON-encode the values for the JS context. HtmlEncode is
        // the wrong tool (doesn't escape `\\` / line terminators that break a
        // JS string literal). JsonSerializer.Serialize outputs a fully quoted
        // and escaped JS-safe string, including leading/trailing quotes.
        var uname = System.Text.Json.JsonSerializer.Serialize(result.Username);
        var tok = System.Text.Json.JsonSerializer.Serialize(token);
        var html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Signing in…</title>"
            + "<style>body{background:#0a0a0a;color:#e0e0e0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}"
            + ".card{background:#1a1a1a;padding:32px 40px;border-radius:8px;text-align:center;border:1px solid #2a2a2a;}"
            + ".spin{width:32px;height:32px;border:3px solid #333;border-top-color:#00a4dc;border-radius:50%;animation:s 0.8s linear infinite;margin:0 auto 16px;}"
            + "@keyframes s{to{transform:rotate(360deg)}}.err{color:#f44336;margin-top:12px;}</style></head>"
            + "<body><div class=\"card\"><div class=\"spin\"></div><div id=\"msg\">Completing sign-in…</div>"
            + "<div id=\"err\" class=\"err\"></div></div><script>"
            + "(function(){"
            + "var u=" + uname + ",t=" + tok + ";"
            + "var did=(function(){try{var x=localStorage.getItem('_deviceId2');if(!x){x=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b=>b.toString(16).padStart(2,'0')).join('');localStorage.setItem('_deviceId2',x);}return x;}catch(e){return 'bridge-'+Date.now();}})();"
            + "var auth='MediaBrowser Client=\"Jellyfin Web\", Device=\"Browser\", DeviceId=\"'+did+'\", Version=\"10.11.0\"';"
            + "fetch('/Users/AuthenticateByName',{method:'POST',headers:{'Content-Type':'application/json','X-Emby-Authorization':auth,'Authorization':auth},body:JSON.stringify({Username:u,Pw:t})})"
            + ".then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})"
            + ".then(function(res){"
            + "var server={Id:res.ServerId,Name:'Jellyfin',AccessToken:res.AccessToken,UserId:res.User.Id,Type:'Server',DateLastAccessed:Date.now(),LastConnectionMode:1,ManualAddress:window.location.origin,LocalAddress:window.location.origin};"
            + "var creds={Servers:[server]};"
            + "localStorage.setItem('jellyfin_credentials',JSON.stringify(creds));"
            + "document.getElementById('msg').textContent='Signed in as '+res.User.Name+' — redirecting…';"
            + "setTimeout(function(){window.location.href='/web/index.html';},400);"
            + "})"
            + ".catch(function(e){document.getElementById('msg').textContent='Sign-in failed.';document.getElementById('err').textContent=e.message;setTimeout(function(){window.location.href='/web/index.html#!/login.html';},3000);});"
            + "})();"
            + "</script></body></html>";
        // Stops browsers/proxies caching the bridge token in history or shared cache.
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        // CSP limits fetch/XHR/img/script to same origin so even if an injection
        // slipped past JSON encoding, it couldn't exfiltrate the bridge token.
        Response.Headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'";
        return Content(html, "text/html; charset=utf-8");
    }

    private static string LoginErrorUrl(string msg)
    {
        // Trim to prevent log pollution via long IdP-returned errors, and
        // strip control characters. The message reaches the login page fragment
        // so it's not HTML-injected (it's URL-encoded), but we still don't
        // want to echo unlimited attacker-chosen text back to browsers.
        var safe = new string(msg.Take(200).Where(c => c >= 0x20 && c != 0x7F).ToArray());
        return "/web/index.html#!/login.html?oidcError=" + Uri.EscapeDataString(safe);
    }

    private string BuildRedirectUri(string providerId)
    {
        // SECURITY: X-Forwarded-Host/Proto are ONLY trusted when the direct
        // peer is a configured trusted-proxy CIDR. Otherwise we'd accept any
        // attacker-sent host header and hand it to the IdP as redirect_uri —
        // the IdP would reject it (not a registered URI), but it lets an
        // attacker poison the flow. Fall back to Request.Host when unverified.
        var cfg = Plugin.Instance?.Configuration;
        var peer = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        var proxyTrusted = cfg is not null && cfg.TrustedProxyCidrs.Any(c => BypassEvaluator.IsIpInCidr(peer, c));

        string scheme;
        string host;
        if (proxyTrusted
            && Request.Headers.TryGetValue("X-Forwarded-Proto", out var p) && !string.IsNullOrEmpty(p)
            && Request.Headers.TryGetValue("X-Forwarded-Host", out var h) && !string.IsNullOrEmpty(h))
        {
            scheme = p.ToString().Split(',')[0].Trim();
            host = h.ToString().Split(',')[0].Trim();
        }
        else
        {
            scheme = Request.Scheme;
            host = Request.Host.ToString();
        }
        return $"{scheme}://{host}/TwoFactorAuth/Oidc/Callback/{providerId}";
    }

    // =========================================================================
    // USER SSO LINKS
    // =========================================================================

    [HttpGet("Oidc/MyLinks")]
    [Authorize]
    public async Task<ActionResult<IReadOnlyList<object>>> ListMyLinks()
    {
        var data = await _store.GetUserDataAsync(GetCurrentUserId()).ConfigureAwait(false);
        var providers = Plugin.Instance?.Configuration.OidcProviders ?? new List<OidcProvider>();
        var safe = data.SsoLinks.Select(l => new
        {
            providerId = l.ProviderId,
            providerDisplay = providers.FirstOrDefault(p => p.Id == l.ProviderId)?.DisplayName ?? l.ProviderId,
            subject = l.Subject,
            email = l.Email,
            linkedAt = l.LinkedAt,
            lastUsedAt = l.LastUsedAt,
        }).ToList<object>();
        return Ok(safe);
    }

    [HttpDelete("Oidc/MyLinks/{providerId}/{subject}")]
    [Authorize]
    public async Task<ActionResult> UnlinkMine([FromRoute] string providerId, [FromRoute] string subject)
    {
        var userId = GetCurrentUserId();
        var removed = false;
        await _store.MutateAsync(userId, ud =>
        {
            removed = ud.SsoLinks.RemoveAll(l => l.ProviderId == providerId && l.Subject == subject) > 0;
        }).ConfigureAwait(false);
        return removed ? Ok() : NotFound();
    }

    // =========================================================================
    // IP BAN MANAGEMENT (admin)
    // =========================================================================

    public class BanIpRequest
    {
        [Required] public string Ip { get; set; } = string.Empty;
        public string Note { get; set; } = string.Empty;
        public int Hours { get; set; } = 24;
    }

    [HttpGet("IpBans")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult<IReadOnlyList<IpBanEntry>> ListBans() => Ok(_bans.ListActive());

    [HttpPost("IpBans")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult<IpBanEntry> CreateBan([FromBody, Required] BanIpRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Ip))
            return BadRequest(new { message = "IP is required." });
        var entry = _bans.Ban(req.Ip.Trim(), "manual", req.Note, req.Hours);
        return Ok(entry);
    }

    [HttpDelete("IpBans/{ip}")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult DeleteBan([FromRoute] string ip)
        => _bans.Unban(ip) ? Ok() : NotFound();

    // =========================================================================
    // PER-USER IP ALLOWLIST
    // =========================================================================

    public class IpAllowlistRequest
    {
        public List<string> Cidrs { get; set; } = new();
    }

    [HttpGet("IpAllowlist")]
    [Authorize]
    public async Task<ActionResult<IReadOnlyList<string>>> GetMyAllowlist()
    {
        var data = await _store.GetUserDataAsync(GetCurrentUserId()).ConfigureAwait(false);
        return Ok(data.IpAllowlistCidrs);
    }

    [HttpPut("IpAllowlist")]
    [Authorize]
    public async Task<ActionResult> SetMyAllowlist([FromBody, Required] IpAllowlistRequest req)
    {
        // Validate each CIDR before persisting — bad input here would silently
        // never match any IP and effectively soft-lock the user out of their
        // own account, which is much worse than a 400.
        foreach (var cidr in req.Cidrs)
        {
            if (!IsValidCidr(cidr))
            {
                return BadRequest(new { message = $"Invalid CIDR: {cidr}" });
            }
        }
        await _store.MutateAsync(GetCurrentUserId(), ud =>
        {
            ud.IpAllowlistCidrs = req.Cidrs.Select(c => c.Trim()).Where(c => c.Length > 0).Distinct().ToList();
        }).ConfigureAwait(false);
        return Ok();
    }

    [HttpGet("IpAllowlist/User/{userId}")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<ActionResult<IReadOnlyList<string>>> GetUserAllowlist([FromRoute] Guid userId)
    {
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        return Ok(data.IpAllowlistCidrs);
    }

    [HttpPut("IpAllowlist/User/{userId}")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<ActionResult> SetUserAllowlist([FromRoute] Guid userId, [FromBody, Required] IpAllowlistRequest req)
    {
        foreach (var cidr in req.Cidrs)
        {
            if (!IsValidCidr(cidr))
            {
                return BadRequest(new { message = $"Invalid CIDR: {cidr}" });
            }
        }
        await _store.MutateAsync(userId, ud =>
        {
            ud.IpAllowlistCidrs = req.Cidrs.Select(c => c.Trim()).Where(c => c.Length > 0).Distinct().ToList();
        }).ConfigureAwait(false);
        return Ok();
    }

    private static bool IsValidCidr(string cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr)) return false;
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2) return false;
        if (!System.Net.IPAddress.TryParse(parts[0], out var ip)) return false;
        if (!int.TryParse(parts[1], out var prefix)) return false;
        var max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return prefix >= 0 && prefix <= max;
    }

    private static string SlugifyId(string s)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var ch in s.ToLowerInvariant())
        {
            if (ch >= 'a' && ch <= 'z') sb.Append(ch);
            else if (ch >= '0' && ch <= '9') sb.Append(ch);
            else if (ch == '-' || ch == ' ' || ch == '_') sb.Append('-');
        }
        var slug = sb.ToString().Trim('-');
        while (slug.Contains("--", StringComparison.Ordinal)) slug = slug.Replace("--", "-", StringComparison.Ordinal);
        return slug;
    }
}

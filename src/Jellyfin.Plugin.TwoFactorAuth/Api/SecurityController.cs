using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller.Library;
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
    private readonly PasskeyService _passkeys;
    private readonly PasskeyChallengeStore _passkeyChallenges;
    private readonly IUserManager _userManager;
    private readonly RateLimiter _rateLimiter;
    // SECURITY [v2.5.6] (U3): step-up service for gating destructive admin
    // mutations on OIDC provider configuration.
    private readonly StepUpService _stepUp;
    // [v2.5.7] OIDC step-up: needed to mint user step-up tokens from the
    // callback handler.
    private readonly ChallengeStore _challenges;
    private readonly ILogger<SecurityController> _logger;

    public SecurityController(
        OidcService oidc,
        OidcLoginTokenStore oidcBridge,
        IpBanService bans,
        IpAllowlistService allowlist,
        UserTwoFactorStore store,
        PasskeyService passkeys,
        PasskeyChallengeStore passkeyChallenges,
        IUserManager userManager,
        RateLimiter rateLimiter,
        StepUpService stepUp,
        ChallengeStore challenges,
        ILogger<SecurityController> logger)
    {
        _oidc = oidc;
        _oidcBridge = oidcBridge;
        _bans = bans;
        _allowlist = allowlist;
        _store = store;
        _passkeys = passkeys;
        _passkeyChallenges = passkeyChallenges;
        _userManager = userManager;
        _rateLimiter = rateLimiter;
        _stepUp = stepUp;
        _challenges = challenges;
        _logger = logger;
    }

    // SECURITY [v2.5.6] (U3): inline step-up guard mirroring the helper in
    // TwoFactorAuthController. Returns a 403 with stepUpRequired=true when
    // the current admin needs a fresh step-up before proceeding.
    private ActionResult? StepUpGuard(StepUpAction action)
    {
        if (!Guid.TryParse(User.FindFirst("Jellyfin-UserId")?.Value, out var adminId))
        {
            return Unauthorized();
        }
        if (_stepUp.NeedsStepUpToken(adminId, action))
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new { message = "Step-up authentication required.", stepUpRequired = true });
        }
        return null;
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
        // [v2.5.13] (#97) separate "show built-in button" from "provider enabled".
        public bool ShowLoginButton { get; set; } = true;
        // [v2.5.6] (issue #28): default true. Most Jellyfin servers sit behind
        // a TLS-terminating reverse proxy; old default left users with a
        // broken http:// redirect_uri and a confusing IdP error.
        public bool ForceHttps { get; set; } = true;
        // [v2.5.7] (issue #54, cwildfoerster): per-provider opt-in to bypass
        // the v2.5.5 SSRF guard for LAN/VPN IdPs. Default false.
        public bool AllowPrivateNetworks { get; set; }
        // [v2.5.15] (#103): operator-controlled SSRF allowlist (comma-separated
        // CIDRs) for non-RFC1918 / link-local IdP addresses the guard rejects.
        public string AdditionalAllowedCidrs { get; set; } = string.Empty;
        // [v2.5.10] (#66) sync IdP avatar into the Jellyfin profile picture.
        public bool SyncProfilePicture { get; set; }
        public string PictureClaim { get; set; } = "picture";
        // [v2.5.10] (#65) role→library access.
        public bool ApplyRoleLibraryAccess { get; set; }
        public List<RoleLibraryMappingDto> RoleLibraryMappings { get; set; } = new();
        // [v2.5.10] force the IdP account chooser (prompt=select_account).
        public bool PromptSelectAccount { get; set; }
        // [v2.5.11] (#70) configurable email claim + auto-fill the user's email.
        public string EmailClaim { get; set; } = "email";
        public bool SyncEmailFromClaim { get; set; } = true;
        // [v2.5.11] (#69) custom login-button text + icon.
        public string ButtonText { get; set; } = string.Empty;
        public string ButtonIconUrl { get; set; } = string.Empty;
        // [v2.5.13] (#96) opt-in: actually elevate users matched by AdminGroups.
        public bool AllowAdminGroupElevation { get; set; }
        // [v2.5.13] (#93) template user GUID for auto-created users.
        public string TemplateUserId { get; set; } = string.Empty;
        // [v2.5.14] (#100) force a new OIDC user to set a local Jellyfin password.
        public bool ForcePasswordSetup { get; set; }
        // [v2.5.14] (#94, Re4mstr) Optional explicit callback slug. The slug is the
        // last segment of the OIDC redirect URI (…/Oidc/Callback/&lt;slug&gt;).
        // Sending a non-empty value on UPDATE renames the provider's slug (e.g. to
        // fix a typo'd "sing-in-with-…") in place — migrating existing SSO links —
        // instead of forcing a delete + re-add. Ignored on create (the slug is
        // derived from the display name there). Blank = leave the slug unchanged.
        public string CallbackSlug { get; set; } = string.Empty;
    }

    /// <summary>[v2.5.10] (#65) one role→libraries mapping as sent by the admin
    /// UI. <see cref="LibraryIds"/> is a comma-separated list of Jellyfin
    /// virtual-folder GUIDs the role grants.</summary>
    public class RoleLibraryMappingDto
    {
        public string Role { get; set; } = string.Empty;
        public string LibraryIds { get; set; } = string.Empty;
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
        // [v2.5.13] (#97) Only emit a button for providers that are enabled AND
        // configured to show their built-in button. A provider with SSO enabled
        // but ShowLoginButton=false stays fully usable via its URL (custom button)
        // yet renders no button here.
        var safe = config.OidcProviders.Where(p => p.Enabled && p.ShowLoginButton).Select(p => new
        {
            id = p.Id,
            displayName = p.DisplayName,
            enabled = true,
            // [v2.5.11] (#69) login-button customization — safe to expose to
            // the anonymous login page (display label + already-sanitized icon).
            buttonText = p.ButtonText,
            buttonIconUrl = p.ButtonIconUrl,
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
            allowAdminGroupElevation = p.AllowAdminGroupElevation,
            templateUserId = p.TemplateUserId,
            autoCreateUsers = p.AutoCreateUsers,
            requireIdpMfa = p.RequireIdpMfa,
            bypassPluginTwoFa = p.BypassPluginTwoFa,
            enabled = p.Enabled,
            showLoginButton = p.ShowLoginButton,
            forceHttps = p.ForceHttps,
            allowPrivateNetworks = p.AllowPrivateNetworks,
            additionalAllowedCidrs = p.AdditionalAllowedCidrs,
            syncProfilePicture = p.SyncProfilePicture,
            pictureClaim = p.PictureClaim,
            applyRoleLibraryAccess = p.ApplyRoleLibraryAccess,
            roleLibraryMappings = p.RoleLibraryMappings.Select(m => new { role = m.Role, libraryIds = m.LibraryIds }).ToList(),
            promptSelectAccount = p.PromptSelectAccount,
            emailClaim = p.EmailClaim,
            syncEmailFromClaim = p.SyncEmailFromClaim,
            buttonText = p.ButtonText,
            buttonIconUrl = p.ButtonIconUrl,
            // [v2.5.14] (#100) force-password-on-onboarding opt-in.
            forcePasswordSetup = p.ForcePasswordSetup,
            createdAt = p.CreatedAt,
            // [v2.5.14] (#94/#98) Surface the exact callback/redirect URI the IdP
            // must be configured with, and the editable slug. This kills the
            // "wrong callback URL" / "sing-in-with-…" typo confusion: the admin can
            // now see and copy the real value instead of reconstructing it by hand.
            callbackSlug = p.Id,
            callbackUrl = BuildRedirectUri(p),
        }).ToList<object>();
        return Ok(safe);
    }

    [HttpPost("Oidc/Providers")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult<object> CreateProvider([FromBody, Required] OidcProviderUpsertRequest req)
    {
        // SECURITY [v2.5.6] (U3): require step-up. Adding an OIDC provider
        // wires a new identity-issuer trust path into the plugin and could
        // be used to silently redirect future sign-ins to an attacker IdP.
        // ConfigChange-classified step-up.
        var guardCreate = StepUpGuard(StepUpAction.ConfigChange);
        if (guardCreate is not null) return guardCreate;

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
            AllowAdminGroupElevation = req.AllowAdminGroupElevation,
            TemplateUserId = (req.TemplateUserId ?? string.Empty).Trim(),
            AutoCreateUsers = req.AutoCreateUsers,
            RequireIdpMfa = req.RequireIdpMfa,
            BypassPluginTwoFa = req.BypassPluginTwoFa,
            Enabled = req.Enabled,
            ShowLoginButton = req.ShowLoginButton,
            ForceHttps = req.ForceHttps,
            // [v2.5.7] (issue #54): per-provider SSRF-guard opt-out.
            AllowPrivateNetworks = req.AllowPrivateNetworks,
            // [v2.5.15] (#103): per-provider SSRF allowlist (extra CIDRs).
            AdditionalAllowedCidrs = req.AdditionalAllowedCidrs,
            // [v2.5.10] (#66 / #65)
            SyncProfilePicture = req.SyncProfilePicture,
            PictureClaim = string.IsNullOrWhiteSpace(req.PictureClaim) ? "picture" : req.PictureClaim.Trim(),
            ApplyRoleLibraryAccess = req.ApplyRoleLibraryAccess,
            RoleLibraryMappings = MapRoleLibraryMappings(req.RoleLibraryMappings),
            PromptSelectAccount = req.PromptSelectAccount,
            // [v2.5.11] (#70 / #69)
            EmailClaim = string.IsNullOrWhiteSpace(req.EmailClaim) ? "email" : req.EmailClaim.Trim(),
            SyncEmailFromClaim = req.SyncEmailFromClaim,
            ButtonText = (req.ButtonText ?? string.Empty).Trim(),
            ButtonIconUrl = SanitizeButtonIconUrl(req.ButtonIconUrl),
            // [v2.5.14] (#100) force-password-on-onboarding opt-in.
            ForcePasswordSetup = req.ForcePasswordSetup,
            CreatedAt = DateTime.UtcNow,
        };
        config.OidcProviders.Add(provider);
        plugin.SaveConfiguration();
        return Ok(new { id = provider.Id, displayName = provider.DisplayName });
    }

    [HttpPut("Oidc/Providers/{id}")]
    [Authorize(Policy = "RequiresElevation")]
    public async Task<ActionResult> UpdateProvider([FromRoute] string id, [FromBody, Required] OidcProviderUpsertRequest req)
    {
        // SECURITY [v2.5.6] (U3): require step-up before mutating an OIDC
        // provider. Editing the DiscoveryUrl or ClientSecret silently
        // redirects future sign-ins to an attacker IdP.
        var guardUpd = StepUpGuard(StepUpAction.ConfigChange);
        if (guardUpd is not null) return guardUpd;

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
        existing.AllowAdminGroupElevation = req.AllowAdminGroupElevation;
        existing.TemplateUserId = (req.TemplateUserId ?? string.Empty).Trim();
        existing.AutoCreateUsers = req.AutoCreateUsers;
        existing.RequireIdpMfa = req.RequireIdpMfa;
        existing.BypassPluginTwoFa = req.BypassPluginTwoFa;
        existing.Enabled = req.Enabled;
        existing.ShowLoginButton = req.ShowLoginButton;
        existing.ForceHttps = req.ForceHttps;
        // [v2.5.7] (issue #54): per-provider SSRF-guard opt-out.
        existing.AllowPrivateNetworks = req.AllowPrivateNetworks;
        // [v2.5.15] (#103): per-provider SSRF allowlist (extra CIDRs).
        existing.AdditionalAllowedCidrs = req.AdditionalAllowedCidrs;
        // [v2.5.10] (#66 / #65)
        existing.SyncProfilePicture = req.SyncProfilePicture;
        existing.PictureClaim = string.IsNullOrWhiteSpace(req.PictureClaim) ? "picture" : req.PictureClaim.Trim();
        existing.ApplyRoleLibraryAccess = req.ApplyRoleLibraryAccess;
        existing.RoleLibraryMappings = MapRoleLibraryMappings(req.RoleLibraryMappings);
        existing.PromptSelectAccount = req.PromptSelectAccount;
        // [v2.5.11] (#70 / #69)
        existing.EmailClaim = string.IsNullOrWhiteSpace(req.EmailClaim) ? "email" : req.EmailClaim.Trim();
        existing.SyncEmailFromClaim = req.SyncEmailFromClaim;
        existing.ButtonText = (req.ButtonText ?? string.Empty).Trim();
        existing.ButtonIconUrl = SanitizeButtonIconUrl(req.ButtonIconUrl);
        // [v2.5.14] (#100) force-password-on-onboarding opt-in.
        existing.ForcePasswordSetup = req.ForcePasswordSetup;

        // [v2.5.14] (#94, Re4mstr) Optional in-place callback-slug rename. The slug
        // is BOTH the last segment of the OIDC redirect URI (…/Oidc/Callback/<slug>)
        // AND the key SsoLinks are stored under, so renaming it must migrate those
        // links or already-linked users get orphaned. This lets an admin fix a
        // typo'd slug (e.g. "sing-in-with-…") without deleting + re-adding the
        // provider and re-entering every field. The admin MUST then update the
        // redirect_uri at their IdP to the new callback URL (returned below).
        string? renamedTo = null;
        var requestedSlug = (req.CallbackSlug ?? string.Empty).Trim();
        if (!string.IsNullOrEmpty(requestedSlug))
        {
            var newId = SlugifyId(requestedSlug);
            if (string.IsNullOrEmpty(newId))
            {
                return BadRequest(new { message = "Requested callback slug produces an empty id." });
            }

            if (!string.Equals(newId, existing.Id, StringComparison.Ordinal))
            {
                if (plugin.Configuration.OidcProviders.Any(p => p.Id == newId))
                {
                    return Conflict(new { message = $"Another OIDC provider already uses the slug '{newId}'." });
                }

                var oldId = existing.Id;
                existing.Id = newId;
                var migrated = await MigrateSsoLinkProviderIdAsync(oldId, newId).ConfigureAwait(false);
                _oidc.InvalidateCache(oldId);
                renamedTo = newId;
                _logger.LogWarning(
                    "[2FA] OIDC provider callback slug renamed '{Old}' -> '{New}' ({Count} SSO link(s) migrated). " +
                    "The redirect_uri at the identity provider MUST be updated to the new callback URL or sign-in will fail.",
                    oldId, newId, migrated);
            }
        }

        plugin.SaveConfiguration();
        _oidc.InvalidateCache(existing.Id);
        return Ok(new
        {
            id = existing.Id,
            renamed = renamedTo is not null,
            callbackUrl = BuildRedirectUri(existing),
        });
    }

    /// <summary>[v2.5.14] (#94) Re-point every user's SSO link from an old provider
    /// slug to a new one after a callback-slug rename, so already-linked accounts
    /// keep working. Returns the number of users whose links were migrated.</summary>
    private async Task<int> MigrateSsoLinkProviderIdAsync(string oldId, string newId)
    {
        var users = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var count = 0;
        foreach (var u in users)
        {
            if (!u.SsoLinks.Any(l => string.Equals(l.ProviderId, oldId, StringComparison.Ordinal)))
            {
                continue;
            }

            await _store.MutateAsync(u.UserId, ud =>
            {
                foreach (var l in ud.SsoLinks)
                {
                    if (string.Equals(l.ProviderId, oldId, StringComparison.Ordinal))
                    {
                        l.ProviderId = newId;
                    }
                }
            }).ConfigureAwait(false);
            count++;
        }

        return count;
    }


    /// <summary>[v2.5.10] (#65) map admin-UI role→library DTOs to the stored
    /// model, dropping blank rows and normalizing the library-id list.</summary>
    private static List<OidcRoleLibraryMapping> MapRoleLibraryMappings(List<RoleLibraryMappingDto>? dtos)
    {
        var result = new List<OidcRoleLibraryMapping>();
        if (dtos is null) return result;
        foreach (var d in dtos)
        {
            if (d is null || string.IsNullOrWhiteSpace(d.Role)) continue;
            var ids = (d.LibraryIds ?? string.Empty)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            result.Add(new OidcRoleLibraryMapping
            {
                Role = d.Role.Trim(),
                LibraryIds = string.Join(",", ids),
            });
        }

        return result;
    }

    /// <summary>[v2.5.11] (#69) accept only an https URL or a data: image URI
    /// for the login-button icon. Anything else (http, javascript:, relative,
    /// garbage) is dropped to empty — the button then renders with the default
    /// glyph. Prevents mixed-content warnings and an admin-typed javascript:
    /// URL ending up in the anonymous login page.</summary>
    private static string SanitizeButtonIconUrl(string? raw)
    {
        var v = (raw ?? string.Empty).Trim();
        if (v.Length == 0) return string.Empty;
        if (v.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase)) return v;
        if (Uri.TryCreate(v, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttps)
        {
            return v;
        }

        return string.Empty;
    }

    [HttpDelete("Oidc/Providers/{id}")]
    [Authorize(Policy = "RequiresElevation")]
    public ActionResult DeleteProvider([FromRoute] string id)
    {
        // SECURITY [v2.5.6] (U3): require step-up. Deleting an IdP locks
        // users out of OIDC sign-in; not catastrophic but still admin-
        // sensitive enough to gate.
        var guardDel = StepUpGuard(StepUpAction.ConfigChange);
        if (guardDel is not null) return guardDel;

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
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_bans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var rl = _oidcRateLimiter.CheckAndRecord("oidc_login:" + ip, 20, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many sign-in attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null) return NotFound(new { message = "Provider not found or disabled." });

        // returnUrl must be a same-origin relative path. Block absolute URLs,
        // protocol-relative, control chars (CR/LF/NUL), percent-encoded
        // variants of the same, backslash variants used to confuse browser-
        // side URL parsers, and anything that isn't a plain path. Defence-
        // in-depth: even though the current consumer only echoes the value
        // into a redirect-uri stored in PendingFlow, a future refactor that
        // surfaces it in a Location:/Refresh: header or a templated HTML
        // attribute would otherwise be header-injection / open-redirect.
        // SECURITY [v2.5.5] hardening (Finding 2).
        var safeReturn = "/web/";
        if (!string.IsNullOrEmpty(returnUrl) && IsSafeRelativePath(returnUrl))
        {
            safeReturn = returnUrl;
        }

        var redirectUri = BuildRedirectUri(provider);
        try
        {
            var (authUrl, state) = await _oidc.BeginAsync(provider, redirectUri, safeReturn).ConfigureAwait(false);

            // [v2.5.9] (issue #64): Google — and other strict IdPs — return
            // "403: disallowed_useragent" when their OAuth consent screen is
            // loaded inside an embedded app webview (e.g. the Jellyfin Android
            // app's in-app browser), and the app can't receive an OAuth
            // redirect back from an external browser. A blind 302 into that
            // webview dead-ends. So when the request originates from an
            // embedded webview we run a DEVICE-POLL flow: serve an interstitial
            // that (a) opens the consent in the system browser and (b) polls
            // this server for completion. The browser callback stashes the
            // session under a secret poll token (kept only in the app webview),
            // and the interstitial picks it up and logs the app in — no
            // copy-paste, no in-webview Google load.
            var userAgent = Request.Headers.UserAgent.ToString();
            if (IsEmbeddedWebView(userAgent))
            {
                var pollToken = _oidcBridge.BeginDeviceFlow(state);
                _logger.LogInformation("[2FA] OIDC begin from an embedded webview — serving device-poll interstitial (provider={Pid})", providerId);
                return Content(BuildWebViewBreakoutHtml(authUrl, provider.DisplayName, pollToken), "text/html; charset=utf-8");
            }

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

    /// <summary>[v2.5.9] (issue #64): device-poll endpoint for app-initiated
    /// OIDC. The app webview polls this with its secret poll token; once the
    /// external browser has finished the consent + callback, this returns the
    /// one-shot bridge token + resolved username so the app can complete login
    /// via /Users/AuthenticateByName. Returns {ready:false} while pending. The
    /// poll token is 256-bit random and single-use, so an unknown/!ready token
    /// is indistinguishable from a not-yet-complete one.</summary>
    [HttpGet("Oidc/DevicePoll")]
    [AllowAnonymous]
    public IActionResult OidcDevicePoll([FromQuery] string? pt)
    {
        var ip = RateLimiter.ClientKey(HttpContext);
        // Lenient cap: the app polls ~every 2s; this only stops flooding. The
        // poll token's entropy + one-shot consume are the real protection.
        var rl = _oidcRateLimiter.CheckAndRecord("oidc_devicepoll:" + ip, 150, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new { ready = false });
        }

        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        var res = _oidcBridge.PollDeviceFlow(pt ?? string.Empty);
        if (res is null) return Ok(new { ready = false });
        return Ok(new { ready = true, username = res.Value.Username, token = res.Value.BridgeToken });
    }

    /// <summary>[v2.5.9] (issue #64): JSON "begin" for the IN-PAGE app flow.
    /// The injected login button (inject.js) calls this instead of navigating
    /// to /Oidc/Login when it detects the Jellyfin app's native shell —
    /// navigating the app's webview off /web/ bounces it to the server-select
    /// screen and destroys the polling page. This returns the authorize URL +
    /// a device poll token WITHOUT navigating, so inject.js can open the
    /// browser via NativeShell, poll in-page, and complete login while the web
    /// client stays loaded.</summary>
    [HttpGet("Oidc/LoginInfo/{providerId}")]
    [AllowAnonymous]
    public async Task<IActionResult> OidcLoginInfo([FromRoute] string providerId)
    {
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_bans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = "This IP address is temporarily blocked.", expiresAt = ban.ExpiresAt });
        }

        var rl = _oidcRateLimiter.CheckAndRecord("oidc_login:" + ip, 20, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = $"Too many sign-in attempts. Try again in {rl.retryAfterSeconds} seconds." });
        }

        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null) return NotFound(new { message = "Provider not found or disabled." });

        var redirectUri = BuildRedirectUri(provider);
        try
        {
            var (authUrl, state) = await _oidc.BeginAsync(provider, redirectUri, "/web/").ConfigureAwait(false);
            var pollToken = _oidcBridge.BeginDeviceFlow(state);
            Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
            _logger.LogInformation("[2FA] OIDC in-page device flow begun (provider={Pid})", providerId);
            return Ok(new { authUrl, pollToken });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] OIDC LoginInfo begin failed for {Provider}", providerId);
            return StatusCode(StatusCodes.Status502BadGateway, new { message = "Failed to start OIDC sign-in — check server logs." });
        }
    }

    /// <summary>[v2.5.7] OIDC step-up — begin flow for an already-signed-in
    /// user who wants to satisfy a factor-change step-up gate via their
    /// linked IdP. Returns the IdP authorize URL for the client to open in
    /// a popup; the standard /Oidc/Callback/{providerId} endpoint routes
    /// step-up state to <see cref="OidcService.CompleteUserStepUpAsync"/>.</summary>
    [HttpPost("Oidc/StepUpBegin/{providerId}")]
    [Authorize]
    public async Task<IActionResult> OidcStepUpBegin([FromRoute] string providerId)
    {
        if (!Guid.TryParse(User.FindFirst("Jellyfin-UserId")?.Value, out var userId))
        {
            return Unauthorized();
        }
        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null)
        {
            return NotFound(new { message = "Provider not found or disabled." });
        }
        // Require an existing SsoLink so an attacker who hijacks an
        // authenticated session can't "step-up" through an arbitrary IdP
        // they happen to have an account at.
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (!userData.SsoLinks.Any(l => string.Equals(l.ProviderId, providerId, StringComparison.Ordinal)))
        {
            return BadRequest(new { message = "You don't have this provider linked to your account." });
        }
        var redirectUri = BuildRedirectUri(provider);
        try
        {
            var (authUrl, _) = await _oidc.BeginUserStepUpAsync(provider, userId, redirectUri).ConfigureAwait(false);
            return Ok(new { authUrl });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] OIDC step-up begin failed for {Provider}", providerId);
            return StatusCode(StatusCodes.Status502BadGateway, new
            {
                message = "Failed to start OIDC step-up — check server logs.",
            });
        }
    }

    /// <summary>[v2.5.13] (#95, yannolerobot) Begin an EXPLICIT account-link for
    /// the authenticated user (Setup → "Link a new provider"). No pre-existing
    /// link is required — that's the point — but the user must be authenticated,
    /// and the link is bound to THIS user in server-side state. This is how an
    /// admin links OIDC: the regular sign-in resolver refuses admin email/username
    /// matches (anti-takeover), and this path never goes through it.</summary>
    [HttpPost("Oidc/LinkBegin/{providerId}")]
    [Authorize]
    public async Task<IActionResult> OidcLinkBegin([FromRoute] string providerId)
    {
        if (!Guid.TryParse(User.FindFirst("Jellyfin-UserId")?.Value, out var userId))
        {
            return Unauthorized();
        }
        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null)
        {
            return NotFound(new { message = "Provider not found or disabled." });
        }
        var redirectUri = BuildRedirectUri(provider);
        try
        {
            var (authUrl, _) = await _oidc.BeginUserLinkAsync(provider, userId, redirectUri).ConfigureAwait(false);
            return Ok(new { authUrl });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] OIDC link begin failed for {Provider}", providerId);
            return StatusCode(StatusCodes.Status502BadGateway, new
            {
                message = "Failed to start OIDC linking — check server logs.",
            });
        }
    }

    /// <summary>[v2.5.7] HTML response served to the OIDC step-up popup so
    /// it can postMessage the result back to the opener and close itself.
    /// Strict-mode JS, opener-relative origin check, no inline interactivity
    /// beyond what's needed for the handoff.</summary>
    private static string BuildStepUpPopupHtml(bool success, string? stepUpToken, string? message)
    {
        // Token + message are both server-controlled in the success path
        // (mint output / static strings); even so we escape defensively.
        var tokenJs = success && !string.IsNullOrEmpty(stepUpToken)
            ? System.Text.Json.JsonSerializer.Serialize(stepUpToken)
            : "null";
        var msgJs = System.Text.Json.JsonSerializer.Serialize(message ?? string.Empty);
        var successJs = success ? "true" : "false";
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in complete</title>"
            + "<style>body{background:#111;color:#eee;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;padding:20px;}"
            + ".card{max-width:380px;}h1{font-size:18px;margin:0 0 8px;}p{margin:0;color:#aaa;font-size:14px;}</style>"
            + "</head><body><div class=\"card\"><h1 id=\"h\"></h1><p id=\"p\"></p></div><script>(function(){"
            + "var ok=" + successJs + ",t=" + tokenJs + ",m=" + msgJs + ";"
            + "document.getElementById('h').textContent=ok?'Signed in':'Sign-in failed';"
            + "document.getElementById('p').textContent=ok?'You can close this window.':(m||'Try again.');"
            + "try{if(window.opener){window.opener.postMessage({type:'tfa-stepup-oidc',success:ok,stepUpToken:t,message:m},window.location.origin);}}catch(e){}"
            + "setTimeout(function(){try{window.close();}catch(e){}},800);"
            + "})();</script></body></html>";
    }

    /// <summary>[v2.5.13] (#95) HTML served to the explicit-link popup; it
    /// postMessages the link result back to the Setup-page opener and closes.</summary>
    private static string BuildLinkPopupHtml(bool success, string? message)
    {
        var msgJs = System.Text.Json.JsonSerializer.Serialize(message ?? string.Empty);
        var successJs = success ? "true" : "false";
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Link account</title>"
            + "<style>body{background:#111;color:#eee;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;padding:20px;}"
            + ".card{max-width:380px;}h1{font-size:18px;margin:0 0 8px;}p{margin:0;color:#aaa;font-size:14px;}</style>"
            + "</head><body><div class=\"card\"><h1 id=\"h\"></h1><p id=\"p\"></p></div><script>(function(){"
            + "var ok=" + successJs + ",m=" + msgJs + ";"
            + "document.getElementById('h').textContent=ok?'Account linked':'Linking failed';"
            + "document.getElementById('p').textContent=ok?'You can close this window.':(m||'Try again.');"
            + "try{if(window.opener){window.opener.postMessage({type:'tfa-link-oidc',success:ok,message:m},window.location.origin);}}catch(e){}"
            + "setTimeout(function(){try{window.close();}catch(e){}},900);"
            + "})();</script></body></html>";
    }

    [HttpGet("Oidc/Callback/{providerId}")]
    [AllowAnonymous]
    public async Task<IActionResult> Callback(
        [FromRoute] string providerId,
        [FromQuery] string? code,
        [FromQuery] string? state,
        [FromQuery] string? error)
    {
        var callbackIp = BypassEvaluator.ResolveClientIp(HttpContext)
            ?? RateLimiter.ClientKey(HttpContext);
        if (_bans.CheckBanned(callbackIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        _logger.LogInformation("[2FA] OIDC Callback hit: provider={Pid} codeLen={CL} stateLen={SL} error={Err}",
            providerId, code?.Length ?? 0, state?.Length ?? 0, error ?? "(none)");
        if (!string.IsNullOrEmpty(error))
        {
            // SECURITY [v2.5.5]: do NOT echo the raw IdP-supplied `error`
            // string into the redirect URL. The full value is logged server-
            // side at Warning for diagnostics, but the user-facing redirect
            // only carries a sanitized message mapped from the standard
            // OIDC/OAuth2 error code set (RFC 6749 §4.1.2.1 + OIDC core
            // §3.1.2.6). Unknown codes coerce to a generic message so a
            // crafty IdP (or a replayed callback URL) can't inject arbitrary
            // text into the login screen via the oidcError query parameter.
            _logger.LogWarning("[2FA] OIDC provider returned error: {Err}", error);
            var safeMsg = error.ToLowerInvariant() switch
            {
                "access_denied" => "Sign-in was cancelled.",
                "login_required" or "interaction_required" or "consent_required" => "Sign-in requires interaction at the identity provider.",
                "invalid_request" or "invalid_scope" or "unsupported_response_type" or "unauthorized_client" => "Sign-in request was rejected by the identity provider. Contact your administrator.",
                "server_error" or "temporarily_unavailable" => "Identity provider is temporarily unavailable. Try again shortly.",
                _ => "Sign-in failed at the identity provider.",
            };
            return Redirect(LoginErrorUrl(safeMsg));
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

        var redirectUri = BuildRedirectUri(provider);
        _logger.LogInformation("[2FA] OIDC token exchange redirect_uri={Uri}", redirectUri);

        // [v2.5.7] OIDC step-up: if the state was minted by a step-up Begin
        // (rather than a regular login Begin), run the step-up completion
        // and return a popup-friendly HTML that postMessages success back to
        // the opener instead of redirecting the whole window. Non-consuming
        // peek so a state for the OTHER path still routes correctly.
        if (_oidc.IsUserStepUpState(state))
        {
            var su = await _oidc.CompleteUserStepUpAsync(provider, code, state, redirectUri).ConfigureAwait(false);
            if (!su.Success || su.UserId is null)
            {
                _bans.RecordFailure(callbackIp);
                _logger.LogWarning("[2FA] OIDC step-up failed: {Err}", su.Error ?? "(unknown)");
                return Content(BuildStepUpPopupHtml(success: false, stepUpToken: null,
                    message: "Step-up sign-in failed. You can close this window and try again."),
                    "text/html; charset=utf-8");
            }
            var stepUpToken = _challenges.MintUserStepUpToken(su.UserId.Value);
            return Content(BuildStepUpPopupHtml(success: true, stepUpToken: stepUpToken, message: null),
                "text/html; charset=utf-8");
        }

        // [v2.5.13] (#95) Explicit account-link from Setup. The state was minted
        // by an authenticated LinkBegin, so the Jellyfin user is already known —
        // link by sub directly (the sign-in resolver, which refuses admin
        // matches, is never consulted) and return a popup that reports the result.
        if (_oidc.IsUserLinkState(state))
        {
            var lr = await _oidc.CompleteUserLinkAsync(provider, code, state, redirectUri).ConfigureAwait(false);
            if (!lr.Success)
            {
                _bans.RecordFailure(callbackIp);
                _logger.LogWarning("[2FA] OIDC explicit link failed: {Err}", lr.Error ?? "(unknown)");
            }
            return Content(BuildLinkPopupHtml(lr.Success, lr.Error), "text/html; charset=utf-8");
        }

        // [v2.5.14] (#95) Diagnostic: we reach here only when the callback state
        // matched neither a pending step-up NOR a pending explicit-link flow, so
        // it is treated as a normal sign-in (which runs the resolver that refuses
        // admin email/username matches). If an admin clicked "Link a new provider"
        // and still lands here, the link state was LOST between LinkBegin and this
        // callback (plugin/server restart, a second instance, or TTL expiry) — that
        // is the #95 fall-through. Logging it makes the cause unambiguous in the
        // server log instead of surfacing only as the generic resolver refusal.
        _logger.LogInformation(
            "[2FA] OIDC callback state did not match a pending step-up or explicit-link flow — handling as a normal sign-in (provider {Provider}). If this was a Setup 'Link a new provider' attempt, the link state was lost before the callback (see #95).",
            provider.Id);

        var result = await _oidc.CompleteAsync(provider, code, state, redirectUri).ConfigureAwait(false);
        if (!result.Success || result.UserId is null || result.Username is null)
        {
            // SECURITY [v2.5.5] (N-A9): do NOT echo the raw internal error
            // message into the redirect URL. CompleteAsync's error strings
            // can include token-validation library detail
            // ("Token verification failed: IDX10501: …") that fingerprints
            // the JWK matching logic / library version / configured issuer.
            // Log the full message server-side, surface a generic one-of-a-few
            // user-facing message to the browser.
            _logger.LogWarning("[2FA] OIDC sign-in failed: {Err}", result.Error);
            var lower = (result.Error ?? string.Empty).ToLowerInvariant();
            string safeMsg;
            if (lower.Contains("state token", StringComparison.Ordinal))
            {
                safeMsg = "Your sign-in session expired. Try again.";
            }
            else if (lower.Contains("token exchange", StringComparison.Ordinal))
            {
                safeMsg = "The identity provider rejected the sign-in. Contact your administrator if this persists.";
            }
            else if (lower.Contains("verification", StringComparison.Ordinal) || lower.Contains("signature", StringComparison.Ordinal))
            {
                safeMsg = "Sign-in token could not be verified.";
            }
            // [v2.5.11] (ZEROX7) actionable guidance for the common SSO setup
            // mistakes. These carry NO token/library internals — only config
            // advice — so they're safe to surface to the browser. Without them
            // every failure read "Sign-in failed" and the user (and admin) had
            // no idea why the sign-in bounced.
            else if (lower.Contains("no jellyfin user matched", StringComparison.Ordinal)
                || lower.Contains("auto-create", StringComparison.Ordinal))
            {
                safeMsg = "No matching Jellyfin account — link this provider from your Setup page, or ask your admin.";
            }
            else if (lower.Contains("allowed group", StringComparison.Ordinal))
            {
                safeMsg = "Your account isn't in a group allowed to sign in here.";
            }
            else if (lower.Contains("mfa", StringComparison.Ordinal))
            {
                safeMsg = "This provider requires MFA — enable it at your identity provider, then try again.";
            }
            else
            {
                safeMsg = "Sign-in failed.";
            }

            return Redirect(LoginErrorUrl(safeMsg));
        }

        _logger.LogInformation("[2FA] OIDC success for user {User} ({UserId}) via {Pid}",
            result.Username, result.UserId, providerId);

        if (!await _allowlist.IsAllowedAsync(result.UserId.Value, callbackIp).ConfigureAwait(false))
        {
            _logger.LogWarning("[2FA] OIDC sign-in refused for {User}: IP {Ip} not in allowlist",
                result.Username, callbackIp);
            _bans.RecordFailure(callbackIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        // [v2.5.12] (issue #64): device-poll logins put a HUMAN in the loop —
        // the user finishes consent in the SYSTEM browser, then manually
        // switches back to the app, which only THEN poll-picks the token and
        // calls /Users/AuthenticateByName. Android also throttles/pauses the
        // webview's poll timer while the app is backgrounded. That round-trip
        // routinely exceeds the default 60s bridge-token TTL, so the token
        // expired before the app could spend it → AuthenticateByName 401/403
        // AFTER a successful consent ("you're signed in, then 403 in the app").
        // Give device-flow tokens a TTL that matches the poll window (3 min);
        // the desktop bridge auto-submits in the same tab within ~1s and keeps
        // the tight 60s default.
        var isDeviceFlow = _oidcBridge.HasDeviceFlow(state);

        // Mint a one-shot bridge token.
        var token = _oidcBridge.Mint(
            result.UserId.Value,
            result.Username,
            providerId,
            ttl: isDeviceFlow ? TimeSpan.FromMinutes(3) : null,
            bypassPluginTwoFa: provider.BypassPluginTwoFa);

        // [v2.5.9] (issue #64): if this login was started from an app webview
        // (device-poll flow), the consent ran here in the external browser but
        // the SESSION belongs to the app. Stash the bridge token under the
        // flow's secret poll token so the app's webview poll picks it up, and
        // show the browser a "return to your app" page instead of logging the
        // browser in.
        if (isDeviceFlow)
        {
            _oidcBridge.CompleteDeviceFlow(state, result.Username, token);
            _logger.LogInformation("[2FA] OIDC device-poll completed in browser for {User} — app will pick up the session", result.Username);
            Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
            Response.Headers.Pragma = "no-cache";
            Response.Headers["X-Content-Type-Options"] = "nosniff";
            return Content(BuildDeviceReturnHtml(), "text/html; charset=utf-8");
        }

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
        // [v2.5.14] (#100) If this user must still choose a local Jellyfin password
        // (flagged on auto-create for a ForcePasswordSetup provider), land them on
        // the onboarding page instead of /web. They arrive with a valid session, so
        // the set-password page can change the password and then forward to /web.
        var mustSetPassword = false;
        try
        {
            mustSetPassword = (await _store.GetUserDataAsync(result.UserId.Value).ConfigureAwait(false)).MustSetPassword;
        }
        catch (Exception mspEx)
        {
            _logger.LogDebug(mspEx, "[2FA] Could not read MustSetPassword for {User}; landing on /web", result.Username);
        }
        var landingPath = mustSetPassword ? "/TwoFactorAuth/SetPassword" : "/web/index.html";

        var uname = System.Text.Json.JsonSerializer.Serialize(result.Username);
        var tok = System.Text.Json.JsonSerializer.Serialize(token);
        var land = System.Text.Json.JsonSerializer.Serialize(landingPath);
        var html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Signing in…</title>"
            + "<style>body{background:#0a0a0a;color:#e0e0e0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}"
            + ".card{background:#1a1a1a;padding:32px 40px;border-radius:8px;text-align:center;border:1px solid #2a2a2a;}"
            + ".spin{width:32px;height:32px;border:3px solid #333;border-top-color:#00a4dc;border-radius:50%;animation:s 0.8s linear infinite;margin:0 auto 16px;}"
            + "@keyframes s{to{transform:rotate(360deg)}}.err{color:#f44336;margin-top:12px;}</style></head>"
            + "<body><div class=\"card\"><div class=\"spin\"></div><div id=\"msg\">Completing sign-in…</div>"
            + "<div id=\"err\" class=\"err\"></div></div><script>"
            + "(function(){"
            + "var u=" + uname + ",t=" + tok + ",land=" + land + ",forcePw=" + (mustSetPassword ? "true" : "false") + ";"
            + "var did=(function(){try{var x=localStorage.getItem('_deviceId2');if(!x){x=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b=>b.toString(16).padStart(2,'0')).join('');localStorage.setItem('_deviceId2',x);}return x;}catch(e){return 'bridge-'+Date.now();}})();"
            + "var auth='MediaBrowser Client=\"Jellyfin Web\", Device=\"Browser\", DeviceId=\"'+did+'\", Version=\"10.11.0\"';"
            + "fetch('/Users/AuthenticateByName',{method:'POST',headers:{'Content-Type':'application/json','X-Emby-Authorization':auth,'Authorization':auth},body:JSON.stringify({Username:u,Pw:t})})"
            + ".then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})"
            + ".then(function(res){"
            + "var server={Id:res.ServerId,Name:'Jellyfin',AccessToken:res.AccessToken,UserId:res.User.Id,Type:'Server',DateLastAccessed:Date.now(),LastConnectionMode:1,ManualAddress:window.location.origin,LocalAddress:window.location.origin};"
            + "var creds={Servers:[server]};"
            + "localStorage.setItem('jellyfin_credentials',JSON.stringify(creds));"
            // [v2.5.14] (#98) Clear any STALE 2FA-pending flag before landing on
            // /web. A leftover '__tfa_pending' (from an earlier failed/abandoned
            // attempt on this browser) would otherwise make inject.js short-circuit
            // the freshly-signed-in session's bootstrap API calls with synthetic
            // 403s, and Jellyfin Web bounces straight back to login. This is the
            // per-browser sessionStorage that explained why the same user worked on
            // one device but not another (#98). The OIDC sign-in just succeeded, so
            // there is by definition no pending 2FA challenge to preserve.
            + "try{sessionStorage.removeItem('__tfa_pending');}catch(e){}"
            // [v2.5.16] (#100, Re4mstr) For a force-password user, set a marker so
            // inject.js bounces them back to /SetPassword if they later reach /web
            // (e.g. by pressing Back) without completing it. Cleared by the
            // set-password page on a successful set, or if the server reports no
            // setup pending (stale). This makes the forced step inescapable.
            + "try{if(forcePw)localStorage.setItem('__tfa_set_pw_required','1');}catch(e){}"
            + "document.getElementById('msg').textContent='Signed in as '+res.User.Name+' — redirecting…';"
            + "setTimeout(function(){window.location.href=land;},400);"
            + "})"
            // [v2.5.13] (#98) Do NOT silently bounce to login on failure — the IdP
            // authenticated the user but this server's AuthenticateByName step
            // failed (commonly an auth proxy intercepting /Users/AuthenticateByName,
            // or an expired bridge token). Surface the real error + a manual link so
            // the user (and we) can see why instead of an infinite login loop.
            + ".catch(function(e){"
            + "console.error('[2FA] OIDC bridge sign-in failed:', e);"
            + "var sp=document.querySelector('.spin'); if(sp)sp.style.display='none';"
            + "document.getElementById('msg').textContent='Sign-in could not be completed.';"
            + "var err=document.getElementById('err'); err.innerHTML='';"
            + "var d=document.createElement('div'); d.textContent=(e&&e.message)?('Error: '+e.message):'Unknown error.'; err.appendChild(d);"
            + "var hint=document.createElement('div'); hint.style.cssText='margin-top:8px;color:#888;font-size:12px;line-height:1.4;'; hint.textContent='The identity provider authenticated you, but this server did not accept the sign-in token. If Jellyfin is behind an auth proxy (Authelia / Authentik), make sure it is not intercepting POST /Users/AuthenticateByName.'; err.appendChild(hint);"
            + "var a=document.createElement('a'); a.href='/web/index.html#!/login.html'; a.textContent='Back to login'; a.style.cssText='display:inline-block;margin-top:14px;color:#00a4dc;text-decoration:none;'; err.appendChild(a);"
            + "});"
            + "})();"
            + "</script></body></html>";
        // Stops browsers/proxies caching the bridge token in history or shared cache.
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        // SECURITY [v2.5.6] (F5-A9): defence-in-depth headers for the
        // bridge HTML — the token is embedded in inline JS so anti-clickjack
        // (X-Frame-Options) and no-referrer (Referrer-Policy) close edge
        // exposure paths even though the bridge auto-submits immediately.
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        // CSP limits fetch/XHR/img/script to same origin so even if an injection
        // slipped past JSON encoding, it couldn't exfiltrate the bridge token.
        Response.Headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; frame-ancestors 'none'";
        return Content(html, "text/html; charset=utf-8");
    }

    // =========================================================================
    // OIDC TOKEN EXCHANGE (v2.5.1, anonymous, RFC 8693-style)
    // =========================================================================
    // Native clients (Swiftfin, Findroid, Tizen apps) run their own OIDC
    // auth-code+PKCE flow against the same client_id this plugin is configured
    // with, then POST the resulting id_token here. We verify it (signature +
    // issuer + audience=ClientId + expiry — NOT nonce, because we didn't
    // issue one) and mint a one-shot bridge token the client posts to
    // /Users/AuthenticateByName, identical to the browser bridge flow.

    public class OidcTokenExchangeRequest
    {
        [Required] public string IdToken { get; set; } = string.Empty;
        public string? AccessToken { get; set; }
    }

    public class OidcTokenExchangeResponse
    {
        public string Username { get; set; } = string.Empty;
        public string BridgeToken { get; set; } = string.Empty;
        public bool BypassPluginTwoFa { get; set; }
    }

    [HttpPost("Oidc/Exchange/{providerId}")]
    [AllowAnonymous]
    public async Task<IActionResult> ExchangeToken(
        [FromRoute] string providerId,
        [FromBody, Required] OidcTokenExchangeRequest req)
    {
        // Same IP-ban / rate-limit gate as /Oidc/Login. Token exchange is
        // unauthenticated so it gets the same anti-abuse boundary.
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_bans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var rl = _oidcRateLimiter.CheckAndRecord("oidc_exchange:" + ip, 20, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many sign-in attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var provider = Plugin.Instance?.Configuration.OidcProviders
            .FirstOrDefault(p => p.Id == providerId && p.Enabled);
        if (provider is null)
        {
            return NotFound(new { message = "Provider not found or disabled." });
        }
        if (string.IsNullOrWhiteSpace(req.IdToken))
        {
            return BadRequest(new { message = "id_token is required." });
        }

        var result = await _oidc.ExchangeIdTokenAsync(provider, req.IdToken, req.AccessToken).ConfigureAwait(false);
        if (!result.Success || result.UserId is null || result.Username is null)
        {
            _bans.RecordFailure(clientIp);
            _logger.LogWarning("[2FA] OIDC token-exchange failed for {Pid}: {Err}", providerId, result.Error);
            // SECURITY [v2.5.6] (U4): map internal error to a safe user-
            // facing message instead of echoing result.Error directly.
            // result.Error can include Microsoft.IdentityModel exception
            // text (IDX10501 ..., JWK lookup detail, configured issuer)
            // which fingerprints the deployment for an attacker. Same
            // pattern N-A9 applied to the browser callback path; this
            // is the native /Exchange sibling that was missed.
            var exchangeLower = (result.Error ?? string.Empty).ToLowerInvariant();
            var exchangeSafeMsg = exchangeLower.Contains("state token", StringComparison.Ordinal)
                ? "Your sign-in session expired. Try again."
                : exchangeLower.Contains("token exchange", StringComparison.Ordinal)
                    ? "The identity provider rejected the sign-in. Contact your administrator if this persists."
                    : exchangeLower.Contains("verification", StringComparison.Ordinal) || exchangeLower.Contains("signature", StringComparison.Ordinal)
                        ? "Sign-in token could not be verified."
                        : "Sign-in failed.";
            return BadRequest(new { message = exchangeSafeMsg });
        }

        // Per-user IP allowlist (same gate as the browser callback).
        if (!await _allowlist.IsAllowedAsync(result.UserId.Value, clientIp).ConfigureAwait(false))
        {
            _logger.LogWarning("[2FA] OIDC token-exchange refused for {User}: IP {Ip} not in allowlist",
                result.Username, clientIp);
            _bans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        var token = _oidcBridge.Mint(
            result.UserId.Value,
            result.Username,
            providerId,
            bypassPluginTwoFa: provider.BypassPluginTwoFa);

        _logger.LogInformation("[2FA] OIDC token-exchange success for {User} via {Pid}",
            result.Username, providerId);

        return Ok(new OidcTokenExchangeResponse
        {
            Username = result.Username,
            BridgeToken = token,
            BypassPluginTwoFa = provider.BypassPluginTwoFa,
        });
    }

    /// <summary>[v2.5.9] (issue #64): heuristically detect an embedded app
    /// webview from the User-Agent. Google and other strict IdPs reject their
    /// OAuth consent screen with "403: disallowed_useragent" inside these, so
    /// the OIDC begin endpoint serves a break-out interstitial instead of a
    /// blind redirect. Deliberately conservative — only the reliable Android
    /// System WebView marker and well-known in-app social browsers — so normal
    /// desktop/mobile browsers and the Jellyfin web client are never affected.</summary>
    private static bool IsEmbeddedWebView(string? ua)
    {
        if (string.IsNullOrEmpty(ua)) return false;
        if (ua.Contains("; wv", StringComparison.OrdinalIgnoreCase)) return true;   // Android System WebView
        if (ua.Contains("(wv)", StringComparison.OrdinalIgnoreCase)) return true;
        string[] markers = { "FBAN", "FBAV", "FB_IAB", "Instagram", "Line/", "GSA/", "musical_ly", "TikTok", "Snapchat" };
        foreach (var m in markers)
        {
            if (ua.Contains(m, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>[v2.5.9] (issue #64): interstitial served to embedded webviews
    /// in place of the OIDC begin redirect. Google blocks its consent screen
    /// inside app webviews; this page breaks the sign-in out to the system
    /// browser — Android via an intent:// URL, everything else via a normal
    /// link — with a copyable-URL fallback. All URLs are injected as
    /// JSON-encoded JS string literals (never raw into HTML) so the auth URL's
    /// query string can't break out of the markup.</summary>
    private static string BuildWebViewBreakoutHtml(string authUrl, string providerDisplayName, string pollToken)
    {
        // Android intent:// that forces the OS default browser (outside the
        // webview). On webviews that pass intent:// to Android this opens
        // Chrome/the default browser; elsewhere the page falls back to a
        // plain link + a copyable URL.
        var intentUrl = authUrl;
        try
        {
            var u = new Uri(authUrl);
            intentUrl = "intent://" + u.Host + u.PathAndQuery
                + "#Intent;scheme=" + u.Scheme + ";action=android.intent.action.VIEW;end";
        }
        catch (UriFormatException)
        {
            // keep the plain URL
        }

        var authJson = System.Text.Json.JsonSerializer.Serialize(authUrl);
        var intentJson = System.Text.Json.JsonSerializer.Serialize(intentUrl);
        var nameJson = System.Text.Json.JsonSerializer.Serialize(
            string.IsNullOrWhiteSpace(providerDisplayName) ? "your identity provider" : providerDisplayName);
        var pollJson = System.Text.Json.JsonSerializer.Serialize(pollToken);

        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            + "<title>Continue sign-in</title><style>"
            + "body{background:#0a0a0a;color:#e6e6e6;font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}"
            + ".card{background:#16181c;border:1px solid #2a2d33;border-radius:14px;max-width:420px;width:100%;padding:28px;box-sizing:border-box;}"
            + "h1{font-size:20px;margin:0 0 12px;}p{color:#aeb4bd;line-height:1.5;font-size:15px;margin:0 0 16px;}"
            + ".btn{display:block;text-align:center;background:#00a4dc;color:#fff;text-decoration:none;font-weight:600;padding:14px;border-radius:10px;font-size:16px;border:0;width:100%;box-sizing:border-box;cursor:pointer;}"
            + ".btn2{display:block;text-align:center;background:#23262c;color:#e6e6e6;border:1px solid #2a2d33;font-weight:600;padding:13px;border-radius:10px;font-size:15px;width:100%;box-sizing:border-box;cursor:pointer;margin-top:10px;}"
            + ".spin{width:26px;height:26px;border:3px solid #333;border-top-color:#00a4dc;border-radius:50%;animation:s .8s linear infinite;margin:14px auto 0;display:none;}"
            + "@keyframes s{to{transform:rotate(360deg)}}"
            + ".status{font-size:14px;color:#9aa0a8;margin-top:14px;min-height:18px;}"
            + ".hint{font-size:13px;color:#7d828b;margin-top:18px;}"
            + ".url{width:100%;box-sizing:border-box;margin-top:8px;padding:10px;border-radius:8px;border:1px solid #2a2d33;background:#0c0d10;color:#aeb4bd;font-size:12px;}"
            + "</style></head><body><div class=\"card\">"
            + "<h1>Finish sign-in in your browser</h1>"
            + "<p id=\"desc\"></p>"
            + "<button class=\"btn\" id=\"go\">Open sign-in in browser</button>"
            + "<button class=\"btn2\" id=\"cp\">Copy sign-in link</button>"
            + "<div class=\"spin\" id=\"sp\"></div>"
            + "<div class=\"status\" id=\"st\"></div>"
            + "<p class=\"hint\">Your browser should open automatically. If it doesn't, tap <b>Open sign-in in browser</b> — or <b>Copy sign-in link</b>, paste it into Chrome and sign in. Then return to this screen; it finishes automatically.</p>"
            + "<input class=\"url\" id=\"u\" readonly onclick=\"this.select()\">"
            + "</div><script>(function(){"
            + "var au=" + authJson + ",intent=" + intentJson + ",name=" + nameJson + ",pt=" + pollJson + ";"
            + "var done=false,tries=0,MAX=140;"
            + "function st(m){document.getElementById('st').textContent=m;}"
            + "document.getElementById('desc').textContent='For security, '+name+' blocks sign-in inside apps. Open the sign-in in your phone\\u2019s browser; this screen finishes automatically when you\\u2019re done.';"
            + "document.getElementById('u').value=au;"
            + "var isAndroid=/Android/i.test(navigator.userAgent);"
            // CRITICAL: open the browser via window.open ONLY — NEVER navigate
            // the main frame (window.location). The Jellyfin Android app's
            // webview treats a top-frame navigation to an external/intent URL
            // as a lost server connection and bounces to the server-select
            // screen (issue #64 loop). window.open either spawns an external
            // window or harmlessly no-ops; it never resets the app. If it
            // no-ops, the Copy-link button is the reliable path.
            + "function go(){document.getElementById('sp').style.display='block';"
            + "st('Opening your browser\\u2026 approve sign-in there, then return to this screen.');"
            // The Jellyfin app injects NativeShell/NativeInterface — its
            // app-sanctioned bridge to open an external URL (fires an Android
            // Intent -> system browser). Plain window.open / window.location
            // get hijacked into a main-frame navigation and bounce the app to
            // its server-select screen (issue #64), so use the bridge first.
            + "try{if(window.NativeShell&&typeof window.NativeShell.openUrl==='function'){window.NativeShell.openUrl(au,'_blank');return;}}catch(e){}"
            + "try{if(window.NativeInterface&&typeof window.NativeInterface.openUrl==='function'){window.NativeInterface.openUrl(au);return;}}catch(e){}"
            + "try{window.open(au,'_blank');}catch(e){}"
            + "try{window.open(au,'_system');}catch(e){}}"
            + "document.getElementById('go').addEventListener('click',go);"
            // Auto-open through the native bridge when present — gives the app
            // the automatic 'redirect' UX (native bridge calls aren't gated by
            // a user gesture). Falls back to the visible buttons otherwise.
            + "try{if((window.NativeShell&&window.NativeShell.openUrl)||(window.NativeInterface&&window.NativeInterface.openUrl)){setTimeout(go,300);}}catch(e){}"
            + "function copied(){document.getElementById('sp').style.display='block';st('Link copied \\u2014 open Chrome, paste it, and sign in. Then return to this screen.');}"
            + "document.getElementById('cp').addEventListener('click',function(){"
            + "try{navigator.clipboard.writeText(au).then(copied,function(){var i=document.getElementById('u');i.focus();i.select();try{document.execCommand('copy');}catch(_){}copied();});}"
            + "catch(e){var i=document.getElementById('u');i.focus();i.select();try{document.execCommand('copy');}catch(_){}copied();}"
            + "});"
            + "if(isAndroid){void intent;}"
            // Device-poll: once the browser side completes the callback, this
            // returns the one-shot bridge token; complete login like the
            // browser bridge page (AuthenticateByName -> localStorage -> /web).
            + "function complete(u,t){"
            + "var did=(function(){try{var x=localStorage.getItem('_deviceId2');if(!x){x=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function(b){return b.toString(16).padStart(2,'0');}).join('');localStorage.setItem('_deviceId2',x);}return x;}catch(e){return 'bridge-'+Date.now();}})();"
            + "var auth='MediaBrowser Client=\"Jellyfin Web\", Device=\"Browser\", DeviceId=\"'+did+'\", Version=\"10.11.0\"';"
            + "fetch('/Users/AuthenticateByName',{method:'POST',headers:{'Content-Type':'application/json','X-Emby-Authorization':auth,'Authorization':auth},body:JSON.stringify({Username:u,Pw:t})})"
            + ".then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})"
            + ".then(function(res){"
            + "var server={Id:res.ServerId,Name:'Jellyfin',AccessToken:res.AccessToken,UserId:res.User.Id,Type:'Server',DateLastAccessed:Date.now(),LastConnectionMode:1,ManualAddress:window.location.origin,LocalAddress:window.location.origin};"
            + "localStorage.setItem('jellyfin_credentials',JSON.stringify({Servers:[server]}));"
            + "st('Signed in as '+res.User.Name+' \\u2014 opening Jellyfin\\u2026');"
            + "setTimeout(function(){window.location.href='/web/index.html';},400);"
            + "}).catch(function(e){st('Sign-in failed: '+e.message);});"
            + "}"
            + "function poll(){"
            + "if(done)return;"
            + "if(tries++>MAX){st('Timed out \\u2014 tap the button to try again.');return;}"
            + "fetch('/TwoFactorAuth/Oidc/DevicePoll?pt='+encodeURIComponent(pt),{headers:{'Accept':'application/json'}})"
            + ".then(function(r){return r.json();})"
            + ".then(function(j){if(j&&j.ready){done=true;document.getElementById('sp').style.display='block';st('Finishing sign-in\\u2026');complete(j.username,j.token);}else{setTimeout(poll,2500);}})"
            + ".catch(function(){setTimeout(poll,2500);});"
            + "}"
            + "poll();"
            + "})();</script></body></html>";
    }

    /// <summary>[v2.5.9] (issue #64): the page the EXTERNAL browser lands on
    /// after completing an app-initiated (device-poll) OIDC sign-in. The
    /// session belongs to the app, not this browser tab — so instead of
    /// logging the browser in, tell the user to switch back to the app (which
    /// is polling and will finish automatically).</summary>
    private static string BuildDeviceReturnHtml()
    {
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            + "<title>Signed in</title><style>"
            + "body{background:#0a0a0a;color:#e6e6e6;font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}"
            + ".card{background:#16181c;border:1px solid #2a2d33;border-radius:14px;max-width:420px;width:100%;padding:32px 28px;box-sizing:border-box;text-align:center;}"
            + ".ok{font-size:42px;line-height:1;margin-bottom:12px;}h1{font-size:21px;margin:0 0 12px;}"
            + "p{color:#aeb4bd;line-height:1.5;font-size:15px;margin:0;}"
            + "</style></head><body><div class=\"card\">"
            + "<div class=\"ok\">✅</div>"
            + "<h1>You’re signed in</h1>"
            + "<p>Switch back to your Jellyfin app — it will finish signing you in automatically. You can close this tab.</p>"
            + "</div></body></html>";
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

    private string BuildRedirectUri(OidcProvider provider)
    {
        // SECURITY: X-Forwarded-Host/Proto are ONLY trusted when the direct
        // peer is a configured trusted-proxy CIDR. Otherwise we'd accept any
        // attacker-sent host header and hand it to the IdP as redirect_uri —
        // the IdP would reject it (not a registered URI), but it lets an
        // attacker poison the flow. Fall back to Request.Host when unverified.
        var cfg = Plugin.Instance?.Configuration;
        var peer = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        var trustedCidrs = (IReadOnlyList<string>?)cfg?.TrustedProxyCidrs ?? Array.Empty<string>();

        // [v2.5.6] (issue #28): if the IdP's discovery URL is https, the
        // callback MUST be https too — every real IdP rejects an http
        // redirect_uri against a registered https origin. Infer ForceHttps
        // when the provider's DiscoveryUrl starts with https://, so
        // existing providers created on v2.5.4/v2.5.5 with ForceHttps=false
        // also get the right scheme on upgrade without the admin having to
        // flip a hidden toggle. The explicit ForceHttps=true setting
        // still wins; this only adds a sane fallback when the admin left
        // it false but the IdP is clearly https-only.
        var inferHttps = provider.ForceHttps
            || (!string.IsNullOrEmpty(provider.DiscoveryUrl)
                && provider.DiscoveryUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase));

        return OidcRedirectUriBuilder.Build(
            directScheme: Request.Scheme,
            directHost: Request.Host.ToString(),
            forwardedProto: Request.Headers.TryGetValue("X-Forwarded-Proto", out var p) ? p.ToString() : null,
            forwardedHost: Request.Headers.TryGetValue("X-Forwarded-Host", out var h) ? h.ToString() : null,
            peer: peer,
            trustedCidrs: trustedCidrs,
            providerId: provider.Id,
            forceHttps: inferHttps);
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

    // =========================================================================
    // PASSKEY PRIMARY LOGIN (v2.1) — username + passkey, no password prompt
    // =========================================================================

    public class PasskeyLoginBeginRequest { [Required] public string Username { get; set; } = string.Empty; }
    public class PasskeyLoginCompleteRequest
    {
        [Required] public string Username { get; set; } = string.Empty;
        [Required] public string Nonce { get; set; } = string.Empty;
        [Required] public string Response { get; set; } = string.Empty;
    }

    [HttpPost("Passkey/LoginBegin")]
    [AllowAnonymous]
    public async Task<IActionResult> PasskeyLoginBegin([FromBody, Required] PasskeyLoginBeginRequest req)
    {
        // Rate limit before touching user data — an unauthenticated attacker
        // hitting this endpoint could enumerate which usernames have passkeys.
        // Returning identical shape regardless of username validity would be
        // better but Fido2NetLib's allowCredentials list is user-specific.
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_bans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        var rl = _rateLimiter.CheckAndRecord("passkey_login:" + ip, 20, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds}s.",
            });
        }

        // SECURITY [v2.5.5] (Finding 11): equalize timing for the user-
        // does-not-exist vs user-exists-but-no-passkey paths so a low-
        // and-slow probe can't enumerate which usernames have passkeys
        // by measuring response time. Both paths now perform an equivalent
        // GetUserDataAsync(...) call (dummy GUID for the no-user case) and
        // return the same 404 response body.
        var user = _userManager.GetUserByName(req.Username);
        var lookupId = user?.Id ?? Guid.Empty;
        var data = await _store.GetUserDataAsync(lookupId).ConfigureAwait(false);
        if (user is null || data.Passkeys.Count == 0)
        {
            return NotFound(new { message = "No passkey registered for this user." });
        }
        if (!await _allowlist.IsAllowedAsync(user.Id, clientIp).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        var optionsJson = _passkeys.BuildAssertionOptions(HttpContext, data.Passkeys);
        var nonce = _passkeyChallenges.Begin(optionsJson, user.Id);

        // Return raw options JSON; the browser parses it and converts base64url
        // challenge / credential-id fields to ArrayBuffers before calling
        // navigator.credentials.get().
        return Ok(new { options = optionsJson, nonce });
    }

    [HttpPost("Passkey/LoginComplete")]
    [AllowAnonymous]
    public async Task<IActionResult> PasskeyLoginComplete([FromBody, Required] PasskeyLoginCompleteRequest req)
    {
        var ip = RateLimiter.ClientKey(HttpContext);
        var clientIp = BypassEvaluator.ResolveClientIp(HttpContext) ?? ip;
        if (_bans.CheckBanned(clientIp) is { } ban)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "This IP address is temporarily blocked.",
                expiresAt = ban.ExpiresAt,
            });
        }

        // SECURITY [v2.5.5] (Finding 15): explicit per-IP rate limit on the
        // verify endpoint. The Begin endpoint already enforces 20/5min/IP
        // (which constrains the nonce-mint rate), but each minted nonce
        // could only be burned by one call to Complete — without this
        // explicit limiter a misconfigured Begin (or a client retry loop)
        // could land more assertion-verify attempts than expected on the
        // PasskeyService.CompleteAssertionAsync code path.
        var rl = _rateLimiter.CheckAndRecord("passkey_complete:" + ip, 20, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds}s.",
            });
        }

        var user = _userManager.GetUserByName(req.Username);
        if (user is null)
        {
            _logger.LogWarning("[2FA] Passkey login: unknown username {User}", req.Username);
            _bans.RecordFailure(clientIp);
            return Unauthorized(new { message = "Passkey verification failed." });
        }

        if (!await _allowlist.IsAllowedAsync(user.Id, clientIp).ConfigureAwait(false))
        {
            _bans.RecordFailure(clientIp);
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Sign-in is not allowed from this network.",
            });
        }

        var (optionsJson, storedUserId) = _passkeyChallenges.Consume(req.Nonce);
        if (optionsJson is null || storedUserId != user.Id)
        {
            _logger.LogWarning("[2FA] Passkey login: nonce mismatch for {User}", req.Username);
            _bans.RecordFailure(clientIp);
            // SECURITY [v2.5.5] (Finding 15): also record per-user failure
            // so the existing per-user lockout machinery picks this up. An
            // attacker rotating source IPs to evade the IP-bucket still hits
            // the per-user bucket and gets the account locked after the
            // configured threshold.
            await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
            return Unauthorized(new { message = "Passkey verification failed." });
        }

        bool ok;
        try
        {
            ok = await _passkeys.CompleteAssertionAsync(HttpContext, user.Id, optionsJson, req.Response).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Passkey assertion verify threw");
            _bans.RecordFailure(clientIp);
            await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
            return Unauthorized(new { message = "Passkey verification failed." });
        }
        if (!ok)
        {
            _bans.RecordFailure(clientIp);
            await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
            return Unauthorized(new { message = "Passkey verification failed." });
        }

        _bans.RecordSuccess(clientIp);

        // Reuse the OIDC bridge-token mechanism — mint a 60-second one-shot
        // token, the caller submits it as the password to /Users/AuthenticateByName,
        // TwoFactorAuthProvider consumes it and signs the user in with no
        // password + no further 2FA challenge. Same security guarantees as OIDC.
        var token = _oidcBridge.Mint(user.Id, user.Username ?? req.Username, "passkey");

        // Route this user's auth through our provider (same as OIDC flow).
        try
        {
            var ourProviderId = typeof(TwoFactorAuthProvider).FullName!;
            if (!string.Equals(user.AuthenticationProviderId, ourProviderId, StringComparison.Ordinal))
            {
                user.AuthenticationProviderId = ourProviderId;
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Passkey login: could not reassign AuthenticationProviderId for {User}", req.Username);
        }

        _logger.LogInformation("[2FA] Passkey primary sign-in for {User}", req.Username);
        return Ok(new { username = user.Username, token });
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

    // SECURITY [v2.5.5] (Finding 2): strict validator for the OIDC returnUrl
    // query parameter. Rejects anything that isn't a same-origin relative
    // path. The encoded-control-character check catches `%0d`, `%0a`, `%00`,
    // `%5c` (backslash), and their uppercase variants — closing the
    // header-injection / open-redirect class even if the value is later
    // surfaced in a `Location:` / `Refresh:` header by a future refactor.
    // Backslash is also blocked literally (some browser URL parsers treat
    // `\\evil.com` as an absolute URL when concatenated after `https:`).
    private static readonly System.Text.RegularExpressions.Regex _safeRelativePathRegex =
        new(@"^/[A-Za-z0-9/_\-.~?=&%+@!$',;:()*]*$",
            System.Text.RegularExpressions.RegexOptions.Compiled,
            TimeSpan.FromMilliseconds(50));

    private static bool IsSafeRelativePath(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        if (value.Length > 1024) return false;
        if (!value.StartsWith('/')) return false;
        if (value.StartsWith("//", StringComparison.Ordinal)) return false; // protocol-relative
        if (value.Contains('\\', StringComparison.Ordinal)) return false;   // backslash variants
        // Reject any control character (CR/LF/NUL/TAB/etc.)
        foreach (var ch in value)
        {
            if (char.IsControl(ch)) return false;
        }
        // Reject percent-encoded control / backslash / fragment sequences
        // SECURITY [v2.5.6] (third-audit Finding 9 / fourth-audit A6):
        // added %23 (#) — fragment-confusion if the value ever reaches a
        // Location header. Older builds blocked %0a/%0d/%00/%09/%5c only.
        var lower = value.ToLowerInvariant();
        if (lower.Contains("%0a", StringComparison.Ordinal)
            || lower.Contains("%0d", StringComparison.Ordinal)
            || lower.Contains("%00", StringComparison.Ordinal)
            || lower.Contains("%09", StringComparison.Ordinal)
            || lower.Contains("%5c", StringComparison.Ordinal)
            || lower.Contains("%23", StringComparison.Ordinal))
        {
            return false;
        }
        // Final strict allowlist match (covers query, fragment, common path chars).
        try
        {
            return _safeRelativePathRegex.IsMatch(value);
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            return false;
        }
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

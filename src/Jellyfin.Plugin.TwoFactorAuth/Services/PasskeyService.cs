using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// FIDO2 / WebAuthn server logic for the plugin. Implemented as a thin shell
/// around Fido2NetLib so that all crypto / CBOR / attestation parsing is
/// delegated to the upstream library — we only handle config, storage, and
/// the per-user credential list.
///
/// Design choice: passkey is an ADDITIVE 2nd factor, not a replacement for
/// Jellyfin's username+password step. Jellyfin's IAuthenticationProvider is
/// not a clean place to swap an attestation assertion for a password (the
/// signature is `Authenticate(string username, string password)` with no
/// attestation channel), so v1.4 keeps password as primary and lets passkey
/// satisfy the 2FA challenge step alongside TOTP / email / recovery.
/// </summary>
public class PasskeyService
{
    private readonly UserTwoFactorStore _store;
    private readonly ILogger<PasskeyService> _logger;

    public PasskeyService(UserTwoFactorStore store, ILogger<PasskeyService> logger)
    {
        _store = store;
        _logger = logger;
    }

    /// <summary>Build a Fido2 instance scoped to the live request. RP ID is
    /// derived from the public-facing host the BROWSER sees, not the host
    /// Jellyfin sees internally — these differ behind Cloudflare/nginx, and
    /// WebAuthn fails closed if RP ID doesn't exactly match the page origin.
    ///
    /// Derivation order:
    ///  1. Admin-supplied WebAuthnRpId (explicit override — wins)
    ///  2. X-Forwarded-Host header value (only honoured when TrustForwardedFor
    ///     is set and direct peer is in TrustedProxyCidrs)
    ///  3. context.Request.Host.Host (direct connection)
    /// Same priority for scheme via X-Forwarded-Proto.</summary>
    private IFido2 BuildFido2(HttpContext context)
    {
        var config = Plugin.Instance?.Configuration;

        // Derive the public-facing host the browser actually used.
        string host = context.Request.Host.Host;
        string scheme = context.Request.Scheme;
        int? port = context.Request.Host.Port;

        if (config is { TrustForwardedFor: true } && config.TrustedProxyCidrs.Length > 0)
        {
            var peer = context.Connection.RemoteIpAddress?.ToString();
            var peerTrusted = false;
            if (!string.IsNullOrEmpty(peer))
            {
                foreach (var cidr in config.TrustedProxyCidrs)
                {
                    if (BypassEvaluator.IsIpInCidr(peer, cidr)) { peerTrusted = true; break; }
                }
            }
            if (peerTrusted)
            {
                var fwdHost = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault();
                var fwdProto = context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(fwdHost))
                {
                    // X-Forwarded-Host may be host:port; split.
                    var hp = fwdHost.Split(':', 2);
                    host = hp[0];
                    port = hp.Length == 2 && int.TryParse(hp[1], out var p) ? p : null;
                }
                if (!string.IsNullOrWhiteSpace(fwdProto)) scheme = fwdProto;
            }
        }

        var rpId = !string.IsNullOrWhiteSpace(config?.WebAuthnRpId)
            ? config.WebAuthnRpId!
            : host;

        // Origin string for the WebAuthn library — must EXACTLY match what
        // the browser sees in window.location.origin. Default ports omitted
        // by browsers, so omit them here too.
        string originStr;
        var defaultPort = string.Equals(scheme, "https", StringComparison.OrdinalIgnoreCase) ? 443 : 80;
        if (port is null || port == defaultPort)
        {
            originStr = $"{scheme}://{host}";
        }
        else
        {
            originStr = $"{scheme}://{host}:{port}";
        }

        var origins = (config?.WebAuthnOrigins.Length ?? 0) > 0
            ? new HashSet<string>(config!.WebAuthnOrigins, StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal) { originStr };

        _logger.LogInformation("[2FA] WebAuthn config: rpId={RpId} origin={Origin} (host={Host} scheme={Scheme} fwdHost={FwdHost} fwdProto={FwdProto})",
            rpId, originStr, host, scheme,
            context.Request.Headers["X-Forwarded-Host"].FirstOrDefault() ?? "(none)",
            context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault() ?? "(none)");

        return new Fido2(new Fido2Configuration
        {
            ServerDomain = rpId,
            ServerName = "Jellyfin",
            Origins = origins,
            // Soft fail keeps registration usable for authenticators that fail
            // attestation root path lookups (FIDO MDS not bundled). The crypto
            // is still verified end-to-end; only the metadata trust bit is
            // best-effort.
            TimestampDriftTolerance = 300_000,
        });
    }

    /// <summary>Begin a registration ceremony. Returns the JSON the browser
    /// passes to navigator.credentials.create() and the server-side nonce the
    /// browser must echo back on Finish.</summary>
    public string BuildRegistrationOptions(HttpContext context, Guid userId, string username, IReadOnlyList<PasskeyCredential> existing)
    {
        var fido2 = BuildFido2(context);
        var fidoUser = new Fido2User
        {
            Id = userId.ToByteArray(),
            Name = username,
            DisplayName = username,
        };

        var excludeCreds = existing.Select(c => new PublicKeyCredentialDescriptor(Base64UrlDecode(c.CredentialId))).ToList();

        var options = fido2.RequestNewCredential(
            fidoUser,
            excludeCreds,
            AuthenticatorSelection.Default,
            AttestationConveyancePreference.None,
            new AuthenticationExtensionsClientInputs());

        return options.ToJson();
    }

    // SEC-L1: hard cap on registered passkeys per user. WebAuthn registration
    // is auth-allowed by design and a buggy or malicious client could spam
    // the endpoint to inflate the user record. 20 is generous — most users
    // register 1-3 passkeys (phone biometric + laptop + hardware key).
    public const int MaxPasskeysPerUser = 20;

    /// <summary>Validate the browser's attestation response and append the new
    /// credential to the user's record.</summary>
    public async Task<PasskeyCredential> CompleteRegistrationAsync(
        HttpContext context, Guid userId, string optionsJson, string responseJson, string label)
    {
        // SEC-L1: enforce cap before doing the expensive crypto work.
        var existing = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        if (existing.Passkeys.Count >= MaxPasskeysPerUser)
        {
            throw new InvalidOperationException(
                $"Passkey limit reached ({MaxPasskeysPerUser}). Revoke an existing passkey before adding another.");
        }

        var fido2 = BuildFido2(context);
        var options = CredentialCreateOptions.FromJson(optionsJson);
        var raw = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(
            responseJson,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Malformed attestation response");

        // Library callback verifies the credential ID isn't already registered
        // for ANY user in the store. Fast path here since Jellyfin's user
        // base is small; for very large servers this would warrant an index.
        async Task<bool> IsCredentialIdUnique(IsCredentialIdUniqueToUserParams p, CancellationToken _)
        {
            var b64 = Base64UrlEncode(p.CredentialId);
            var all = await _store.GetAllUsersAsync().ConfigureAwait(false);
            foreach (var data in all)
            {
                if (data.Passkeys.Any(c => string.Equals(c.CredentialId, b64, StringComparison.Ordinal)))
                    return false;
            }
            return true;
        }

        var success = await fido2.MakeNewCredentialAsync(raw, options, IsCredentialIdUnique).ConfigureAwait(false);
        if (success.Result is null)
        {
            throw new InvalidOperationException("Attestation failed: " + (success.ErrorMessage ?? "unknown"));
        }

        var credential = new PasskeyCredential
        {
            Id = Guid.NewGuid().ToString("N"),
            CredentialId = Base64UrlEncode(success.Result.CredentialId),
            PublicKeyCose = Convert.ToBase64String(success.Result.PublicKey),
            SignatureCounter = success.Result.Counter,
            Aaguid = success.Result.Aaguid.ToString(),
            Label = string.IsNullOrWhiteSpace(label) ? "Passkey" : label.Trim(),
            Transports = string.Empty,
            CreatedAt = DateTime.UtcNow,
        };

        await _store.MutateAsync(userId, ud =>
        {
            ud.Passkeys.Add(credential);
        }).ConfigureAwait(false);

        return credential;
    }

    /// <summary>Begin an assertion ceremony for an authenticated user (the
    /// challenge step happens AFTER username+password, so userId is known).
    /// Returns the JSON for navigator.credentials.get().</summary>
    public string BuildAssertionOptions(HttpContext context, IReadOnlyList<PasskeyCredential> userCreds)
    {
        var fido2 = BuildFido2(context);
        var allow = userCreds.Select(c => new PublicKeyCredentialDescriptor(Base64UrlDecode(c.CredentialId))).ToList();
        var options = fido2.GetAssertionOptions(
            allow,
            UserVerificationRequirement.Preferred,
            new AuthenticationExtensionsClientInputs());
        return options.ToJson();
    }

    /// <summary>Validate the browser's assertion. Updates the credential's
    /// signature counter on success — a regression in counter indicates a
    /// cloned authenticator and is rejected by Fido2NetLib.</summary>
    public async Task<bool> CompleteAssertionAsync(
        HttpContext context, Guid userId, string optionsJson, string responseJson)
    {
        var fido2 = BuildFido2(context);
        var options = AssertionOptions.FromJson(optionsJson);
        var raw = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(
            responseJson,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Malformed assertion response");

        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var idB64 = Base64UrlEncode(raw.RawId);
        var stored = data.Passkeys.FirstOrDefault(c => string.Equals(c.CredentialId, idB64, StringComparison.Ordinal));
        if (stored is null) return false;

        async Task<bool> IsUserHandleOwnerOfCredentialId(IsUserHandleOwnerOfCredentialIdParams p, CancellationToken _)
        {
            // The user handle is the userId.ToByteArray() we registered; check
            // it back against the requesting user.
            try
            {
                var handleGuid = new Guid(p.UserHandle);
                return handleGuid == userId;
            }
            catch
            {
                return false;
            }
        }

        var publicKey = Convert.FromBase64String(stored.PublicKeyCose);
        var result = await fido2.MakeAssertionAsync(
            raw, options, publicKey, stored.SignatureCounter, IsUserHandleOwnerOfCredentialId)
            .ConfigureAwait(false);

        if (result.Status != "ok") return false;

        // Persist counter + LastUsedAt so a future replay/clone with the old
        // counter is rejected.
        await _store.MutateAsync(userId, ud =>
        {
            var p = ud.Passkeys.FirstOrDefault(c => string.Equals(c.CredentialId, idB64, StringComparison.Ordinal));
            if (p is not null)
            {
                p.SignatureCounter = result.Counter;
                p.LastUsedAt = DateTime.UtcNow;
            }
        }).ConfigureAwait(false);

        return true;
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }
}

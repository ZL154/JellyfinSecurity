using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class NotificationService
{
    // SECURITY [v2.5.6] (ext review #7): the prior unpinned _httpClient was
    // removed. All outbound notification HTTP now flows through
    // _webhookHttpClient with per-call address pinning so ntfy / Gotify /
    // webhook share the same SSRF guarantees.
    private readonly ILogger<NotificationService> _logger;

    // SEC-M2: list of pre-validated allowed IPs for the webhook send currently
    // in flight. ConnectCallback consults this on the actual TCP connect —
    // which happens AFTER .NET's socket layer does its own DNS lookup — so a
    // DNS-rebinding attacker who flips the record between IsSafeWebhookUrl's
    // resolution and the connect is rejected at the boundary.
    // SEC-M2: must flow across awaits — the HttpClient ConnectCallback runs on
    // a thread-pool thread that's NOT guaranteed to be the same thread that
    // called SendAsync, so [ThreadStatic] silently dropped the pinned set after
    // the first continuation. AsyncLocal flows the value through the async
    // execution context so the SSRF guard sees the right set on every connect.
    private static readonly System.Threading.AsyncLocal<System.Net.IPAddress[]?> _pinnedAllowedAddresses = new();

    private static readonly HttpClient _webhookHttpClient = BuildPinnedHttpClient();

    private static HttpClient BuildPinnedHttpClient()
    {
        var handler = new System.Net.Http.SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = async (ctx, ct) =>
            {
                var allowed = _pinnedAllowedAddresses.Value;
                if (allowed is null || allowed.Length == 0)
                {
                    throw new System.Net.Sockets.SocketException(
                        (int)System.Net.Sockets.SocketError.ConnectionRefused);
                }
                System.Net.IPAddress[] resolved;
                try
                {
                    resolved = await System.Net.Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct).ConfigureAwait(false);
                }
                catch
                {
                    throw new System.Net.Sockets.SocketException(
                        (int)System.Net.Sockets.SocketError.HostNotFound);
                }
                // [v2.5.17] (#116): connect-time re-resolution is the DNS-rebinding
                // defence. Link-local / cloud-metadata is rejected unconditionally;
                // other private/loopback is rejected only when the admin has NOT
                // opted into private notification targets. Either way the address
                // must still be in the pinned `allowed` set vetted at dispatch time,
                // so opting in cannot be abused to reach an unpinned host.
                var allowPrivateConnect = Plugin.Instance?.Configuration?.AllowPrivateNotificationTargets ?? false;
                System.Net.IPAddress? pick = null;
                foreach (var ip in resolved)
                {
                    if (IsAlwaysBlockedAddress(ip)) continue;
                    if (!allowPrivateConnect && IsPrivateOrLoopback(ip)) continue;
                    foreach (var safe in allowed)
                    {
                        if (ip.Equals(safe)) { pick = ip; break; }
                    }
                    if (pick is not null) break;
                }
                if (pick is null)
                {
                    throw new System.Net.Sockets.SocketException(
                        (int)System.Net.Sockets.SocketError.ConnectionRefused);
                }
                var sock = new System.Net.Sockets.Socket(
                    pick.AddressFamily, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                try
                {
                    await sock.ConnectAsync(new System.Net.IPEndPoint(pick, ctx.DnsEndPoint.Port), ct).ConfigureAwait(false);
                    return new System.Net.Sockets.NetworkStream(sock, ownsSocket: true);
                }
                catch
                {
                    sock.Dispose();
                    throw;
                }
            },
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
    }

    public NotificationService(ILogger<NotificationService> logger)
    {
        _logger = logger;
    }

    public async Task NotifyLoginAttemptAsync(string username, string remoteIp, string deviceName, bool requiresTwoFactor)
    {
        var title = "2FA Login Attempt";
        var message = $"2FA login attempt from {username} at {remoteIp} ({deviceName})";
        await SendToAllBackendsAsync(title, message, "login_attempt", new
        {
            username, remoteIp, deviceName, requiresTwoFactor
        }).ConfigureAwait(false);
    }

    public async Task NotifyFailedAttemptsAsync(string username, string remoteIp, int attemptCount)
    {
        var title = "2FA Failed Attempts Warning";
        var message = $"Warning: {attemptCount} failed 2FA attempts for {username} from {remoteIp}";
        await SendToAllBackendsAsync(title, message, "failed_attempts", new
        {
            username, remoteIp, attemptCount
        }).ConfigureAwait(false);
    }

    public async Task NotifyPairingRequestAsync(string username, string deviceName, string pairingCode)
    {
        var title = "TV Pairing Request";
        var message = $"TV pairing request from {username} ({deviceName}). Code: {pairingCode}";
        await SendToAllBackendsAsync(title, message, "pairing_request", new
        {
            username, deviceName, pairingCode
        }).ConfigureAwait(false);
    }

    public async Task NotifyPairingCompletedAsync(string username, string deviceName, bool approved)
    {
        var title = approved ? "TV Pairing Approved" : "TV Pairing Denied";
        var message = approved
            ? $"TV pairing approved for {username} ({deviceName})"
            : $"TV pairing denied for {username} ({deviceName})";
        await SendToAllBackendsAsync(title, message,
            approved ? "pairing_approved" : "pairing_denied",
            new { username, deviceName, approved }).ConfigureAwait(false);
    }

    /// <summary>v1.4: novel ASN+country combo for this user. Fired by
    /// SuspiciousLoginDetector before the challenge response is returned —
    /// fire-and-forget at the call site, this method is bounded by the 5s
    /// HttpClient timeout.</summary>
    public async Task NotifySuspiciousLoginAsync(string username, string ip, string country, string asnOrg, uint asn)
    {
        var locationDesc = string.IsNullOrEmpty(country) ? asnOrg : $"{country} via {asnOrg}";
        if (string.IsNullOrEmpty(locationDesc)) locationDesc = "an unknown network";
        var title = "Sign-in from a new location";
        var message = $"{username} signed in from {locationDesc} (IP {ip}). If this wasn't you, change your password and disable trusted devices.";
        await SendToAllBackendsAsync(title, message, "suspicious_login", new
        {
            username, ip, country, asnOrg, asn
        }).ConfigureAwait(false);
    }

    /// <summary>v1.4: emergency self-service lockout fired.</summary>
    public async Task NotifyEmergencyLockoutAsync(string username, string ip)
    {
        var title = "Account locked by user";
        var message = $"{username} triggered emergency lockout from {ip}. All sessions terminated; recovery code required to sign in.";
        await SendToAllBackendsAsync(title, message, "emergency_lockout", new { username, ip }).ConfigureAwait(false);
    }

    /// <summary>v1.4: admin force-logged-out a user.</summary>
    public async Task NotifyAdminForceLogoutAsync(string username, string adminName, int sessionsKilled)
    {
        var title = "Admin force-logout";
        var message = $"{adminName} force-logged-out {username} ({sessionsKilled} sessions terminated).";
        await SendToAllBackendsAsync(title, message, "admin_force_logout", new
        {
            username, adminName, sessionsKilled
        }).ConfigureAwait(false);
    }

    /// <summary>v1.4: fired when a user creates a new passkey.</summary>
    public async Task NotifyPasskeyRegisteredAsync(string username, string label, string ip)
    {
        var title = "New passkey registered";
        var message = $"{username} registered a new passkey '{label}' from {ip}.";
        await SendToAllBackendsAsync(title, message, "passkey_registered", new { username, label, ip }).ConfigureAwait(false);
    }

    /// <summary>v1.4: fired when a user rotates their TOTP secret. Symmetric
    /// with NotifyPasskeyRegisteredAsync — both are "your 2nd factor changed,
    /// did you do this?" alerts.</summary>
    public async Task NotifyTotpRotatedAsync(string username, string ip)
    {
        var title = "TOTP secret rotated";
        var message = $"{username} rotated their TOTP authenticator secret from {ip}. If this wasn't you, your account may be compromised — emergency-lockout from Setup.";
        await SendToAllBackendsAsync(title, message, "totp_rotated", new { username, ip }).ConfigureAwait(false);
    }

    /// <summary>v1.4: fired on a recovery code consume (not on every code, just the first time of a session).</summary>
    public async Task NotifyRecoveryCodeUsedAsync(string username, string ip, int remaining)
    {
        var title = "Recovery code used";
        var message = $"{username} signed in with a recovery code from {ip}. {remaining} remain.";
        await SendToAllBackendsAsync(title, message, "recovery_code_used", new { username, ip, remaining }).ConfigureAwait(false);
    }

    /// <summary>Centralised dispatch — sends to ntfy, Gotify, the configured
    /// webhook (with optional HMAC signature), and logs a stub for email.
    /// `event` is the machine-readable type for webhook consumers; `payload`
    /// is an event-specific bag serialised into the webhook body.</summary>
    private async Task SendToAllBackendsAsync(string title, string message, string @event, object payload)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(config.NtfyUrl) && !string.IsNullOrWhiteSpace(config.NtfyTopic))
        {
            // SECURITY [v2.5.6] (ext review #7): apply the same SSRF guard
            // ntfy got NONE of before. Previously used the unpinned
            // `_httpClient`, which would happily POST title+message to
            // anything an admin (or attacker who compromised the admin
            // config) pasted — including AWS IMDS, Docker host gateways,
            // internal admin panels. Route through `_webhookHttpClient`
            // with pinned, validated addresses so DNS rebinding cannot
            // flip the destination between resolve and connect.
            var ntfyAddrs = GetSafeWebhookAddresses(config.NtfyUrl);
            if (ntfyAddrs is { Length: > 0 })
            {
                try
                {
                    // [v2.5.17] (#116, Arson31) ntfy publishes by POSTing to
                    // {server}/{topic} — the topic is a URL path segment, NOT a
                    // header. The previous code POSTed to the bare base URL with a
                    // non-existent "X-Topic" header, so self-hosted (and ntfy.sh)
                    // instances received a message with no topic and dropped it —
                    // the test notification never arrived. Build the publish URL
                    // from the base + topic; tolerate an admin who already put the
                    // topic in the URL so we don't double it. Host is unchanged, so
                    // the SSRF address-pinning above still applies.
                    var ntfyBase = config.NtfyUrl.TrimEnd('/');
                    var ntfyTopic = config.NtfyTopic.Trim();
                    var ntfyPublishUrl = ntfyBase.EndsWith("/" + ntfyTopic, StringComparison.OrdinalIgnoreCase)
                        ? ntfyBase
                        : ntfyBase + "/" + Uri.EscapeDataString(ntfyTopic);
                    using var request = new HttpRequestMessage(HttpMethod.Post, ntfyPublishUrl);
                    request.Headers.TryAddWithoutValidation("X-Title", title);
                    request.Content = new StringContent(message, Encoding.UTF8, "text/plain");
                    _pinnedAllowedAddresses.Value = ntfyAddrs;
                    try
                    {
                        using var response = await _webhookHttpClient.SendAsync(request).ConfigureAwait(false);
                    }
                    finally
                    {
                        _pinnedAllowedAddresses.Value = null;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError("Failed to send Ntfy notification: {Type}: {Msg}",
                        ex.GetType().Name, ex.Message);
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(config.GotifyUrl) && !string.IsNullOrWhiteSpace(config.GotifyAppToken))
        {
            // SECURITY [v2.5.6] (F5-A7): pass the token via X-Gotify-Key
            // header instead of embedding in the URL. URL form leaked the
            // token into HttpRequestException.Message on transport failure
            // and into any log sink the admin had attached.
            // SECURITY [v2.5.6] (ext review #7): also apply SSRF guard +
            // pinned HttpClient — Gotify had none. An admin who configured
            // GotifyUrl pointing to a private/loopback address would
            // exfiltrate the X-Gotify-Key header to that destination on
            // every notification. Pinning to a public-only validated set
            // closes the SSRF/DNS-rebind class.
            var gotifyBase = $"{config.GotifyUrl.TrimEnd('/')}/message";
            var gotifyAddrs = GetSafeWebhookAddresses(gotifyBase);
            if (gotifyAddrs is { Length: > 0 })
            {
                try
                {
                    var gotifyPayload = new { title, message, priority = 5 };
                    using var req = new HttpRequestMessage(HttpMethod.Post, gotifyBase)
                    {
                        Content = JsonContent.Create(gotifyPayload),
                    };
                    req.Headers.Add("X-Gotify-Key", config.GotifyAppToken);
                    _pinnedAllowedAddresses.Value = gotifyAddrs;
                    try
                    {
                        using var response = await _webhookHttpClient.SendAsync(req).ConfigureAwait(false);
                    }
                    finally
                    {
                        _pinnedAllowedAddresses.Value = null;
                    }
                }
                catch (Exception ex)
                {
                    // Log type + message only; don't pass the exception object
                    // (which serialises the Request and could re-leak the URL).
                    _logger.LogError("Failed to send Gotify notification: {Type}: {Msg}",
                        ex.GetType().Name, ex.Message);
                }
            }
        }

        if (config.NotifyEmailAddresses.Length > 0)
        {
            _logger.LogInformation("Email notification for '{Title}': {Message}", title, message);
        }

        // v1.4 webhook — single endpoint, JSON body, optional HMAC signature.
        // Fire-and-forget at the call site; bounded by the HttpClient timeout.
        // SEC-M2: validate URL + resolve allowed IPs; the pinned HttpClient
        // re-resolves at connect-time and refuses if DNS drifted.
        var pinnedAddresses = !string.IsNullOrWhiteSpace(config.WebhookUrl)
            ? GetSafeWebhookAddresses(config.WebhookUrl)
            : null;
        if (pinnedAddresses is { Length: > 0 })
        {
            try
            {
                var nowUtc = DateTime.UtcNow;
                // Discord webhooks reject our generic JSON shape (they want
                // {content, embeds}). Auto-detect by URL pattern and reshape
                // so users can paste a Discord webhook URL and have it work.
                // Slack uses a different shape too — detect it and emit a
                // simple text payload that Slack accepts.
                var isDiscord = config.WebhookUrl.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase)
                    || config.WebhookUrl.Contains("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase);
                var isSlack = config.WebhookUrl.Contains("hooks.slack.com", StringComparison.OrdinalIgnoreCase);
                string body;
                if (isDiscord)
                {
                    // Discord — username + embed with the title/message + a
                    // small fields block for the structured payload values
                    // (kept short — Discord caps field count at 25).
                    var fields = new List<object>();
                    try
                    {
                        var props = payload?.GetType().GetProperties();
                        if (props is not null)
                        {
                            foreach (var p in props.Take(8))
                            {
                                var v = p.GetValue(payload);
                                fields.Add(new { name = p.Name, value = (v?.ToString() ?? "(none)"), inline = true });
                            }
                        }
                    }
                    catch { /* best-effort field extraction */ }
                    body = JsonSerializer.Serialize(new
                    {
                        username = "Jellyfin 2FA",
                        embeds = new[]
                        {
                            new
                            {
                                title,
                                description = message,
                                color = @event switch
                                {
                                    "lockout" or "emergency_lockout" or "suspicious_login" => 16711680, // red
                                    "passkey_registered" or "totp_rotated" => 16744192,                  // amber
                                    _ => 49151,                                                         // light blue
                                },
                                timestamp = nowUtc.ToString("o"),
                                fields = fields,
                                footer = new { text = "event: " + @event },
                            }
                        }
                    });
                }
                else if (isSlack)
                {
                    body = JsonSerializer.Serialize(new
                    {
                        text = "*" + title + "*\n" + message,
                    });
                }
                else
                {
                    body = JsonSerializer.Serialize(new
                    {
                        @event,
                        title,
                        message,
                        timestamp = nowUtc,
                        payload,
                    });
                }
                using var request = new HttpRequestMessage(HttpMethod.Post, config.WebhookUrl)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                };
                // SEC-M4 (legacy comment, retained): surface timestamp as a
                // header so receivers can do skew checks without parsing JSON,
                // and HMAC over `timestamp.body` so a downstream proxy that
                // minifies the body still produces a verifiable signature
                // (the receiver recomputes from the header timestamp + raw
                // body).
                var tsUnix = new DateTimeOffset(nowUtc).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
                request.Headers.TryAddWithoutValidation("X-2FA-Timestamp", tsUnix);
                if (!string.IsNullOrEmpty(config.WebhookSecret))
                {
                    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(config.WebhookSecret));
                    var signed = tsUnix + "." + body;
                    var sig = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(signed))).ToLowerInvariant();
                    request.Headers.TryAddWithoutValidation("X-2FA-Signature", "sha256=" + sig);
                }
                // SEC-M2: pin the validated allowed-IP set into a thread-local
                // for the dispatch HttpClient's ConnectCallback to read. Cleared
                // in `finally` so a leaked pin doesn't authorize a later send.
                _pinnedAllowedAddresses.Value = pinnedAddresses;
                try
                {
                    using var response = await _webhookHttpClient.SendAsync(request).ConfigureAwait(false);
                }
                finally
                {
                    _pinnedAllowedAddresses.Value = null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Webhook delivery failed");
            }
        }
    }

    /// <summary>SEC-M2: SSRF guard. Resolves once, validates every IP, and
    /// returns the validated set so the dispatch HttpClient's ConnectCallback
    /// can re-resolve at connect-time and reject if the result drifted (DNS-
    /// rebinding defence). Returns null if URL is unsafe.
    ///
    /// Rejects:
    /// - non-http(s) schemes (no file://, gopher://, etc.)
    /// - hostnames that resolve to RFC1918 / loopback / link-local /
    ///   ULA-IPv6 / link-local-IPv6 / CGNAT-100.64.0.0/10 (SEC-L7) — an
    ///   attacker who tricks an admin into pasting an internal URL can't
    ///   make the server hit AWS/GCP metadata, Docker hosts, or carrier-
    ///   internal addresses.</summary>
    private System.Net.IPAddress[]? GetSafeWebhookAddresses(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) return null;

        // SECURITY [v2.5.9] (audit medium): warn (non-breaking) on plaintext
        // http:// notification targets. Bodies can carry pairing codes,
        // usernames and IPs, and webhook auth tokens (X-Gotify-Key / HMAC)
        // travel in headers — all in clear over http. Kept allowed for
        // LAN-only ntfy/Gotify, but surfaced so admins can switch to https.
        if (string.Equals(u.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("[2FA] Notification target host '{Host}' uses plaintext http:// — message content and any auth token are sent unencrypted. Prefer https://.", u.Host);
        }

        try
        {
            var addrs = System.Net.Dns.GetHostAddresses(u.Host);
            if (addrs is null || addrs.Length == 0) return null;
            // [v2.5.17] (#116): self-hosted ntfy/Gotify/webhook behind a reverse
            // proxy usually resolves to a private LAN IP (192.168.x.x). The
            // default SSRF guard refuses those, silently dropping every
            // notification. Admins can opt in to trust private targets; even
            // then, link-local / cloud-metadata addresses stay blocked.
            var allowPrivate = Plugin.Instance?.Configuration?.AllowPrivateNotificationTargets ?? false;
            foreach (var a in addrs)
            {
                if (IsAlwaysBlockedAddress(a))
                {
                    _logger.LogWarning("[2FA] Webhook URL {Url} resolves to link-local/metadata address {Ip} — refusing to dispatch (SSRF guard, always blocked)", url, a);
                    return null;
                }
                if (!allowPrivate && IsPrivateOrLoopback(a))
                {
                    _logger.LogWarning("[2FA] Webhook URL {Url} resolves to private address {Ip} — refusing to dispatch (SSRF guard). Enable 'Allow private notification targets' in the plugin settings for a self-hosted LAN ntfy/webhook.", url, a);
                    return null;
                }
            }
            return addrs;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Webhook DNS lookup failed for {Host}", u.Host);
            return null;
        }
    }

    private static bool IsPrivateOrLoopback(System.Net.IPAddress a)
    {
        if (System.Net.IPAddress.IsLoopback(a)) return true;
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            // 10.0.0.0/8
            if (b[0] == 10) return true;
            // 172.16.0.0/12
            if (b[0] == 172 && (b[1] & 0xF0) == 16) return true;
            // 192.168.0.0/16
            if (b[0] == 192 && b[1] == 168) return true;
            // 169.254.0.0/16  (link-local — covers AWS/GCP metadata 169.254.169.254)
            if (b[0] == 169 && b[1] == 254) return true;
            // 127.0.0.0/8 already covered by IsLoopback but be explicit
            if (b[0] == 127) return true;
            // 0.0.0.0/8
            if (b[0] == 0) return true;
            // SEC-L7: 100.64.0.0/10 — CGNAT (RFC 6598). Used by some carriers
            // for internal NAT; an attacker hitting an ISP customer's exposed
            // CGNAT IP from inside the carrier net would otherwise bypass the
            // private-network guard.
            if (b[0] == 100 && (b[1] & 0xC0) == 64) return true;
        }
        else if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // ::1 covered by IsLoopback. Block ULA fc00::/7 and link-local fe80::/10.
            var b = a.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return true;
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;
        }
        return false;
    }

    /// <summary>[v2.5.17] (#116): the subset of blocked ranges that stay blocked
    /// even when AllowPrivateNotificationTargets is on — link-local IPv4/IPv6
    /// (which includes the 169.254.169.254 cloud-metadata endpoint) and the
    /// 0.0.0.0/8 "this host" range. These have no legitimate self-hosted-ntfy
    /// use and are the highest-value SSRF targets, so opting into private LAN
    /// delivery never unlocks them.</summary>
    private static bool IsAlwaysBlockedAddress(System.Net.IPAddress a)
    {
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            if (b[0] == 169 && b[1] == 254) return true; // 169.254.0.0/16 link-local + cloud metadata
            if (b[0] == 0) return true;                  // 0.0.0.0/8
        }
        else if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = a.GetAddressBytes();
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // fe80::/10 link-local
        }
        return false;
    }
}

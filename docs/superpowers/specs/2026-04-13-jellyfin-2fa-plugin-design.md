# Jellyfin 2FA Plugin — Design Spec

## Overview

A native Jellyfin two-factor authentication plugin that intercepts all login requests server-side via `IAuthenticationProvider`. Because authentication is enforced at the API level, every client — web, mobile (Swiftfin, Findroid), TV (Android TV, Apple TV, Infuse), and service integrations (Sonarr, Radarr) — goes through the same pipeline with no client-side bypass possible.

This plugin fills the gap where reverse-proxy solutions (Authelia, Authentik) break native app authentication by handling 2FA natively within Jellyfin.

### Target Platform

- Jellyfin 10.11.x
- .NET 9
- JSON file storage (plugin data directory)

### NuGet Dependencies

- `OtpNet` — TOTP generation and validation (RFC 6238)
- `QRCoder` — QR code generation for TOTP setup

---

## Authentication Flow

### High-Level Flow

1. Client submits username + password via any Jellyfin login endpoint.
2. `TwoFactorAuthProvider` (implements `IAuthenticationProvider`) validates the password by delegating to Jellyfin's default auth provider.
3. If password is valid, the plugin evaluates bypass rules (LAN, trusted device, registered device ID, API key).
4. If a bypass applies → authentication succeeds immediately, normal session token issued.
5. If no bypass applies → authentication fails with a structured error response containing a `challengeToken` and available 2FA methods.
6. The client (or web redirect) calls `POST /TwoFactorAuth/Verify` with the challenge token and OTP code.
7. On successful verification → the plugin issues a real session token via Jellyfin's session manager, plus an optional trusted device token for future bypass.

### Error Response Format

When 2FA is required, the auth failure response includes:

```json
{
  "twoFactorRequired": true,
  "challengeToken": "base64-encoded-random-token",
  "methods": ["totp", "email"],
  "challengePageUrl": "/TwoFactorAuth/Challenge?token=base64-encoded-random-token"
}
```

### Verification Request

```json
POST /TwoFactorAuth/Verify
{
  "challengeToken": "base64-encoded-random-token",
  "code": "123456",
  "method": "totp",
  "trustDevice": true
}
```

### Verification Response (Success)

```json
{
  "accessToken": "jellyfin-session-token",
  "deviceToken": "trusted-device-token-if-requested"
}
```

---

## Web 2FA Challenge

The web challenge is a **dedicated page served by the plugin** at `/TwoFactorAuth/Challenge`, delivered as an embedded resource. This is deliberately not JS injection into Jellyfin's login page — a standalone page is resilient to Jellyfin UI updates.

The challenge page:

- Accepts the `challengeToken` as a query parameter.
- Shows a code entry form (6-digit OTP input).
- Offers method selection if multiple methods are available (TOTP vs email).
- Has a "Send email code" button if email OTP is available.
- Has a "Trust this device" checkbox.
- On successful verification, redirects the user back to the Jellyfin web UI with the issued session token set.
- Styled to match Jellyfin's native look and feel (dark theme, same fonts).

For web clients, when auth fails with `twoFactorRequired: true`, the response includes `challengePageUrl`. The web client's login error handler can be guided to redirect to this URL. If a client does not understand the redirect, the user sees a standard auth failure — they can then use device pairing or trusted device registration as alternative paths.

---

## Components

### TwoFactorAuthProvider

Implements `IAuthenticationProvider`. Entry point for all authentication.

- Delegates password validation to Jellyfin's default provider.
- On valid password, calls `BypassEvaluator` to check if 2FA can be skipped.
- If no bypass, generates a challenge token via `ChallengeStore` and returns an auth failure with the structured 2FA response.
- Registered via `IPluginServiceRegistrator`.

### TwoFactorAuthController

ASP.NET Core API controller providing all plugin endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/TwoFactorAuth/Verify` | POST | Verify OTP code against challenge token |
| `/TwoFactorAuth/Setup/Totp` | POST | Generate TOTP secret + QR code for user |
| `/TwoFactorAuth/Setup/Totp/Confirm` | POST | Confirm TOTP setup with a verification code |
| `/TwoFactorAuth/Setup/Disable` | POST | Disable 2FA for a user |
| `/TwoFactorAuth/Devices` | GET | List trusted devices for current user |
| `/TwoFactorAuth/Devices/{id}` | DELETE | Revoke a trusted device |
| `/TwoFactorAuth/Devices/Register` | POST | Pre-register a device ID (TV/streaming box) |
| `/TwoFactorAuth/Pairings` | GET | List pending TV pairing requests (admin) |
| `/TwoFactorAuth/Pairings/{code}/Approve` | POST | Approve a TV pairing (admin) |
| `/TwoFactorAuth/Pairings/{code}/Deny` | POST | Deny a TV pairing (admin) |
| `/TwoFactorAuth/Users` | GET | List all users with 2FA status (admin) |
| `/TwoFactorAuth/Users/{id}/Toggle` | POST | Enable/disable 2FA requirement for a user (admin) |
| `/TwoFactorAuth/AuditLog` | GET | Get login attempt log (admin) |
| `/TwoFactorAuth/ApiKeys` | GET/POST/DELETE | Manage static API keys for service integrations |
| `/TwoFactorAuth/Email/Send` | POST | Request an email OTP for a pending challenge |
| `/TwoFactorAuth/Sessions/{id}/Revoke` | POST | Revoke an active session (admin) |

### TotpService

TOTP generation and validation using OtpNet.

- Generates 160-bit secrets.
- Validates codes with a ±1 time-step window (30-second steps).
- Constant-time comparison via `CryptographicOperations.FixedTimeEquals`.
- Replay prevention: tracks used codes per user per time window in memory. A code valid for time step T cannot be reused once verified.
- QR code generation via QRCoder, encoded as `otpauth://totp/Jellyfin:{username}?secret={base32}&issuer=Jellyfin`.

### EmailOtpService

Email-based one-time passwords using Jellyfin's existing SMTP configuration.

- Generates 6-digit numeric codes.
- 5-minute TTL, single use.
- Rate limited: max 3 sends per user per 10-minute window.
- Sent via Jellyfin's `IMailManager` (or direct SMTP if unavailable).
- Used as fallback when TOTP is not configured, or when the user explicitly requests an email code.

### DeviceTokenService

Manages trusted device tokens for 2FA bypass on subsequent logins.

- Generates 256-bit tokens via `RandomNumberGenerator`.
- Tokens are per-user, per-device (keyed by Jellyfin device ID + user ID).
- Stored in the user's JSON data file.
- Clients send the token via `X-TwoFactor-Token` header on login.
- Tokens can be revoked individually or all-at-once per user.

### DevicePairingService

TV/limited-input device pairing flow.

- Generates short alphanumeric codes (5 characters, e.g. `AX7K2`), avoiding ambiguous characters (0/O, 1/I/L).
- Codes have a 5-minute TTL.
- On code generation, sends push notification to admin(s) via `NotificationService`.
- Admin approves via web UI dashboard or notification action link.
- On approval, the held challenge is completed: session token issued to the TV client, device registered as trusted.
- On denial or TTL expiry, the challenge is invalidated.

### NotificationService

Push notifications for login events. Supports multiple backends:

- **ntfy** — HTTP POST to configured ntfy server/topic.
- **Gotify** — HTTP POST to configured Gotify server with app token.
- **Email** — Via Jellyfin's SMTP to configured admin email addresses.

Notification triggers:

- New device login requiring 2FA.
- Failed 2FA attempts (threshold: 3+ failures).
- Pending TV pairing request (includes code + approve/deny links).
- Successful pairing completion.

### ChallengeStore

In-memory store for pending 2FA challenges.

- Challenge tokens: 256-bit, cryptographically random, base64url-encoded.
- TTL: 5 minutes.
- Single use: consumed on successful verification.
- Stores: token, user ID, timestamp, available methods, device info.
- Periodic cleanup of expired entries (every 60 seconds via timer).
- Not persisted to disk — server restart invalidates all pending challenges (acceptable behavior).

### UserTwoFactorStore

Per-user persistent storage in JSON files.

- File path: `{PluginDataPath}/users/{userId}.json`
- Contents:
  - TOTP secret (encrypted via `IDataProtectionProvider`)
  - Whether TOTP is configured and verified
  - Trusted device tokens (list with device name, creation date, last used)
  - Registered device IDs
  - Email OTP preference
  - Failed attempt counter + lockout timestamp

### BypassEvaluator

Evaluates bypass rules in order. First match wins:

1. **API key** — If the request uses `X-Emby-Token` matching a plugin-managed static API key, bypass. (Standard Jellyfin API keys from Sonarr/Radarr also bypass since they don't go through user auth at all.)
2. **LAN** — Source IP in configured CIDR ranges. Default: `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`. Configurable. Checks `X-Forwarded-For` when behind a reverse proxy (configurable trust).
3. **Trusted device token** — `X-TwoFactor-Token` header matches a valid token for this user + device.
4. **Registered device ID** — Jellyfin device ID from the auth request matches a pre-registered device.

---

## Data Storage

All data stored as JSON files in the plugin data directory (`{JellyfinDataPath}/plugins/configurations/`):

| File | Contents |
|---|---|
| `users/{userId}.json` | Per-user 2FA config, TOTP secret (encrypted), trusted devices, preferences |
| `devices.json` | Global registered device ID list with owner mappings |
| `audit.json` | Login attempt log — IP, device, timestamp, result, method |
| `pending-pairings.json` | Active TV pairing codes with TTL (runtime only, rebuilt on restart) |
| `api-keys.json` | Plugin-managed static API keys with labels and creation dates |

### Audit Log Retention

- Default: 1000 entries, FIFO.
- Configurable max entries in plugin settings.
- Entries older than 90 days are pruned on startup.

---

## Web UI Pages (Embedded Resources)

### 2FA Challenge Page

- Path: `/TwoFactorAuth/Challenge`
- Standalone HTML page served by the plugin.
- Accepts `token` query parameter (challenge token).
- Shows 6-digit code input, method selector (TOTP/email), trust-device checkbox.
- On success, sets session token and redirects to Jellyfin web UI.
- Styled to match Jellyfin's dark theme.

### User Setup Page

- Path: `/TwoFactorAuth/Setup`
- Registered as a plugin page (`IHasWebPages`) accessible from user settings.
- QR code display for TOTP enrollment.
- Verification step (enter a code to confirm setup).
- Option to enable email OTP as fallback.
- Trusted device list with revoke buttons.
- Registered device ID management.

### Admin Dashboard

- Path: `/TwoFactorAuth/Admin`
- Registered as a plugin config page.
- Sections:
  - **Pending Pairings** — list of active TV pairing requests with approve/deny buttons.
  - **User Management** — table of all users with 2FA status, toggle enable/disable per user.
  - **Trusted Devices** — all trusted devices across all users, with revoke.
  - **Audit Log** — searchable/filterable login attempt history.
  - **API Keys** — generate and manage static API keys for service integrations.
  - **Settings** — LAN bypass CIDR ranges, notification service config, brute force thresholds, email OTP settings.

---

## Security

### TOTP

- 160-bit secrets, base32 encoded.
- 30-second time steps, ±1 step tolerance.
- Constant-time comparison: `CryptographicOperations.FixedTimeEquals` on the computed vs. submitted code bytes.
- Replay prevention: in-memory set of `(userId, timeStep, code)` tuples; a code used for time step T is rejected on resubmission within the same window.

### Email OTP

- 6-digit numeric codes.
- 5-minute TTL, single use (deleted after verification or expiry).
- Rate limited: max 3 per user per 10-minute window.

### Challenge Tokens

- 256-bit, generated via `RandomNumberGenerator.GetBytes`.
- Base64url encoded (URL-safe).
- 5-minute TTL, single use.

### Device Tokens

- 256-bit, generated via `RandomNumberGenerator.GetBytes`.
- Stored hashed (SHA-256) in user data; compared by hashing the submitted token.
- Per-user, per-device.

### Brute Force Protection

- Challenge endpoint (`/TwoFactorAuth/Verify`): 5 failed attempts → 15-minute lockout per user.
- Lockout tracked in `UserTwoFactorStore`.
- Failed attempts logged to audit log.
- Notification sent after 3+ consecutive failures.

### Secret Encryption

- TOTP secrets encrypted at rest using ASP.NET Core `IDataProtectionProvider`.
- Machine-scoped key (survives app restarts, tied to the server).

---

## Plugin Configuration

Standard Jellyfin plugin configuration via `PluginConfiguration`:

| Setting | Type | Default | Description |
|---|---|---|---|
| `Enabled` | bool | `true` | Global 2FA enable/disable |
| `RequireForAllUsers` | bool | `false` | Require 2FA for all users by default |
| `LanBypassEnabled` | bool | `true` | Enable LAN bypass |
| `LanBypassCidrs` | string[] | `["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]` | CIDR ranges for LAN bypass |
| `TrustForwardedFor` | bool | `false` | Trust X-Forwarded-For for IP detection |
| `TrustedProxyCidrs` | string[] | `[]` | Proxy IPs to trust for X-Forwarded-For |
| `EmailOtpEnabled` | bool | `true` | Enable email OTP as fallback |
| `EmailOtpTtlSeconds` | int | `300` | Email OTP code TTL |
| `ChallengeTokenTtlSeconds` | int | `300` | Challenge token TTL |
| `PairingCodeTtlSeconds` | int | `300` | TV pairing code TTL |
| `MaxFailedAttempts` | int | `5` | Failed attempts before lockout |
| `LockoutDurationMinutes` | int | `15` | Lockout duration |
| `AuditLogMaxEntries` | int | `1000` | Max audit log entries |
| `NtfyUrl` | string | `""` | ntfy server URL |
| `NtfyTopic` | string | `""` | ntfy topic |
| `GotifyUrl` | string | `""` | Gotify server URL |
| `GotifyAppToken` | string | `""` | Gotify app token |
| `NotifyEmailAddresses` | string[] | `[]` | Admin email addresses for notifications |

---

## Client Compatibility Matrix

| Client | 2FA Experience | Bypass Path |
|---|---|---|
| Web browser | Redirect to `/TwoFactorAuth/Challenge` page → enter code → redirect back | LAN bypass |
| Swiftfin (iOS) | First login: shows auth failure, user enters code manually or admin pairs. Subsequent: trusted device token auto-bypass | Trusted device token |
| Findroid (Android) | Same as Swiftfin | Trusted device token |
| Android TV | Pairing code flow (code shown, admin approves) | Registered device ID |
| Apple TV / Infuse | Pre-register device ID via web admin, or pairing code flow | Registered device ID |
| Sonarr / Radarr | Use Jellyfin API keys (never hit user auth) | N/A (API key auth) |
| Kodi | Trusted device token after first approval | Trusted device token |
| Other clients | Auth fails with 2FA response; manual code entry or admin pairing | Any bypass rule |

---

## Service Registration

```csharp
public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection services, IServerApplicationHost appHost)
    {
        services.AddSingleton<ChallengeStore>();
        services.AddSingleton<UserTwoFactorStore>();
        services.AddSingleton<TotpService>();
        services.AddSingleton<EmailOtpService>();
        services.AddSingleton<DeviceTokenService>();
        services.AddSingleton<DevicePairingService>();
        services.AddSingleton<NotificationService>();
        services.AddSingleton<BypassEvaluator>();
        services.AddSingleton<TwoFactorAuthProvider>();
    }
}
```

---

## Threat Model Coverage

| Threat | Mitigation |
|---|---|
| Port-forwarded Jellyfin with stolen password | 2FA required for all remote logins |
| Cloudflare Tunnel exposure | Same — all non-LAN requests require 2FA |
| Authelia/Authentik breaking native apps | Native plugin, no proxy dependency |
| Service integrations (Sonarr/Radarr) breaking | API keys bypass user auth entirely |
| TOTP secret theft from disk | Encrypted at rest via DataProtectionProvider |
| Brute force on OTP codes | Rate limiting + lockout after 5 failures |
| Replay attacks on TOTP | Used-code tracking per time window |
| Timing attacks on TOTP comparison | CryptographicOperations.FixedTimeEquals |

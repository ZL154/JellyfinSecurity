```text
██████╗ ███████╗ █████╗
╚════██╗██╔════╝██╔══██╗
 █████╔╝█████╗  ███████║
██╔═══╝ ██╔══╝  ██╔══██║
███████╗██║     ██║  ██║
╚══════╝╚═╝     ╚═╝  ╚═╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Jellyfin-10.11%2B-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
  <img src="https://img.shields.io/badge/Type-Plugin-00a4dc?style=for-the-badge&labelColor=000000&color=00a4dc" />
  <img src="https://img.shields.io/badge/System-Security%20Suite-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
  <img src="https://img.shields.io/badge/Version-2.2.0-00a4dc?style=for-the-badge&labelColor=000000&color=00a4dc" />
  <img src="https://img.shields.io/badge/License-MIT-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
</p>

# 🔐 Jellyfin Security

Comprehensive authentication and hardening for Jellyfin: TOTP, passkeys, email OTP, **OIDC/SSO sign-in**, brute-force IP banning, impossible-travel detection, per-user IP allowlist, device pairing, trusted-browser cookies, and a full audit log — all from one plugin.

> **Why this exists:** for self-hosters who want a complete auth + hardening layer **without standing up a separate identity stack**. Full IdPs like Authentik (with OIDC or LDAP outposts) and Authelia work great with Jellyfin and offer features this plugin doesn't — they're often the right call for serious deployments. This plugin is for the case where you'd rather get TOTP, passkeys, OIDC sign-in, brute-force protection, impossible-travel detection, IP allowlist, audit logging, and a proper admin UI **as a single Jellyfin plugin** — no extra containers, no LDAP outpost, no proxy-auth header juggling, native Jellyfin user model end-to-end.

---

## 📑 Table of contents

- [How it works](#-how-it-works)
- [Features](#-features)
- [Installation](#%EF%B8%8F-installation)
- [First-time setup](#-first-time-setup)
- [Daily use](#-daily-use)
- [Admin guide](#%EF%B8%8F-admin-guide)
- [SSO / OIDC sign-in (v2.0)](#-sso--oidc-sign-in-v20)
- [Brute-force IP banning (v2.0)](#-brute-force-ip-banning-v20)
- [Impossible-travel detection (v2.0)](#-impossible-travel-detection-v20)
- [Per-user IP allowlist (v2.0)](#-per-user-ip-allowlist-v20)
- [SMTP setup (email OTP)](#-smtp-setup-email-otp)
- [Recovery — locked out](#-recovery--locked-out)
- [Architecture](#-architecture)
- [API endpoints](#-api-endpoints)
- [Security model](#-security-model)
- [Limitations](#-limitations)
- [Changelog](#-changelog)
- [Support the project](#-support-the-project)
- [License](#-license)

---

## ⚡ How it works

1. Each user opts into 2FA via `/TwoFactorAuth/Setup` — scans a QR code with an authenticator app and saves recovery codes.
2. On normal login, Jellyfin's `SessionStarted` event fires. The plugin checks if the user has 2FA enabled.
3. If yes, the plugin **blocks all subsequent API requests from that session** until the user completes 2FA via `/TwoFactorAuth/Login`.
4. After successful verification, a signed `__2fa_trust` cookie is set in the browser. **For 30 days, that browser doesn't need 2FA again** — but new browsers/devices still do.
5. The block applies regardless of how the user authenticated (Jellyfin web, mobile API, anything that creates a session).

The standard Jellyfin login page gets a small "Sign in with 2FA" button injected so users with 2FA enrolled can route directly to the plugin's login form.

---

## 🧩 Features

### New in v2.0
- **OIDC / SSO sign-in** — Google, Microsoft/Entra, Apple, Authelia, Authentik, Keycloak, PocketID, Cloudflare Access, or any OIDC-compliant IdP. PKCE, id_token signature validation, group-based authorisation, optional AMR-based IdP-MFA enforcement.
- **Brute-force IP banning** — auto-bans source IPs that exceed N failed sign-ins in M minutes. Persisted across restarts, with admin UI to list/unban.
- **Impossible-travel detection** — notifies when consecutive sign-ins exceed commercial-jet cruise speed (≈900km/h default). Uses MaxMind GeoLite2-City for lat/lon.
- **Per-user IP allowlist** — pin high-value accounts (e.g. admin) to specific CIDRs so sign-in is refused from everywhere else.
- **Login-page provider buttons** — each configured SSO provider shows below the normal sign-in form.
- **Linked sign-in methods in user Setup** — users see/unlink their external accounts self-service.

### Authentication
- **TOTP** (RFC 6238) compatible with Google Authenticator, Authy, 1Password, Microsoft Authenticator, Bitwarden, etc.
- **10 single-use recovery codes** generated at enrollment, stored as SHA-256 hashes, displayable once
- **Email OTP fallback** via configurable SMTP — codes expire in 5 minutes, single-use
- **Per-device trust** via signed HTTP-only cookie (HMAC-SHA256, 30-day expiry, `SameSite=Strict`)

### Enforcement
- Session-level enforcement via `ISessionManager.SessionStarted` — works for all clients, not just web
- API-level request blocking — even valid Jellyfin tokens get 401 until 2FA is completed
- Per-IP rate limiting on verify (10/min) and email send (5/5min)
- Per-challenge attempt limit (5 attempts before challenge is burned)
- Per-user lockout after 5 failed attempts (15-minute cool-down, configurable)
- LAN bypass (configurable CIDR ranges) so local devices can skip 2FA
- Force-2FA-for-all-users mode (admin setting)

### Security
- TOTP secrets encrypted at rest with **AES-GCM** using a persistent 32-byte key (survives restarts)
- Cookie signatures use **HMAC-SHA256** with persistent key
- Constant-time comparison for all secret material (`CryptographicOperations.FixedTimeEquals`)
- TOTP replay prevention (used time-steps tracked per user)
- Recovery codes marked used immediately on validation (not on full login success) — stolen codes can't be retried
- Atomic file writes for user data — crash mid-write doesn't corrupt 2FA state
- Generic error messages prevent account enumeration ("invalid credentials" whether password or code is wrong)

### Native client support (v1.3.0)
- **App passwords** — generate revocable long random passwords for native apps (Swiftfin, Findroid, etc.). Stored as PBKDF2-SHA256 hashes. Users with a Jellyfin password can enter the app password in the native client's password field to bypass 2FA.
- **Device pairing** — passwordless users (no Jellyfin password) can pair native clients: the first failed login registers a "pending pairing request." The user approves it from `/TwoFactorAuth/Setup`, and the device is permanently trusted.
- **Quick Connect pass-through** — when a 2FA-verified user approves a Quick Connect code, the new device inherits the verified status. TVs sign in without a TOTP prompt.
- **Active sessions view** — users can see all their active sessions with device/IP/last-activity and sign them out individually.

### UI
- Polished login page with lockout countdown and low-recovery-code warning
- Redesigned Setup page with status dashboard, TOTP enrollment, recovery codes, email backup, pending device approvals, paired devices, app passwords, trusted browsers, and active sessions — all in one unified view
- Admin dashboard with users, devices, audit log (paginated, filterable), and settings with Test SMTP button
- Configurable TOTP issuer name (what users see in their authenticator app)
- Per-user email address management (self-service from Setup page or admin-set)
- "Sign in with 2FA" button auto-injected into Jellyfin's standard login page
- "Two-Factor Auth" sidebar entry injected into Jellyfin's navigation drawer (follows AchievementBadges' proven DOM injection pattern)
- Settings page tile so users can find Setup from their preferences

### Notifications
- Push notifications for login attempts via **ntfy** or **Gotify**
- Audit log of every 2FA-related event (1000 entries default, FIFO, 90-day prune)

---

## ⚙️ Installation

1. Open Jellyfin → **Dashboard → Plugins → Repositories**
2. Click **+** and add this URL:

```
https://raw.githubusercontent.com/ZL154/JellyfinSecurity/main/manifest.json
```

3. Save and refresh plugins
4. Go to the **Catalogue** tab → install **Two-Factor Authentication**
5. Restart Jellyfin

### Build from source

```powershell
# Windows
.\build.ps1 -Install
```

```bash
# Linux/macOS
chmod +x build.sh && ./build.sh --install
```

### Manual install

Copy these 4 files into `<jellyfin-data>/plugins/TwoFactorAuth/`:

```
TwoFactorAuth/
├── meta.json
├── Jellyfin.Plugin.TwoFactorAuth.dll
├── Otp.NET.dll
└── QRCoder.dll
```

Plugin directories by OS:
- **Docker:** `/config/plugins/TwoFactorAuth/`
- **Linux:** `~/.local/share/jellyfin/plugins/TwoFactorAuth/`
- **Windows:** `%LOCALAPPDATA%\jellyfin\plugins\TwoFactorAuth\`

Restart Jellyfin after copying.

---

## 🚀 First-time setup

### As an admin

1. Install the plugin from the manifest URL in **Dashboard → Plugins → Repositories → Add**, then install **Two-Factor Authentication** from the catalog and restart Jellyfin.
2. Go to **Dashboard → Plugins → Two-Factor Authentication**
3. Open the **Settings** tab and verify:
   - ✅ **Enabled** — master switch
   - ✅ **Require for all users** — off by default. When on, every user with a password must enroll (existing trusted sessions keep working). When off, 2FA is opt-in per user.
   - ✅ **LAN Bypass** — skip 2FA when the request comes from a LAN IP (192.168/16, 10/8, 172.16/12 by default). Adds convenience, reduces prompts on local devices.
   - **Email OTP** — optional fallback if a user loses their authenticator. Requires SMTP config below.
4. If you're behind a reverse proxy (Cloudflare, nginx, Caddy, Traefik):
   - Enable **Trust X-Forwarded-For**
   - Add your proxy IPs (or Cloudflare's IP ranges) to **Trusted Proxy CIDRs**
   - Without this, rate limiting collapses to a single bucket because every request looks like it comes from the proxy's loopback.
5. Optional: configure **Notifications** (Gotify, ntfy, or webhook) to get alerts when someone triggers a 2FA prompt.

### As a user (enroll in 2FA)

1. Sign in to Jellyfin normally (no 2FA yet)
2. Open **Profile → Two-Factor Authentication** (or visit `https://your-jellyfin/TwoFactorAuth/Setup`)
3. Click **Set up Authenticator App**
4. Scan the QR code with your authenticator (Google Authenticator, Authy, 1Password, Bitwarden, etc.)
5. Enter the 6-digit code shown in the app to confirm
6. **Generate recovery codes** — you get 10 single-use codes. Save them in your password manager. Each one can sign you in if you lose your phone.
7. (Optional) Add your email under **Email OTP** if you want email as a backup factor.

### Signing in with 2FA on the web

From this point, every login from a new browser prompts for a code:

1. Sign in at `/web` with username + password as usual
2. You will be redirected to the 2FA challenge page
3. Enter the 6-digit code from your authenticator
4. Done — this browser is trusted for 30 days (cookie bound to your device)

### Passkeys (v1.4) — sign in with Face ID / fingerprint / YubiKey

Passkeys replace the 6-digit code with a biometric or hardware tap. They are phishing-resistant (the credential is bound to your exact domain) and require no typing.

**Important — server config first.** Passkeys require HTTPS AND the WebAuthn Relying Party ID + origin to match the URL the browser is on. In **Dashboard → Plugins → Two-Factor Authentication → Settings → WebAuthn / passkeys**:

- **Relying Party ID**: enter your public hostname only — `jellyfin.example.com`. No `https://`, no port, no path.
- **Allowed origins**: one per line, full origin including scheme and port — e.g. `https://jellyfin.example.com` and `https://jellyfin.example.com:8096`. Add every URL users actually hit.

If you skip this, browsers will refuse to register or use passkeys (Apple Safari is the strictest).

#### Add a passkey on a desktop browser

1. Open the Setup page on the URL you configured above
2. Setup → **Passkeys** card → optionally type a label → **Add a passkey**
3. Browser prompts your platform authenticator (Windows Hello / Touch ID / a YubiKey USB key)
4. Tap / scan / confirm — the passkey is saved

#### Add a passkey on iPhone (Safari)

1. Open **Safari** and visit your Jellyfin HTTPS URL — must be the URL configured as the WebAuthn origin, not the bare LAN IP
2. Sign in with username + password + 2FA code
3. Setup → **Passkeys** → label it (e.g. "iPhone") → **Add a passkey**
4. iOS shows "Save passkey for ...?" — confirm with **Face ID / Touch ID**
5. The passkey is saved to **iCloud Keychain** and syncs to every Apple device on the same Apple ID

#### Add a passkey on Android (Chrome)

1. Open **Chrome** on Android and visit your Jellyfin HTTPS URL
2. Sign in with username + password + 2FA code
3. Setup → **Passkeys** → label it (e.g. "Pixel 8") → **Add a passkey**
4. Android shows "Save passkey to Google Password Manager?" — confirm with **fingerprint / face unlock**
5. The passkey now lives in your Google account and syncs to every Android signed in with the same Google account

**Common Android gotchas:**
- "Add a passkey" does nothing → your phone needs a screen lock (PIN/pattern/biometric). Android refuses to create passkeys without one.
- "No passkey provider available" → Settings → Passwords & accounts → Passwords → enable Google Password Manager, or set Bitwarden / 1Password as your default credential provider.
- Samsung Internet sometimes hides the passkey button — use **Chrome** instead.

#### Using a passkey to sign in

1. Visit your Jellyfin URL → enter username + password as usual
2. At the 2FA challenge page → tap **🔑 Use a passkey instead**
3. The browser prompts your authenticator → confirm with biometric / hardware key
4. You're in. No code typed.

#### What passkeys do NOT do

- **Native apps (Findroid, Streamyfin, Swiftfin, official Jellyfin app) cannot use passkeys.** WebAuthn is a browser-only API; native apps have no hook to call it. For app sign-in use **device pairing** (below) and the **app's own biometric lock** (Findroid → Settings → Biometric authentication, Swiftfin → Settings → Security → Lock with Face ID, etc.).
- Passkeys do not replace your password — they replace the **2FA code step**. You still enter username + password first.

### Native apps / TVs (Jellyfin for Tizen, Swiftfin, Jellyfin Android, etc.)

Native apps don't know how to do a 2FA flow, so the plugin uses **device pairing** instead:

1. Open the native app and sign in with your username + password
2. The app will show "Invalid" or fail to load — that's expected. The server recorded a **pending pairing** for this device.
3. On any already-trusted device (your laptop, phone browser), go to **Setup → Devices Waiting for Approval**
4. You'll see the TV/app listed. Click **Trust**.
5. Back on the TV/app, retry sign-in — it now works and is remembered permanently.

This way a TV/console/media-box that can't type a TOTP code still gets its own credential you can revoke later.

### Native apps that can't do the pairing flow (scripts, older tools)

Use **app passwords**: in Setup → App Passwords → Generate. You get a one-time shown random password. Use it in the app **in place of your Jellyfin password**. The plugin matches it via PBKDF2 hash and bypasses the 2FA prompt. Each app password can be revoked independently.

---

## 🔄 Daily use

### Web login (browser)

- On the standard Jellyfin login page, click the **🔐 Sign in with Two-Factor Authentication** button
- Enter your username, password, and 6-digit code from your app
- After first sign-in on this browser, you won't be asked for the code again for 30 days

### Mobile / TV apps (Swiftfin, Findroid, Jellyfin for Tizen, Android TV, etc.)

Use the **device pairing** flow described in [First-time setup](#-first-time-setup):
1. Sign in on the TV/mobile app with your password
2. It'll fail once — that's normal, the server recorded a pending pairing
3. Approve the device from Setup on any already-trusted browser
4. Retry on the TV/app — it now works permanently

Alternative: generate an **app password** in Setup and use it in place of your real password. Useful for older apps or anything that can't tolerate the pairing-request delay.

### Sonarr / Radarr / Overseerr / Jellyseerr

Use Jellyfin's standard API keys (Dashboard → API Keys). API key auth bypasses user authentication entirely, so 2FA doesn't apply.

---

## 🛠️ Admin guide

The admin dashboard at **Dashboard → Plugins → Two-Factor Authentication** has 5 tabs:

### Users
Per-user 2FA status: TOTP on/off, trusted device count, recovery codes remaining, email address (for OTP), lockout status.
- **Set per-user email** — for email OTP delivery (admin sets these manually)
- **Toggle 2FA on/off** — disabling wipes all 2FA state for that user (secret, codes, devices)

### Trusted Devices
Every trusted device across all users with last-used time and expiry. Revoke any to force 2FA on that browser's next login.

### Pairings
Pending TV pairing requests (currently a stub — see "Limitations" below).

### Audit Log
Paginated, filterable login attempt history. Tracks success, failures, lockouts, bypasses, and challenge issuances.

### Settings
- **General** — plugin toggle, force 2FA for all users, email OTP toggle
- **LAN Bypass** — CIDR ranges, X-Forwarded-For trust, trusted proxies
- **Security** — failed-attempt threshold, lockout duration, audit log size
- **SMTP** — host, port, SSL, credentials, from-address (required for email OTP)
- **Push Notifications** — ntfy URL/topic, Gotify URL/token, admin email addresses

---

## 🌐 SSO / OIDC sign-in (v2.0)

Lets users sign in with Google / Microsoft / Authelia / Authentik / Keycloak / PocketID / Cloudflare Access / etc. instead of (or alongside) a Jellyfin password. 2FA-less accounts work too — SSO replaces the password.

**Matching logic when a user signs in via OIDC:**
1. Existing SSO link on this Jellyfin user (matched by the IdP's stable `sub`) → signs in
2. Email returned by the IdP matches a per-user email configured in the plugin → signs in (and links for next time)
3. Nothing matched + "Auto-create Jellyfin users" is enabled → a new Jellyfin account is created
4. Nothing matched + auto-create is OFF → sign-in refused with "No Jellyfin user matched"

### Setting up a Google provider (walkthrough)

**1. Register a Google OAuth client**
1. Go to [Google Cloud Console](https://console.cloud.google.com) → create a project (or pick existing)
2. **OAuth consent screen** → External → fill App name / support email → add your Gmail as a test user → Finish
3. **Credentials** → **+ Create credentials** → **OAuth client ID** → **Web application**
4. **Authorised redirect URIs** → add exactly: `https://YOUR-JELLYFIN-HOSTNAME/TwoFactorAuth/Oidc/Callback/google`
5. Save. Copy the **Client ID** + **Client secret** from the dialog.

**2. Add the provider in Jellyfin**
1. Jellyfin admin → Plugins → **Jellyfin Security** → **Sign-in Methods** tab → "Add provider…"
2. Preset: **Google**. Paste Client ID + Secret. **Username claim:** `email`. Save.

**3. Make sure each Jellyfin user has their Gmail configured**
- Either: each user sets their email on the Setup page (`/TwoFactorAuth/Setup`), **or**
- admin fills it in Jellyfin Security → Users tab's email column (press Tab after typing to save)

**4. Done.** Sign out and the login page now shows a "Sign in with Google" button. Click → Google consent → bridge page → signed in.

### Other providers

| Preset | Discovery auto-filled | Notes |
|---|---|---|
| Google | ✅ | Username claim: `email` |
| Microsoft / Entra | ✅ | Replace `common` in discovery URL with tenant ID for single-tenant apps |
| Apple | ✅ | Returns email only on first sign-in; no `email_verified` claim |
| Authelia | — | Paste `https://authelia.domain/.well-known/openid-configuration` |
| Authentik | — | Copy discovery URL from provider details in Authentik admin |
| Keycloak | — | `https://keycloak.domain/realms/<realm>/.well-known/openid-configuration` |
| PocketID | — | `https://pocketid.domain/.well-known/openid-configuration` |
| Cloudflare Access | — | SaaS → OIDC app → discovery URL ends `/cdn-cgi/access/sso/oidc/<app-id>/.well-known/openid-configuration` |
| GitHub | ❌ | OAuth2 only, not OIDC — not yet supported |
| Discord | ❌ | OAuth2 only, not OIDC — not yet supported |

### Per-provider options
- **Allowed groups** — sign-in refused unless IdP's `groups` / `roles` claim contains at least one of these
- **Require IdP MFA** — refuses sign-in unless the id_token's `amr` claim indicates MFA (`mfa`, `hwk`, `otp`, `sca`)
- **Auto-create users** — creates a new Jellyfin account for unmatched IdP identities. **Only enable for IdPs where you trust everyone with an account** (not public Google).
- **Skip plugin 2FA** — default ON; the IdP already authenticated. Disable only if you want belt-and-braces.

---

## 🚫 Brute-force IP banning (v2.0)

Auto-bans source IPs that hammer the login endpoint. Fail2Ban-style, entirely in-process — no external service needed.

**Configure:** Jellyfin Security → **Settings** → "Brute-Force Protection":
- Failure threshold (default **10**)
- Window (default **10 min**)
- Ban duration (default **24 h**)
- Exempt CIDRs (never banned — e.g. your office IP)

**Always exempt:** LAN-bypass CIDRs, trusted-proxy CIDRs, anything in the exempt list.

**Manage bans:** Jellyfin Security → **IP Bans** tab lists all active bans with expiry. Click "Unban" to clear. You can also manually ban an IP here (e.g. "someone who's been guessing").

Bans persist across restarts via `<config>/plugins/configurations/TwoFactorAuth/ip-bans.json`.

---

## ✈️ Impossible-travel detection (v2.0)

Flags sign-ins where the geographic distance vs. elapsed time exceeds commercial-jet cruise speed. London → Tokyo in 30 minutes ≈ Mach 20: notification fires.

**Requires:** MaxMind GeoLite2-City.mmdb. [Free account](https://www.maxmind.com/en/geolite2/signup), download the City DB, drop it in `/config/geoip/`, paste the path in **Settings → Impossible-Travel Detection**.

**Signal path:** Triggers the same Notification channels the plugin already uses (ntfy, Gotify, webhook, admin emails). Includes distance, duration, inferred speed, and country hop in the message.

Off by default; enable in Settings once the city DB is in place.

---

## 🔒 Per-user IP allowlist (v2.0)

Pin a user account to specific CIDRs. Empty = no restriction (default). Useful for admin accounts where lateral exposure hurts most.

**Configure (user self-service):** Setup page → **IP Allowlist** card → one CIDR per line → Save.
**Configure (admin, per user):** `PUT /TwoFactorAuth/IpAllowlist/User/{userId}` (UI not wired in yet; edit the user JSON or use the API).

⚠ **Self-lockout risk:** if you typo a CIDR, you can't sign in. Recover by editing `/config/plugins/configurations/TwoFactorAuth/users/<your-guid>.json` and clearing `IpAllowlistCidrs`.

---

## 📧 SMTP setup (email OTP)

Email OTP requires SMTP credentials. Common providers:

### Gmail (with app password)
```
SMTP Host: smtp.gmail.com
SMTP Port: 587
Use SSL/TLS: ✓
SMTP Username: your-email@gmail.com
SMTP Password: <generate at https://myaccount.google.com/apppasswords>
From Address: your-email@gmail.com
From Name: Jellyfin 2FA
```

### Generic SMTP relay
```
SMTP Host: mail.example.com
SMTP Port: 587 (STARTTLS) or 465 (implicit TLS)
Use SSL/TLS: ✓
```

### Per-user email addresses

Email OTP needs the user's email address. In **Admin → Users**, edit each user's email field. The plugin doesn't auto-pull from Jellyfin user metadata (Jellyfin's `User` entity exposes email inconsistently across versions).

---

## 🆘 Recovery — locked out

### Lost authenticator app + have recovery codes
Sign in via `/TwoFactorAuth/Login`. In the code field, enter one of your recovery codes (format: `XXXXX-XXXXX`). Click "Use a recovery code instead" if your authenticator app field is showing.

### Lost authenticator AND lost recovery codes (admin)
SSH into the Jellyfin server and edit the user data file:

```bash
# Path
/config/plugins/configurations/TwoFactorAuth/users/{userId}.json

# Set:
"TotpEnabled": false,
"TotpVerified": false,
"EncryptedTotpSecret": null,
"RecoveryCodes": [],
"TrustedDevices": []
```

Restart Jellyfin. The user can now log in normally and re-enroll.

### Plugin breaking your server
Disable the plugin without uninstalling:

```bash
# Edit
/config/plugins/configurations/Jellyfin.Plugin.TwoFactorAuth.xml

# Set
<Enabled>false</Enabled>
```

Restart Jellyfin. All 2FA enforcement turns off; users can log in normally.

---

## 🏗️ Architecture

The plugin uses **5 ASP.NET Core middleware** components plus an `ISessionManager.SessionStarted` event handler:

1. **`IndexHtmlInjectionMiddleware`** — injects the "Sign in with 2FA" button script into Jellyfin's `index.html`
2. **`TrustCookieMiddleware`** — checks the `__2fa_trust` cookie on auth requests; if valid, marks the user as pre-verified for the upcoming session
3. **`TwoFactorEnforcementMiddleware`** — inspects responses from auth endpoints (catches the auth response shape regardless of which Jellyfin route was used)
4. **`RequestBlockerMiddleware`** — blocks API requests from authenticated users who haven't completed 2FA yet (returns 401)
5. **`AuthenticationEventHandler`** (hosted service) — subscribes to `SessionStarted`; if a session for a 2FA-enabled user starts without verification, the user is added to the blocker's blocklist

Persistent state:
- `users/{userId}.json` — per-user TOTP secret (AES-GCM encrypted), recovery codes (SHA-256 hashed), trusted devices, lockout state
- `secret.key` — 32-byte AES-GCM key for TOTP secret encryption
- `cookie.key` — 32-byte HMAC-SHA256 key for trust cookie signing
- `audit.json` — login attempt log

All file writes use atomic write-then-rename so crashes mid-write don't corrupt user state.

---

## 📡 API endpoints

### User-facing (anonymous or self-auth)
```
GET  /TwoFactorAuth/Login                                — login page (HTML)
GET  /TwoFactorAuth/Setup                                — enrollment page (HTML)
GET  /TwoFactorAuth/Challenge?token=...                  — challenge page (HTML)
GET  /TwoFactorAuth/inject.js                            — login button injection
POST /TwoFactorAuth/Authenticate                         — username + password + code login
POST /TwoFactorAuth/Verify                               — verify code against challenge token
POST /TwoFactorAuth/Email/Send                           — request email OTP for current challenge

POST /TwoFactorAuth/Setup/Totp                           — generate TOTP secret + QR (auth)
POST /TwoFactorAuth/Setup/Totp/Confirm                   — confirm TOTP enrollment (auth)
POST /TwoFactorAuth/Setup/Disable                        — disable 2FA for self (auth)
POST /TwoFactorAuth/RecoveryCodes/Generate               — generate recovery codes (auth)
GET  /TwoFactorAuth/RecoveryCodes/Status                 — count remaining (auth)

GET  /TwoFactorAuth/Devices                              — own trusted devices (auth)
DELETE /TwoFactorAuth/Devices/{id}                       — revoke own trusted device (auth)
POST /TwoFactorAuth/Devices/Register                     — pre-register device ID (auth)
```

### Admin-only (`RequiresElevation`)
```
GET    /TwoFactorAuth/Users                              — all users with 2FA status
POST   /TwoFactorAuth/Users/{id}/Toggle                  — enable/disable 2FA for user
GET    /TwoFactorAuth/AllTrustedDevices                  — devices across all users
DELETE /TwoFactorAuth/Users/{userId}/Devices/{deviceId}  — admin revoke
GET    /TwoFactorAuth/AuditLog                           — login history
GET    /TwoFactorAuth/Pairings                           — pending TV pairings
POST   /TwoFactorAuth/Pairings/{code}/Approve            — approve pairing
POST   /TwoFactorAuth/Pairings/{code}/Deny               — deny pairing
GET    /TwoFactorAuth/ApiKeys                            — list managed API keys
POST   /TwoFactorAuth/ApiKeys                            — generate new API key
DELETE /TwoFactorAuth/ApiKeys/{id}                       — delete API key
POST   /TwoFactorAuth/Sessions/{id}/Revoke               — revoke an active session
```

---

## 🔒 Security model

| Threat | Mitigation |
|---|---|
| Stolen password (no 2FA bypass) | All sessions blocked until 2FA completed; correct password alone gives 401 on every API call |
| TOTP brute force on the 6-digit code space | Per-IP rate limit (10/min on verify, 10/min on auth), per-challenge attempt limit (5), per-user lockout (5 failures → 15min) |
| Stolen recovery code | Marked used immediately on validation regardless of password outcome — can't be retried |
| Stolen trust cookie | HMAC-SHA256 signed with persistent server-side key; HttpOnly, Secure, SameSite=Strict; tied to a server-side trust record (revocable) |
| Account enumeration | Identical "invalid credentials" message whether password is wrong, user doesn't exist, or 2FA code is wrong |
| Disk corruption mid-write | Atomic write-then-rename for all user state files |
| TOTP secret theft from disk | AES-GCM encrypted with persistent 32-byte key |
| Replay attacks on TOTP | Used time-steps tracked per user |
| Timing attacks | `CryptographicOperations.FixedTimeEquals` on all secret comparisons |
| Service integrations breaking | Standard Jellyfin API keys bypass user auth — Sonarr/Radarr unaffected |
| Authelia/Authentik breaking native apps | Native plugin, no proxy dependency |

---

## ⚠️ Limitations

- **Mobile apps (Swiftfin, Findroid)** — these don't support a 2FA flow yet. Workaround: do a 2FA login via web on the same device first; mobile clients can then use the resulting session token. A native mobile flow requires app-side changes.
- **TV pairing flow** — backend exists, no TV-side UI yet. Use trusted device tokens or admin pre-registration of device IDs.
- **Quick Connect** — works as Jellyfin's normal flow but creates a session subject to 2FA enforcement (user will be blocked until they complete 2FA via `/TwoFactorAuth/Login`).
- **Email OTP requires admin to set per-user email** — Jellyfin's user entity doesn't expose email consistently across versions, so admins enter emails in the Users tab.
- **Cookie isn't bound to IP** — a stolen trust cookie works from any IP for 30 days, within the signed deviceId. Revoke the device in admin if a browser is compromised.

---

## 📝 Changelog

### 2.2.0 — Hardening + performance

**Hardening**
- Internal hardening pass on the auth pipeline: cookie attribute handling behind reverse proxies, stricter forwarded-header handling, additional input bounds on auth endpoints, tightened token binding.
- Trusted-browser cookie now correctly carries the `Secure` flag when Jellyfin sits behind a TLS-terminating proxy (Cloudflare, Caddy, nginx, Traefik). Enable by setting **TrustForwardedFor** + **TrustedProxyCidrs** in plugin settings.

**Performance**
- In-memory caches on the hot auth path: per-user data, audit log, parsed CIDRs, and the patched `/web/` index. Disk I/O on every login is now near-zero.
- Login latency improved by replacing an internal polling wait with immediate signaling — fewer 50–500ms ticks per successful sign-in.
- Audit log is now background-flushed instead of rewritten on every event, and stored as compact JSON. Existing logs continue to read fine.

**No breaking changes.** In-place upgrade — existing TOTP enrollments, passkeys, OIDC links, trusted browsers, paired devices, and audit history all carry over.

### 2.1.0 — Passkey primary login

**New**
- **"Sign in with passkey" button** on the standard Jellyfin login page, below the 2FA button. Type username → click → authenticator prompt (Face ID / Touch ID / Windows Hello / YubiKey) → signed in. No password needed, no 2FA challenge layered on top. Uses the same one-shot bridge-token mechanism as OIDC.
- New endpoints `POST /TwoFactorAuth/Passkey/LoginBegin` + `POST /TwoFactorAuth/Passkey/LoginComplete` (anonymous, rate-limited 20/5min per IP).

**Fix**
- `inject.js` now served with `Cache-Control: no-store` so CDN / reverse-proxy caching doesn't pin old script after plugin upgrades. If you hit this on v2.0 (Cloudflare 24h default), just upgrade — new buttons and hardening now appear immediately without a manual purge.

**Note**: WebAuthn requires a secure context (HTTPS, or plain localhost). The passkey button is hidden when accessing Jellyfin over plain-HTTP LAN IPs — that's a browser rule, not a plugin limit.

### 2.0.0 — Jellyfin Security

**Plugin rename** from "Two-Factor Authentication" to "Jellyfin Security" (GUID unchanged — upgrades in place). The plugin now spans the whole auth + hardening stack.

**New features**
- **OIDC / SSO sign-in** — Google, Microsoft, Apple, Authelia, Authentik, Keycloak, PocketID, Cloudflare Access, or any OIDC-compliant provider via discovery. PKCE (S256), id_token signature + issuer + audience + nonce validation, optional AMR-based IdP-MFA enforcement, optional group allowlist.
- **Brute-force IP banning** — threshold + window + duration configurable. LAN / trusted-proxy / exempt CIDRs never banned. Bans persist across restarts. Admin IP Bans tab lists/unbans.
- **Impossible-travel detection** — Haversine distance vs. time exceeding configured km/h fires a notification via existing channels. Uses GeoLite2-City.
- **Per-user IP allowlist** — pin high-value accounts to specific CIDRs. Self-service in Setup.
- **Login-page provider buttons** — anonymous public-providers endpoint; inject.js renders "Sign in with X" below the normal form.
- **OIDC bridge auth** — server-side one-time bridge tokens wire the OIDC success back into a Jellyfin session without relying on fragment params or the SPA router. Auto-reassigns the user's `AuthenticationProviderId` on first link so bridge tokens authenticate correctly.
- **Admin UI refresh** — pill-style tab bar, new **Sign-in Methods** and **IP Bans** tabs, new Settings sections for brute-force and impossible-travel.

**Security hardening**
- `X-Forwarded-Host` / `Proto` only honoured when direct peer is in `TrustedProxyCidrs` (prevents redirect_uri poisoning).
- Rate limit on `/Oidc/Login` (20 per 5 min per IP).
- Bridge HTML uses `JsonSerializer.Serialize` for JS context injection + strict CSP + `Cache-Control: no-store`.
- `returnUrl` on sign-in validated to same-origin relative paths.
- New `/TwoFactorAuth/MyStatus` (auth-only) so the user Setup page shows correct TOTP state without admin permission.

**Bug fixes**
- TOTP replay cache now cleared on new-secret generation — fixed "Invalid code" false-positive when Begin Setup ran twice.
- Setup page no longer silently shows "NOT SET UP" for non-admin users (was calling admin-only `/Users` endpoint).

### 1.4.2 — Fix gzip-encoded `/web/` corruption

**Critical fix for anyone upgrading to 1.4.x.** The IndexHtml injection middleware (which inserts `<script src="/TwoFactorAuth/inject.js">` into Jellyfin's main index page) was reading the response buffer as UTF-8 text without checking `Content-Encoding`. When Jellyfin served the pre-gzipped `index.html.gz` static asset, the middleware read compressed bytes as text, mangled them, and wrote garbage back — the browser then tried to render the binary gzip payload as text, producing a wall of mojibake and the entire web UI refusing to load.

**Fix:** strip `Accept-Encoding` from the incoming `/web/` request before the response is generated, so Kestrel's static-file handler responds with identity-encoded HTML we can safely inject into. Only applied to the three specific paths the middleware intercepts (`/web/`, `/web`, `/web/index.html`) — other assets still compress normally. Cost: one uncompressed ~50KB HTML per page load. Negligible.

If you're on 1.4.0 or 1.4.1 and the web UI renders as random characters, upgrade.

### 1.4.1 — Tizen / reverse-proxy bug fix

**Critical regression fix.** Samsung Tizen (Smart TV) clients behind any reverse proxy (Caddy, nginx, Cloudflare Tunnel, etc) couldn't sign in after upgrading to v1.4 — password entry returned "Invalid username or password" immediately. Root cause: the TV's `AuthenticateByName` request arrives at the server without an `X-Emby-Device-Id` header and with a reformatted `X-Emby-Authorization` that the plugin's parser couldn't extract a deviceId from. No deviceId meant paired-device and registered-device bypasses silently skipped, and the middleware rewrote the auth response as a 2FA challenge — which the native Tizen app can't render, so it just looped on "Invalid".

**Fixes:**
- Enforcement middleware now reads `SessionInfo.DeviceId` from Jellyfin's auth response body as a fallback when request headers don't carry a deviceId. That value is always present and authoritative.
- `RegisteredDeviceIds` bypass lookup now uses the same UA-hash normalisation as `PairedDevices` so Tizen webview deviceIds (which include a per-session timestamp suffix that changes on every app restart) match across restarts.
- Removed dev-only diagnostic log lines accumulated during the investigation.

If you're on Tizen / Jellyfin for Smart TV and couldn't sign in after v1.4, this release fixes it. No re-pair needed.

### 1.4.0 — Passkeys + safety net

**New factors**
- **Passkeys / WebAuthn** as a 2nd-factor option. Sign in with Face ID, Windows Hello, Touch ID, a YubiKey, or any FIDO2 authenticator. Phishing-resistant (signature is bound to your domain). Add and remove passkeys from Setup → Passkeys. Passkey verification replaces the OTP step at the 2FA challenge — username + password still happen first.

**User self-service**
- **"I lost my phone" emergency lockout** — single button on Setup. Terminates every session, revokes every trusted/paired device, requires recovery code or email OTP to sign back in.
- **TOTP secret rotation** — replace your authenticator seed without admin involvement (current code + a recovery code).
- **Recovery codes PDF + print** — download as PDF or print directly from the browser instead of the .txt download.
- **QR-pair-from-phone** — Setup page renders a QR an already-signed-in phone can scan to add this browser as a paired device. Reverse direction of the existing TV pairing.
- **`autocomplete="one-time-code"`** on the OTP input — iOS picks codes from Messages.

**Admin tools**
- **Overview / adoption dashboard** — % enrolled, recent enrollments, failed verifies + lockouts in last 24h, users past the configured enrollment deadline.
- **Diagnostics tab** — run a green/red checklist (signing keys readable, audit chain intact, IAuthenticationProvider registered, recovery hash format upgrade complete, GeoIP DBs loaded, etc.).
- **Rate-limit observability** — see when buckets trip, key by key, since last restart.
- **Bulk user actions** — disable 2FA / rotate recovery / revoke paired / revoke trusted / force logout, applied across N users at once.
- **User search + filter** in the Users tab.
- **Force-logout user** button per row — kills every session, clears trust state.
- **Per-user GDPR export** — JSON dump of everything we have on file (no secrets).
- **Webhook events** — POST `{event, user, ip, timestamp, payload}` to any URL. Optional HMAC-SHA256 signature header (`X-2FA-Signature: sha256=...`) computed over `<unix-timestamp>.<body>`. The unix timestamp is also exposed as `X-2FA-Timestamp` so receivers can do replay/skew checks without parsing the JSON body. Events: lockout, new device, recovery used, suspicious login, passkey registered, TOTP rotated, emergency lockout, admin force-logout.<br><br>**Privacy note:** webhook payloads include the username, source IP, device name, and (for suspicious-login events) ASN + country code. Don't send webhooks to a third-party service you wouldn't share that data with. The plugin refuses to dispatch to RFC1918, loopback, link-local (incl. cloud metadata 169.254/16) or IPv6 private/link-local addresses as a basic SSRF guard.
- **Suspicious-login alerts** — first sign-in from a never-seen ASN/country fires a notification. Requires admin to drop free MaxMind GeoLite2 .mmdb files into the config dir (paths configurable in Settings).

**Security & integrity**
- **Audit log hash chain** — each entry's hash chains the previous, so silent tampering with `audit.json` is detectable. The Diagnostics tab verifies the chain on demand.
- **Per-user concurrent-session cap** — admin sets a default and per-user override; oldest non-paired sessions get evicted when over the limit.
- **NAT-hairpin self-IP bypass** (opt-in) — admin can have the plugin auto-discover the server's public IP at startup and treat hairpinned requests as LAN. Documented with an explicit warning about the IoT/guest-WiFi blast radius.

**Tunables**
- Pre-verify window (the brief allowance after a successful verify so follow-up sessions go through) — configurable 30s–900s.
- Trust cookie TTL — configurable 1d–90d.
- Optional enrollment deadline — flagged on the Overview dashboard.

**New dependencies bundled** (Linux x64 native libs included; Windows / macOS users currently need Docker or to manually supply `libsodium`):
- Fido2NetLib (MIT) — FIDO2 / WebAuthn server-side
- MaxMind.Db (Apache 2.0) — offline ASN/country lookup
- QuestPDF (Community license — free under USD 1M revenue) — recovery-codes PDF render

### 1.3.3 — Security hardening

**Critical fixes**
- Trust cookie now signs the `deviceId` and expiry into the payload. A stolen cookie can no longer be replayed with an attacker-chosen `X-Emby-Device-Id` header (device substitution bypass). Cookie rotates on every use.
- Token-approval race between the SessionStarted event handler and response-intercept middleware is now bound to `(userId, deviceId, token)` and single-consume — closes a narrow timing window that could leak a bypass.
- Recovery codes upgraded from plain SHA-256 to PBKDF2-SHA256 (100k iters, per-code salt). Legacy codes still validate seamlessly; new generations write the hardened format.
- Open redirect in `/TwoFactorAuth/Challenge?return=` closed — same-origin check with `javascript:` / `data:` / `file:` rejection.

**High-severity fixes**
- `PairedDevice` / `TrustedDevice` `deviceId` comparisons are now case-sensitive (`Ordinal`). Previously `OrdinalIgnoreCase` allowed case-variant bypass.
- Pairing approve refuses records with `Guid.Empty` user or empty `deviceId` (phantom-user write prevention).
- `RegisteredDeviceIds` capped at 50 per user with 128-char printable-ASCII validation — no more storage-inflation DoS.
- `IsAuthPath` is now anchored to `^/Users/…` instead of substring `Contains` — closes a confused-deputy path where a third-party plugin's response could be rewritten as a 2FA challenge.
- `X-Frame-Options: DENY`, `CSP frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` on all embedded pages (anti-clickjacking).
- Rate limiter is now reverse-proxy aware via `TrustForwardedFor` + `TrustedProxyCidrs`. IPv6 is bucketed by `/64` to prevent host-rotation bypass.
- `/Verify` now has a per-user rate limit (15 per 15 min) in addition to per-IP.
- `/Pairings/Initiate` input (`Username`, `DeviceName`) sanitized against control characters and HTML-significant bytes; length-capped at 64.

**Medium-severity fixes**
- `inject.js` redirects to a hardcoded `/TwoFactorAuth/Challenge?token=…` path instead of trusting the server body's `ChallengePageUrl`.
- `TestSmtp` admin endpoint no longer echoes `ex.Message` — full detail goes to server logs.
- Device revocation (both paired and trusted) wipes in-memory pre-verified flags and calls `Logout(accessToken)` on any live session for that device.
- `PairConfirm` records a short-TTL seen-signature set — the same signed pairing token can only be used once.
- API keys are now stored as SHA-256 hash + short preview. Raw key is shown once on create. Legacy plaintext keys auto-migrate on first load; the API key listing never returns the raw secret.
- `CookieSigner.Verify` length-checks signatures before `FixedTimeEquals` to eliminate the throw/non-throw timing oracle.

**Quality of life**
- Settings tile now renders inline with Profile/Quick Connect/Display under the user section of themed drawers (JellyFlare, StarTrack, KefinTweaks). Previously appeared in a floating bottom-left position.
- Dev-only log chatter moved to Debug. Info/Warn retained only for audit-worthy events (challenge issued, bypass applied, lockout, paired device added/revoked).
- LAN bypass now auto-registers the `deviceId` and clears stale pending pairings for the same device — browsers that alternate between LAN and Cloudflare (NAT hairpin) no longer accumulate pending entries.

### 1.3.2

- Fixed DI circular dependency when registering `IAuthenticationProvider` (`TwoFactorAuthProvider` now resolves `IUserManager` lazily via `IApplicationHost`).
- Samsung Tizen / Jellyfin for Tizen pairing works end-to-end.
- Login loop fixed by removing access-token blocking — middleware response-intercept is now the only gate.

---

## ❤ Support the project

2FA for Jellyfin is built and maintained in my spare time. If it's protecting your server and you'd like to support ongoing development, any of these means a lot:

- ⭐ **Star this repo** — it's free and helps others find it
- 💖 **[Sponsor on GitHub](https://github.com/sponsors/ZL154)** — one-off or monthly, every dollar reaches the project
- ☕ **[Buy me a coffee on Ko-fi](https://ko-fi.com/zl154)** — one-off tips

Not expected, just appreciated. Security issues reported responsibly are equally valuable.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

| You can | You must | You cannot |
|---------|----------|------------|
| Use on any server, personal or commercial | Keep the copyright notice in any redistribution | Hold the authors liable for damage |
| Fork and modify | | Claim author endorsement of your fork |
| Redistribute, modified or unmodified | | |

---

⭐ If you use this plugin, consider starring the repository.

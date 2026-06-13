<p align="center">
  <img src="assets/logo-banner.png" alt="Jellyfin Security" width="100%" />
</p>

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
  <!-- Static version badge — bump on each release. Switched from img.shields.io/github/v/release because that endpoint periodically returns 'unable to select next GitHub token from pool'. -->
  <img src="https://img.shields.io/badge/Version-v2.5.9-00a4dc?style=for-the-badge&labelColor=000000&color=00a4dc" />
  <img src="https://img.shields.io/badge/License-MIT-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
</p>

<p align="center">
  <a href="https://github.com/ZL154/JellyfinSecurity/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ZL154/JellyfinSecurity/ci.yml?branch=main&style=for-the-badge&labelColor=000000&label=CI&logo=github&logoColor=white" alt="CI" /></a>
  <a href="https://github.com/ZL154/JellyfinSecurity/actions/workflows/codeql.yml"><img src="https://img.shields.io/github/actions/workflow/status/ZL154/JellyfinSecurity/codeql.yml?branch=main&style=for-the-badge&labelColor=000000&label=CodeQL&logo=github&logoColor=white" alt="CodeQL" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/ZL154/JellyfinSecurity"><img src="https://img.shields.io/ossf-scorecard/github.com/ZL154/JellyfinSecurity?style=for-the-badge&labelColor=000000&label=OSSF%20Score&color=00a4dc" alt="OpenSSF Scorecard" /></a>
  <a href="https://github.com/ZL154/JellyfinSecurity/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-254%20passing-00a4dc?style=for-the-badge&labelColor=000000&logo=xunit&logoColor=white" alt="Tests" /></a>
  <a href="https://github.com/ZL154/JellyfinSecurity/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b&logo=gitbook&logoColor=white" alt="Security policy" /></a>
</p>

<p align="center">
  <a href="https://github.com/ZL154/JellyfinSecurity/stargazers"><img src="https://img.shields.io/github/stars/ZL154/JellyfinSecurity?style=for-the-badge&labelColor=000000&label=Stars&color=00a4dc&logo=github&logoColor=white" alt="Stars" /></a>
  <!-- Static last-commit badge — bump when pushing meaningful changes. img.shields.io/github/last-commit is the most rate-limited GitHub-API endpoint in the shields family and has been intermittently unavailable. Static avoids it. -->
  <a href="https://github.com/ZL154/JellyfinSecurity/commits/main"><img src="https://img.shields.io/badge/Last%20commit-2026--05--30-2b2b2b?style=for-the-badge&labelColor=000000&color=2b2b2b&logo=github&logoColor=white" alt="Last commit" /></a>
  <a href="https://github.com/ZL154/JellyfinSecurity/security/advisories"><img src="https://img.shields.io/github/issues-search/ZL154/JellyfinSecurity?style=for-the-badge&labelColor=000000&label=Open%20advisories&query=is%3Aopen%20label%3Asecurity&color=00a4dc&logo=github&logoColor=white" alt="Open security advisories" /></a>
</p>

# 🔐 Jellyfin Security

Comprehensive authentication and hardening for Jellyfin: TOTP, passkeys, email OTP, **OIDC/SSO sign-in**, brute-force IP banning, impossible-travel detection, per-user IP allowlist, device pairing, trusted-browser cookies, and a full audit log — all from one plugin.

> **Why this exists:** for self-hosters who want a complete auth + hardening layer **without standing up a separate identity stack**. Full IdPs like Authentik (with OIDC or LDAP outposts) and Authelia work great with Jellyfin and offer features this plugin doesn't — they're often the right call for serious deployments. This plugin is for the case where you'd rather get TOTP, passkeys, OIDC sign-in, brute-force protection, impossible-travel detection, IP allowlist, audit logging, and a proper admin UI **as a single Jellyfin plugin** — no extra containers, no LDAP outpost, no proxy-auth header juggling, native Jellyfin user model end-to-end.

---

## 🛡️ Security posture — what to check before you trust this with your server

You don't have to take my word for it. Every signal below is automated and
visible to anyone, including you:

- **[CI badge](https://github.com/ZL154/JellyfinSecurity/actions/workflows/ci.yml)** — every push and PR builds and runs the full xUnit test suite (254 tests covering crypto, parsers, and middleware). Green = tests pass.
- **[CodeQL badge](https://github.com/ZL154/JellyfinSecurity/actions/workflows/codeql.yml)** — GitHub's static security scanner runs the `security-extended` + `security-and-quality` C# query packs on every push, PR, and weekly. Green = no security findings.
- **[OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/ZL154/JellyfinSecurity)** — the Linux Foundation's automated security-posture rating (0–10). Scores branch protection, CodeQL, dependency updates, pinned actions, signed releases, security policy, token permissions, and more. Click the badge to see the per-check breakdown.
- **[Test suite](https://github.com/ZL154/JellyfinSecurity/actions/workflows/ci.yml)** — 254 xUnit tests covering the security-critical code paths (cookie HMAC, TOTP replay protection, recovery-code PBKDF2, CIDR parser, X-Forwarded-For trust-walk, refuse-LAN-bypass-when-XFF-missing guard, device-token binding, AES-GCM v2 AAD, HIBP k-anonymity hashing, atomic challenge consumption, OIDC redirect_uri proxy-header resolution, OIDC userinfo claim merge, SMTP port 465 socket-option mapping, step-up code verification, step-up action classification, ChallengeStore step-up tokens). Runs on every PR + push.
- **[Open security advisories](https://github.com/ZL154/JellyfinSecurity/security/advisories)** — historical vulnerabilities filed via [SECURITY.md](SECURITY.md), with patch versions, severity, and CVE references.
- **[Dependabot PRs](https://github.com/ZL154/JellyfinSecurity/pulls?q=is%3Apr+author%3Aapp%2Fdependabot)** — security and version updates for every NuGet dependency. Frequent merges = vulnerabilities don't sit unpatched.
- **[Pull request review history](https://github.com/ZL154/JellyfinSecurity/pulls?q=is%3Apr+is%3Aclosed)** — non-trivial changes go through review even when the maintainer is solo, and the diff is public.
- **[Release SHA-256 checksums](https://github.com/ZL154/JellyfinSecurity/releases)** — every release ships with `.md5` and `.sha256` files alongside the `.zip` so you can verify the artifact wasn't tampered with after upload.
- **[Threat model in SECURITY.md](SECURITY.md#threat-model--what-this-plugin-defends-against)** — explicit list of what the plugin defends against and what it intentionally does not. No hand-waving "secure by design" claims.

If any of these go red, file an issue or DM `@zack154` on Discord — fixing
visible trust signals is treated as a high-priority bug.

---

## 🆕 What's new in v2.5.8

- **Admin Save Settings now triggers the step-up modal** *(fix #57)* — when `StepUpLevel` is set to `AllConfigChanges` or above, clicking Save in the admin UI used to silently fail with no UI prompt because the main config save call went through Jellyfin's built-in ApiClient helper, which doesn't know about the plugin's `stepUpRequired` response. Re-wired through the existing step-up-aware fetch wrapper so the same TOTP modal that gates every other admin action now also gates plugin-config saves.
- **`StepUpLevel` dropdown persists across saves** — enum-serialization mismatch was making the dropdown go blank after every save, and silently posting `0` (Off) which reset the level on the server. The dropdown's `<option value=>` strings now match Jellyfin's `JsonStringEnumConverter` wire format.
- **Admin Users tab shows ALL Jellyfin users** *(fix #55 followup, Dasnap)* — previously listed only users with plugin-side data files, so users who'd never interacted with the plugin were invisible until their next login. Enumeration now starts from Jellyfin's user table and merges plugin data per user, defaulting to all-zero counts for unenrolled users. Single-user read failures no longer 500 the whole listing.
- **Trusted-proxy CIDR misconfig guidance** *(fix #56, derpacco)* — admins typing broad RFC1918 ranges (e.g. `10.0.0.0/8`) into Trusted Proxy CIDRs caused LAN bypass to silently refuse for every LAN client (the SEC-H3 guard from v2.4.12 can't distinguish "stale-XFF proxy" from "direct LAN client in a broad range"). Added a help block under the admin field spelling out the trap, and promoted the SEC-H3 refusal log to Information level on first hit per peer IP so admins see the actionable diagnostic in their logs without filtering for Debug.
- **Pending-pair Deny / Approve / QR buttons no longer fail silently** — wrapped each click handler so a server error surfaces via `alert` + `console.error` instead of leaving the button looking dead. Touches the disabled-during-request UX too.
- **Textarea clipping fixed** — `.tfa-input` now uses `box-sizing: border-box` so `width:100%` textareas (LAN CIDRs, Trusted Proxy CIDRs, Admin emails, Exempt CIDRs, Restore JSON) sit inside their parent panels instead of bleeding the horizontal padding outside.
- **Two CodeQL alerts dismissed as false positives** — `cs/cleartext-storage-of-sensitive-information` on the SEC-H3 log line was flagging CIDR strings as if they were credentials. CIDRs are admin-configured network topology, already in cleartext in `PluginConfiguration.xml` by necessity, and the SEC-H3 diagnostic depends on surfacing the matched CIDR.
- 254/254 tests pass. In-place upgrade — every persisted record carries over.

---

## 🆕 What was new in v2.5.7

- **OIDC step-up for users** — users who only have an IdP linked (no TOTP / passkey / recovery code / email OTP) can now satisfy `SelfServiceStepUpMode=Forced` by re-authenticating to that IdP in a popup. Subject match against the stored `SsoLink` is enforced, so signing into a different IdP account doesn't grant step-up.
- **Verified-session state survives restart** *(fix #52)* — `/Users/Foo` getting 403'd by `RequestBlockerMiddleware` after `docker compose down/up` is gone. The plugin now persists SHA-256 hashes of verified tokens to a sidecar JSON, so the in-memory verified-set is rehydrated on every restart instead of locking out every active session.
- **OIDC private / VPN / LAN endpoints** *(fix #54)* — new per-provider toggle lets you point the plugin at a LAN-only Authentik / Authelia / Pocket ID / etc. without the v2.5.5 SSRF guard rejecting it. Public-Internet IdPs keep the strict guard.
- **Hide built-in 2FA / Passkey login buttons** *(feature #48)* — two independent admin toggles for OIDC-only deployments. Pick any combination of "show 2FA", "show passkey", "show neither" — your configured IdP buttons stay visible regardless.
- **User-listing crash fix** *(fix #55)* — junk `Guid.Empty` lockout entries from brute-force testing no longer 500 the Users tab. Two layers: defensive skip in the listing + write-refuse at the store boundary.
- **Login-page 8-digit OTP fix** *(fix #50)* — the embedded login page now accepts 8-digit email OTP codes; the v2.5.5 brute-force hardening changed the digit count but `login.html` was missed. Thanks to **@duongynhi000005-oss** for the PR.
- **Better error feedback on pending-pair actions** — Approve / Deny / QR buttons now show a spinner during the request and surface server errors via alert + `console.error`, instead of silently looking dead.
- 254/254 tests pass. Clean build with `TreatWarningsAsErrors=true`. In-place upgrade — every persisted record (TOTP, passkeys, OIDC links, trusted browsers, paired devices, audit history) carries over. *(Shipped 2026-06-05.)*

---

## 🆕 What was new in v2.5.6

- **Critical: bare DeviceId can no longer bypass 2FA.** New `BareDeviceIdBypassEnabled` flag (default off). The signed trusted-device cookie path is unchanged.
- **Issue #28 — OIDC redirect_uri behind TLS-terminating proxies.** New providers default to `ForceHttps=true`; existing providers also get https automatically.
- **Issue #48 — OIDC pre-existing-user link.** No more duplicate-user errors when a Jellyfin user with the matching username already exists.
- **Issue #49 — login showed "incorrect username or password" instead of 2FA.** Race between `inject.js` and Jellyfin's bundled scripts fixed.
- **Issue #50 — Email OTP digit-count UI mismatch.** Server-side fix (login.html caught up in v2.5.7).
- **Hardened self-service** (`SelfServiceStepUpMode`, default `Forced`) — adding/replacing TOTP, recovery codes, app password, or passkey now requires proof of an existing factor.
- **Email step-up** — for users who don't have TOTP/passkey but do have email, the step-up modal can mail them an 8-digit code.

---

## 🆕 What was new in v2.5.5

- **OIDC empty-password sign-in path** closed. Auto-provisioned OIDC users now get a 256-bit random password at creation so Jellyfin's default auth provider stops treating them as accepting any password.
- **TOTP rotate endpoint** fixed — earlier versions rejected the current code unconditionally.
- **General security hardening**: OIDC token algorithm allowlist, OIDC discovery URL validation, recovery-code PBKDF2 iteration bump, email-OTP storage hardening, GeoIP path validation, log scrubbing, and a handful of small race fixes.
- **`BlockEmptyPasswordLogin`** (default off) — when true, the plugin refuses empty/whitespace passwords for all users.

---

## 🆕 What was new in v2.5.4

- **Issue #35 — Cloudflare Tunnel re-block after legit login.** All four legitimate-bypass branches now call `MarkTokenVerified` so the 30-day verified flag short-circuits later `SessionStarted` re-evaluations regardless of proxy IP rotation.
- **Jellyfin 10.11.10 SDK bump** with the `IUserManager.Users` property → `GetUsers()` method rename handled via reflection so the same DLL still loads on 10.11.0–10.11.9.

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
- [Step-up authentication (v2.5)](#-step-up-authentication-v25)
- [Encrypted configuration exports (v2.5)](#-encrypted-configuration-exports-v25)
- [Security score & admin overview (v2.5)](#-security-score--admin-overview-v25)
- [Internationalization (v2.5)](#-internationalization-v25)
- [Indefinite device trust (v2.5)](#-indefinite-device-trust-v25)
- [Hardened self-service factor changes (v2.5.6)](#-hardened-self-service-factor-changes-v256)
- [OIDC step-up factor for users (v2.5.7)](#-oidc-step-up-factor-for-users-v257)
- [Hide built-in 2FA / Passkey login buttons (v2.5.7)](#-hide-built-in-2fa--passkey-login-buttons-v257)
- [OIDC private / VPN / LAN endpoints (v2.5.7)](#-oidc-private--vpn--lan-endpoints-v257)
- [Verified-token persistence (v2.5.7)](#-verified-token-persistence-v257)
- [SMTP setup (email OTP)](#-smtp-setup-email-otp)
- [Recovery — locked out](#-recovery--locked-out)
- [Troubleshooting](#%EF%B8%8F-troubleshooting)
- [Architecture](#-architecture)
- [API endpoints](#-api-endpoints)
- [Security model](#-security-model)
- [Limitations](#-limitations)
- [Changelog](#-changelog)
- [Credits](#-credits)
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

### Added in v2.5.4 – v2.5.7
- **OIDC step-up factor** — re-authenticate to a linked IdP in a popup to satisfy hardened-security step-up, with subject-match against the stored `SsoLink`.
- **Hardened self-service** (`SelfServiceStepUpMode` — `Off` / `UserChoice` / `Forced`, default `Forced`) — proof of an existing factor is required before adding/replacing TOTP, recovery codes, app password, or passkey.
- **Email step-up codes** — users with email but no TOTP/passkey can request an 8-digit code by mail to clear the step-up gate.
- **OIDC private / VPN / LAN endpoints** — per-provider toggle to allow private-IP IdPs without weakening the v2.5.5 SSRF guard for the public-Internet ones.
- **Hide built-in 2FA / Passkey login buttons** — independent admin toggles for OIDC-only deployments.
- **`BlockEmptyPasswordLogin`** — when true, refuses empty/whitespace passwords for all users.
- **`BareDeviceIdBypassEnabled` flag** — gates the registered/paired-device-without-cookie fallback (default off; signed trusted-device cookies unaffected).
- **Verified-session persistence** — SHA-256 hashes of verified tokens survive process restart so active sessions don't get re-blocked.

### New in v2.5
- **Step-up authentication** — configurable level (`Off` / `Destructive` / `AllConfigChanges` / `Everything`) re-prompts for 2FA on sensitive admin actions.
- **Encrypted configuration exports** — passphrase-protected (AES-256-GCM, PBKDF2-SHA256 600k iter) versioned export envelopes for back-up / migration.
- **12-factor security score** — coverage, admins, enforcement, audit chain, IP ban, impossible-travel (functional check), HIBP, clean-7d audit, require-to-disable, step-up, webhook, recovery codes. Raw 130 pts normalized to a 100 ceiling.
- **Admin Dashboard Overview** — auth-activity stacked-area chart with 1w / 1m / 1y range selector, hover tooltips, dashed gridlines, x-axis date markers, server-side bucket backfill.
- **Internationalization (8 languages)** — en / de / es / fr / it / ja / pt / zh at full key parity. Native-name picker. Per-user preference + server-wide default + URL `?lang=` override.
- **Indefinite device trust (opt-in)** — admin-gated `AllowIndefiniteTrust` flag; users can mark individual trusted browsers / paired devices to never expire.
- **Audit-chain rebuild** — admin action (step-up gated) to repair audit-log hash continuity after disk corruption.
- **`RequireTwoFactorToDisable`** — re-prompts for 2FA before a user can disable their own 2FA.

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

> **Requires Jellyfin 10.11+.** The plugin depends on the auth-provider APIs introduced in 10.11. If your server is on 10.10.x or older, the plugin will **not appear in the Catalogue** after adding the repository — Jellyfin silently filters out plugins whose `targetAbi` is newer than the server. Check your version under **Dashboard → About**; upgrade to 10.11+ if needed.

1. Open Jellyfin → **Dashboard → Plugins → Repositories**
2. Click **+** and add this URL:

```
https://raw.githubusercontent.com/ZL154/JellyfinSecurity/main/manifest.json
```

3. Save and refresh plugins
4. Go to the **Catalogue** tab → install **Jellyfin Security**
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
- **Hardening (v2.5)** — `RequireTwoFactorToDisable` (re-prompts before a user can self-disable 2FA), `StepUpLevel` (which admin actions re-prompt for 2FA), `AllowIndefiniteTrust` (gates the user-side opt-in for never-expiring trust), `DefaultLanguage` (server-wide UI default; users can still override per-user)
- **Audit chain (v2.5)** — **Rebuild audit chain** button repairs the hash chain after disk corruption / manual edits (step-up gated)

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
4. **Authorised redirect URIs** — leave this open for now, we'll fill it in step 2c with the exact URL the plugin shows you.
5. Save. Copy the **Client ID** + **Client secret** from the dialog.

**2. Add the provider in Jellyfin**
1. Jellyfin admin → Plugins → **Jellyfin Security** → **Sign-in Methods** tab → "Add provider…"
2. Preset: **Google**. Paste Client ID + Secret. **Username claim:** `email`. Save.
3. After save, the provider list shows the **exact `redirect_uri` to register at the IdP** — it's `https://YOUR-JELLYFIN-HOSTNAME/TwoFactorAuth/Oidc/Callback/<slug>`, where `<slug>` is derived from the **Display name** you chose (e.g. *Google* → `google`, *Login with Google* → `login-with-google`). **Go back to Google Cloud Console → Credentials → your OAuth client → add this exact URL to Authorised redirect URIs** and save. If the slug doesn't match what's registered, the IdP returns `redirect_uri_mismatch` and sign-in fails (issue #28).

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

## 🔐 Step-up authentication (v2.5)

Re-prompts the admin for a fresh 2FA challenge before sensitive operations. Defends against a logged-in session being hijacked or left unattended on a workstation.

**Configure:** Jellyfin Security → **Settings → Hardening → Step-up level**:

| Level | What re-prompts |
|---|---|
| `Off` | Nothing. (Default — opt in deliberately.) |
| `Destructive` | Deleting users, wiping 2FA state, rebuilding the audit chain, removing OIDC providers. |
| `AllConfigChanges` | All of `Destructive`, plus toggling settings, editing SMTP / push / brute-force / impossible-travel config. |
| `Everything` | All of `AllConfigChanges`, plus viewing audit log, listing IP bans, exporting config. (Strongest — least convenient.) |

**How the flow looks**:
1. Admin clicks a gated action (e.g. **Rebuild audit chain**).
2. UI shows a 2FA challenge modal.
3. Admin enters the 6-digit code (or passkey / recovery code).
4. Action proceeds. Step-up token is single-use; re-prompts next time.

**Related setting**: `RequireTwoFactorToDisable` — when on, users can't disable their own 2FA without entering a fresh code first. Stops a stolen session cookie from being used to switch 2FA off.

---

## 📦 Encrypted configuration exports (v2.5)

Back up or migrate plugin configuration (settings, OIDC providers, trusted CIDRs, brute-force config, etc.) without leaking secrets.

**Export (admin)**:
1. Admin dashboard → **Config → Export**.
2. Enter a passphrase (10+ chars recommended; longer is better).
3. Download the `.json.enc` envelope. Treat it like a password — its strength is the passphrase's.

**Import (admin)**:
1. Admin dashboard → **Config → Import**.
2. Upload the `.json.enc` file → enter the same passphrase → review the preview of what will change → confirm.

**Crypto envelope** (so you can audit it):
- **KDF**: PBKDF2-SHA256, 600 000 iterations, 32-byte derived key, 16-byte random salt per export.
- **Cipher**: AES-256-GCM with 12-byte random nonce.
- **AAD**: Plugin version + envelope version, so an export captured under v2.5 can't be replayed against a future incompatible schema.
- **Versioned envelope**: `{ "v": 1, "salt": "...", "nonce": "...", "ct": "...", "tag": "..." }` — future versions can change parameters without breaking decryption of older exports.

⚠ **No back door**: a lost passphrase means the export is unrecoverable. The plugin author cannot decrypt your file. Store the passphrase in your password manager *separately from the export file*.

---

## 📊 Security score & admin overview (v2.5)

A 12-factor security score (raw 130 points, normalized to 100) and a live auth-activity chart on the admin dashboard.

### 12 score factors

| Factor | Points | What it checks |
|---|---:|---|
| Coverage | 30 | % of users enrolled in 2FA |
| Admin coverage | 20 | All admins specifically have 2FA on |
| Enforcement | 15 | `RequireForAll` is on |
| Audit chain | 10 | Hash chain is intact (no breakage) |
| IP ban | 8 | Brute-force banning enabled with sane threshold |
| Impossible travel | 7 | Functional — requires `GeoIpCityDbPath` set to a valid MaxMind file |
| HIBP | 5 | Have-I-Been-Pwned password check enabled |
| Clean 7-day audit | 5 | No failed admin sign-ins in the last 7 days |
| Require-to-disable | 8 | `RequireTwoFactorToDisable` is on |
| Step-up | 7 | `StepUpLevel` is `Destructive` or stronger |
| Webhook | 5 | Push notifications (ntfy / Gotify / webhook) configured |
| Recovery codes | 5 | At least one user has generated recovery codes |

### Auth-activity overview

Admin dashboard → **Overview** tab shows a stacked-area chart of successful / failed / blocked sign-ins.

- **Range selector**: 1 week / 1 month / 1 year. Buckets are server-side: per-hour for 1w, per-day for 1m, per-month for 1y.
- **Sparse-range backfill**: empty buckets are filled with zero on the server so a 1-year chart still spans 12 bars even if only one month has data — no collapsed-bar UX.
- **Hover tooltips** show exact counts and the bucket date.
- **Dashed gridlines at 25 / 50 / 75 %** and **first / middle / last x-axis date markers** so values are readable without hovering.

---

## 🌍 Internationalization (v2.5)

Every user-visible string in the setup, login, challenge, and admin pages is translatable. Ships with 8 first-class languages at full key parity (664 keys each).

| Language | Locale | Display name in picker |
|---|---|---|
| English | en | English |
| Deutsch | de | Deutsch |
| Español | es | Español |
| Français | fr | Français |
| Italiano | it | Italiano |
| 日本語 | ja | 日本語 |
| Português | pt | Português |
| 中文 | zh | 中文 |

**How the active language is chosen** (first match wins):
1. URL `?lang=de` override (useful for support / screenshots).
2. Per-user preference saved from the language picker (`PUT /TwoFactorAuth/Users/{id}/preferences`).
3. `localStorage` (so the picker remembers across sessions).
4. Server-wide `DefaultLanguage` setting (admin sets in **Settings → Hardening**).
5. Fallback to English.

**Native-name picker** — the picker shows each language in its own script ("Deutsch", "日本語", "中文") rather than locale codes, so a user who only reads Japanese can find their language without reading English.

**Implementation notes** (for translators / contributors):
- Translation bundles live in `src/Jellyfin.Plugin.TwoFactorAuth/Pages/translations/<lang>.json` and are served via `/TwoFactorAuth/translations/{lang}` with strong caching.
- The shared `tfa-i18n.js` helper exposes `window.tfaI18n.tr(key, fallback)`, `loadTranslations(lang)`, `applyTranslations(root)`, `renderLanguagePicker(container)`, `getEffectiveLanguage()`, and a `ready` promise so dynamic JS-rendered content doesn't render in English before the bundle loads.
- `/TwoFactorAuth/public-config` exposes the server-wide default language to anonymous pages (login / challenge) without leaking other config.

**Want to add a language?** Copy `translations/en.json` → translate → drop in `translations/<your-locale>.json`. The picker auto-discovers new files. Pull requests welcome.

---

## 🕰️ Indefinite device trust (v2.5)

Lets a user mark a specific trusted browser or paired device as "trusted forever" instead of "trusted for 30 days." Useful for a personal phone or home TV where the user would rather have one less prompt and accept the residual risk if the device is lost.

**Admin gate (default off)**: Jellyfin Security → **Settings → Hardening → AllowIndefiniteTrust**. When off, the user-side opt-in toggle is hidden entirely — no way to enable per-device. When on, users see an **Indefinite trust** toggle on each of their trusted browsers / paired devices.

**User opt-in** (per device):
1. Setup page → **Trusted Devices** or **Paired Devices** card.
2. Click the **Indefinite trust** toggle on the device you want to never expire.
3. Confirm. The trust cookie's expiry is set to 100 years and the middleware skips the normal expiry check for this device.

**Revoke / undo**: same toggle off. Or revoke the device entirely from Setup → Trusted Devices.

⚠ **Tradeoff** — an indefinite-trust device is your weakest link. If someone steals the laptop, that browser is signed in until *you* revoke it. Don't enable on shared / borrowed machines, and revoke immediately on device loss. The admin gate exists so org admins can keep this off entirely if their threat model doesn't tolerate the tradeoff.

---

## 🔐 Hardened self-service factor changes (v2.5.6)

Closes the stolen-session takeover path. Before v2.5.6, an attacker who hijacked an authenticated browser cookie could silently enroll their own authenticator (add a passkey, generate a new TOTP secret, regenerate recovery codes) without ever proving they were the legitimate user — the original 2FA only gated *login*, not *factor changes*. v2.5.6 closes that.

**Setting**: Jellyfin Security → **Settings → Hardening → Hardened security for users (factor changes)**. Tri-state:

- **Off** — users can change 2FA factors without a current code (legacy behaviour, ≤ v2.5.5).
- **User choice** — exposes a per-user toggle on the Setup page; each user opts in individually.
- **Forced** (default) — every user must submit a current factor before adding/replacing any 2FA factor.

**Covered mutations** — adding/replacing TOTP, regenerating recovery codes, creating an app password, adding/removing a passkey, enabling/disabling email OTP. All gated.

**Proof of factor** — the step-up prompt accepts any of:
- A current TOTP code from the user's authenticator app
- An unused recovery code
- A passkey assertion (when the user has at least one passkey enrolled)
- An emailed 8-digit step-up code (when the user has a configured email + SMTP is set up)
- An OIDC re-auth via a linked IdP (v2.5.7 — see below)

Step-up tokens are single-use, 60-second TTL, and bound to the requesting user — they can't be replayed or reused for a second mutation.

---

## 🔑 OIDC step-up factor for users (v2.5.7)

Lets a user satisfy the hardened self-service step-up by re-authenticating to a linked OIDC provider, instead of needing a TOTP / passkey / recovery code. Useful for users whose only configured factor is OIDC (common in OIDC-only deployments — see "Hide built-in login buttons" below).

**How it works**:
1. Step-up modal renders a "🌐 Verify with *ProviderName*" button per IdP the user has linked (data from `GET /TwoFactorAuth/Oidc/MyLinks`).
2. Click opens the IdP in a popup window (520×720) with `prompt=login` so the IdP must actually re-authenticate the user — silent SSO confirmation is rejected.
3. The IdP redirects to the standard `/TwoFactorAuth/Oidc/Callback/{providerId}` endpoint. The state token marks this as a step-up flow.
4. Callback validates: the state token is bound to the current user; the IdP-returned `sub` matches the user's stored `SsoLink` for that provider. Both must match. Signing into a *different* IdP account doesn't grant step-up.
5. On match, the server mints a step-up token, returns an HTML page that `postMessage`s it back to the opener (same-origin only), and closes the popup.
6. The modal stores the token and proceeds with the factor mutation.

**Security guards**:
- `prompt=login` defeats a hijacked-session attacker who clicks "Sign in with X" hoping for a silent confirmation.
- Subject-match against `SsoLink` defeats a hijacked-session attacker who happens to have their own account at the same IdP.
- State token is single-use, 10-minute TTL, bound to the requesting user id and provider id.
- Popup `postMessage` target is restricted to `window.location.origin`, never `'*'`.

The "Verify with X" buttons only appear in the step-up modal when the user has at least one OIDC link; they don't add UI for users who don't use OIDC.

---

## 🙈 Hide built-in 2FA / Passkey login buttons (v2.5.7)

For OIDC-only deployments where every user signs in through your IdP and the plugin's injected sign-in shortcuts add noise. Two independent admin toggles in **Settings → Hardening**:

- **Hide the "Sign in with Two-Factor Authentication" button** — removes the 2FA shortcut `inject.js` adds to Jellyfin's main login page.
- **Hide the "Sign in with passkey" button** — removes the passkey shortcut.

Each is independent — pick any combination. Configured OIDC provider buttons stay visible regardless of these flags.

⚠ **The `/TwoFactorAuth/Login` page still works directly** even when both toggles are on. Admins/fallback users can always reach it by URL, so you don't lock yourself out of the plugin's login flow if your IdP becomes unreachable.

---

## 🌐 OIDC private / VPN / LAN endpoints (v2.5.7)

Lets you point the plugin at an IdP that lives on a private network (Tailscale, Wireguard, LAN-only Authentik / Authelia / Pocket ID, etc.). Without this toggle, v2.5.5's SSRF guard rejects any OIDC discovery URL that resolves to an RFC1918 / loopback / link-local address, or that uses plain `http`.

**Setting**: per-provider, in the OIDC provider edit form → **Allow private / VPN / LAN endpoints** (marked **Advanced**, default off).

**Granularity**: per-provider. A public Google + a private Authentik can coexist — Google keeps the strict SSRF guard, Authentik gets the bypass. The toggle scopes to ONE provider's discovery / token / userinfo / jwks fetches; other providers are unaffected.

⚠ **Trade-off** — enabling this for a provider whose discovery URL gets tampered with would let an attacker pivot the plugin into your internal services (e.g. AWS IMDS at 169.254.169.254, internal admin APIs, the Docker daemon socket via host networking). Only enable for IdPs you intentionally host on private networks where the network boundary IS the security boundary.

The OIDC spec doesn't let admins mix-and-match per-endpoint — the IdP's discovery document dictates which token / userinfo / jwks URLs the plugin fetches, and they all live in the same network as discovery. So per-provider is the natural granularity.

---

## 💾 Verified-token persistence (v2.5.7)

Closes the "session permanently 403'd after restart" issue (#52). Before v2.5.7, the plugin tracked which access tokens had completed 2FA in an in-memory dictionary. After a `docker compose down/up` (or any process restart), that dictionary was empty — but the user's Jellyfin auth token was still valid in Jellyfin's DB. The failsafe `BlockToken` then triggered on every `SessionStarted` reconnect, and `RequestBlockerMiddleware` 403'd every API call. The user couldn't even reach `/Users/Me/Logout` — they had to wipe local storage.

**Fix**: SHA-256 hashes of verified tokens persist to `{plugin-data}/verified_tokens.json`. On every restart, the hashes are loaded back into the in-memory set, so already-verified sessions stay verified.

**What's stored**:
- 64-char hex SHA-256 hash of each verified token (one-way, leak-resistant — a stolen sidecar yields no usable tokens).
- ISO-8601 UTC expiry timestamp (30-day TTL per entry).
- Cap at 5000 most-recent entries to bound disk usage.

**What's NOT stored** — never the plaintext token, never user ids, never device ids. Just hash + expiry.

**Operational signal** — after the first restart following a successful login, the log emits `[2FA] Loaded N verified-token hashes from /config/plugins/configurations/TwoFactorAuth/verified_tokens.json`. That confirms persistence is active.

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

---

## 🛠️ Troubleshooting

### Plugin breaking your server
Disable the plugin without uninstalling:

```bash
# Edit
/config/plugins/configurations/Jellyfin.Plugin.TwoFactorAuth.xml

# Set
<Enabled>false</Enabled>
```

Restart Jellyfin. All 2FA enforcement turns off; users can log in normally.

### Behind SWAG / fail2ban: other services on the same proxy go offline after a 2FA login

If you run Jellyfin behind [SWAG](https://github.com/linuxserver/docker-swag) (linuxserver.io's all-in-one nginx + fail2ban + Let's Encrypt container) or any other stack with a fail2ban jail watching for HTTP 401s, you may see this symptom:

- Jellyfin works fine on the LAN
- External access via the reverse proxy fails with `ERR_CONNECTION_REFUSED`
- **Other applications behind the same proxy also become unreachable**
- Brief recovery every ~10–15 minutes, then it fails again

**Why this happens.** When 2FA enforcement is on and a user logs in, the plugin's `RequestBlockerMiddleware` 401s every post-login API call from the browser (`/Sessions/Capabilities/Full`, `/DisplayPreferences/usersettings`, `/socket`, `/System/Endpoint`, etc.) until the user completes 2FA — that's roughly **15 401s in a few seconds** per legitimate login.

SWAG's default `nginx-unauthorized` fail2ban jail watches the nginx access log for any 401 response code (regardless of which backend produced it) and bans the source IP after 5 in 10 minutes. A single 2FA login trips it. The ~15-minute recovery cycle matches the jail's default `bantime = 600`.

The "everything else breaks" symptom depends on what IP fail2ban actually bans:

- If SWAG sees Cloudflare's edge IP (you're behind Cloudflare) → it bans Cloudflare → all external traffic to all services fails
- If SWAG sees the Docker bridge gateway IP (misconfigured forwarded headers) → inter-container traffic dies → SWAG can't reach any backend
- If SWAG sees the user's real client IP → only they get locked out

**Fix.** Drop this into `/config/fail2ban/jail.d/jellyfin.local`:

```ini
[nginx-unauthorized]
maxretry = 30
findtime = 600
```

That changes "ban after 5 401s in 10 min" → "ban after 30 401s in 10 min." A normal 2FA login generates ~15 401s, so 30 gives ~2× headroom while still catching real brute-force (hundreds of 401s per minute).

**Scale by user count** — fail2ban counts per source IP, and if you're behind Cloudflare or a similar CDN, ALL your users share the same source IP from fail2ban's view. Simultaneous logins compound:

| Users on the server | Recommended `maxretry` |
|---|---|
| 1 (solo) | `30` |
| 2–3 (small household) | `50` |
| 4–6 (family) | `100` |
| 10+ (community / extended) | `150` or `enabled = false` |

Restart SWAG (`docker restart swag` or your equivalent) after the change.

**Alternative — disable the jail entirely.** If you'd rather not patch fail2ban:

```ini
[nginx-unauthorized]
enabled = false
```

You lose protection against generic 401-burst attacks on **all** apps behind SWAG (not just Jellyfin), but the other default SWAG jails (`nginx-http-auth`, `nginx-badbots`, `nginx-botsearch`, `nginx-deny`) still cover the common brute-force vectors.

**Why this isn't strictly a plugin bug.** The plugin behaves correctly per HTTP/OAuth (401 on unverified tokens). SWAG's fail2ban behaves correctly per brute-force-protection norms. The collision sits in the gap between the two — fail2ban can't tell a legitimate 2FA enforcement burst from an attack just by reading status codes in the access log. A future plugin release may reduce the 401 burst size at the source ([tracking issue #36](https://github.com/ZL154/JellyfinSecurity/issues/36)) but the jail-threshold fix above resolves it today.

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

### 2.5.0 — Hardening, observability, i18n, and indefinite trust

**Hardening**
- **Step-up authentication** — configurable level (`Off` / `Destructive` / `AllConfigChanges` / `Everything`) re-prompts the admin for 2FA before sensitive operations. Step-up tokens are single-use.
- **Encrypted configuration exports** — passphrase-protected backup/migration. AES-256-GCM with PBKDF2-SHA256 (600 000 iterations) key derivation, versioned envelope so future schema changes don't break old exports.
- **Audit-chain rebuild** — admin action (step-up gated) to repair audit-log hash continuity after disk corruption or manual edits.
- **`RequireTwoFactorToDisable` flag** — re-prompts for 2FA before a user can disable their own 2FA.

**Observability**
- **12-factor security score** (was 5). New factors: clean-7d audit, require-to-disable, step-up coverage, webhook configured, recovery codes generated, impossible-travel as a functional check. Raw 130 pts normalized to a 100 ceiling. Translatable factor labels with interpolation data.
- **Admin Dashboard Overview** — auth-activity stacked-area chart with 1w / 1m / 1y range selector, hover tooltips, dashed gridlines at 25/50/75 %, x-axis date markers. Server-side bucket backfill so sparse 1-year data still spans the full range.
- **`/Dashboard/Overview` endpoint** — accepts `?range=1w|1m|1y`. Backs the chart and the score breakdown.

**Internationalization**
- **8 languages** (en / de / es / fr / it / ja / pt / zh) at full key parity — 664 keys each.
- **`tfa-i18n.js` shared helper** — `tr() / loadTranslations() / applyTranslations() / renderLanguagePicker() / getEffectiveLanguage()` + a `ready` promise so dynamic JS-rendered content waits for the bundle.
- **Native-name picker** — shows each language in its own script ("Deutsch", "日本語", "中文") instead of locale codes.
- **Resolution order**: URL `?lang=` → per-user pref → `localStorage` → server `DefaultLanguage` → English.
- **Admin Settings → Default Language** — server-wide picker; users can still override per-user.
- **`/TwoFactorAuth/public-config`** — exposes default language to anonymous pages.
- **`/TwoFactorAuth/translations/{lang}`** — embedded-resource endpoint with strong caching.

**Indefinite device trust (opt-in)**
- Admin-gated `AllowIndefiniteTrust` config flag — default off. When off the user-side toggle is hidden entirely.
- Per-device opt-in for trusted browsers and paired devices. Trust cookie expiry = 100 years; middleware skips expiry check for records flagged `IndefiniteTrust=true`.
- Revoke instantly from the same Setup-page card.

**Other fixes**
- `admin-script.js` externalized from `admin.html` so Jellyfin's SPA `loadView` template-literal stripping no longer breaks the dashboard with a `SyntaxError: Unexpected token 'class'`.
- `/Dashboard/Overview` DTOs flattened to force camelCase JSON serialization.
- Setup page stashes `/Users/Me` Id into a module-scope `_myUserId` so the indefinite-trust toggle works without `window.ApiClient` (which isn't loaded on the Setup page).
- Admin enumeration uses `_userManager.Users.HasPermission(PermissionKind.IsAdministrator)` directly (typed extension method) — fixes the 0/0 admin count regression.
- All dynamic JS-rendered content deferred behind `window.tfaI18n.ready` so it doesn't render in English before the translation bundle loads.

**Tests**: 254/254 pass. Clean build with `TreatWarningsAsErrors=true`.

**Upgrade**: in-place — existing TOTP enrollments, passkeys, OIDC links, trusted browsers, paired devices, and audit history all carry over.

### 2.3.0 — Security maintenance and forced enrollment

**Security**
- Fixed some security issues and tightened the sign-in flow. Details are intentionally kept high-level in public release notes.
- Strengthened passkey verification requirements and OIDC sign-in handling.

**Fixes**
- `Require 2FA for all users` now has a proper forced-enrollment flow for users who do not have 2FA set up yet.
- Standard Jellyfin login, plugin login, passkey verification, and Google/OIDC sign-in were tested together so each path keeps the intended 2FA behavior.
- Fixed a Settings-page layout overlap in the NAT hairpin warning row.

### 2.2.3 — PDF font fix

**Fixes**
- Recovery-code PDF now actually renders the text. v2.2.2 swapped the font from `Fonts.SegoeUI` to `"Lato"` thinking QuestPDF auto-loaded Lato — it doesn't, the constant is just a name. Skia's fallback found nothing usable inside the Jellyfin Docker container (no system fonts) and rendered every glyph as an empty box.
- Lato-Regular and Lato-Bold are now **embedded as resources** in the plugin DLL and registered with QuestPDF's `FontManager` in the `RecoveryCodePdfService` static constructor. Works on any container regardless of installed system fonts.

### 2.2.2 — UX polish

**Fixes**
- Recovery-code PDF now renders correctly inside Linux containers — the previous build used `Fonts.SegoeUI` / `Fonts.Consolas` (Windows-only fonts), which produced a PDF full of empty glyph boxes when generated on a Linux host. Switched to the cross-platform `Lato` font that QuestPDF bundles by default.
- 2FA challenge page now exposes a **Recovery code** tab alongside Authenticator and Email, so a user who lost their authenticator can sign in directly from the challenge screen instead of having to reach the standalone Login page.

**UI**
- All Setup-page confirmation prompts (regenerate recovery codes, revoke device / app password / trusted browser, disable 2FA, emergency lockout, etc.) now use a dark-themed in-page modal instead of the browser's native `confirm()` popup. Esc cancels, Enter confirms, click outside cancels.

### 2.2.1 — Multi-architecture support

**New**
- Recovery-code PDF generation (QuestPDF) now works on **linux-x64**, **linux-arm64**, and **linux-musl-x64** containers. Previously only `linux-x64` shipped working native libs, so Pi / Apple-Silicon-Linux / Alpine deployments couldn't generate the recovery PDF.
- Runtime architecture + libc detection (`Architecture.X64` / `Arm64` + `/lib/ld-musl-*` sniff) in `RecoveryCodePdfService` picks the right RID's natives at startup, copies them next to the plugin DLL where QuestPDF probes, and `NativeLibrary.Load`s them in dependency order before the first render.
- PDF init now wraps in try/catch — if native deps fail to load on an unsupported runtime, the rest of the plugin keeps working and PDF render throws a clear `InvalidOperationException` instead of taking the whole plugin down.

**Build**
- `build.sh` rewritten as a fat-package builder: managed assemblies published once without RID, then per-RID native libs (`linux-x64`, `linux-arm64`, `linux-musl-x64`) bundled into `runtimes/<rid>/native/` with a copy at the plugin root.
- New `.github/workflows/build-multiarch.yml` runs the fat build inside a `mcr.microsoft.com/dotnet/sdk:9.0` Docker container and publishes the zip + MD5 + SHA256 to a GitHub Release.

**Credit**
- Multi-arch QuestPDF runtime fix and fat-package build flow contributed by [@glauciocampos](https://github.com/glauciocampos) (originally cut as `v2.1.0.1` in [their fork](https://github.com/glauciocampos/JellyfinSecurity)). Thanks Glaucio.

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

## 🙏 Credits

Contributors who have shipped substantive changes to this plugin:

- **[@glauciocampos](https://github.com/glauciocampos)** — multi-architecture QuestPDF runtime fix and fat-package build flow ([v2.2.1](#221--multi-architecture-support)). Originally cut as `v2.1.0.1` in [their fork](https://github.com/glauciocampos/JellyfinSecurity). Pi / Apple-Silicon-Linux / Alpine deployments work because of this.

Maintained by **[@ZL154](https://github.com/ZL154)**. PRs and issue reports welcome.

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

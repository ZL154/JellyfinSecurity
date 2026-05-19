# Security Policy

Thanks for taking the time to report security issues responsibly.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for security bugs.** A public report
gives attackers a head start before users can upgrade.

Use one of the following private channels:

1. **GitHub Private Vulnerability Reporting** (preferred) — open
   <https://github.com/ZL154/JellyfinSecurity/security/advisories/new>
   and submit the advisory. Only repository maintainers can see it.
2. **Discord** — DM **`@zack154`** on Discord with a description of the issue.

### What to include

- Affected plugin version(s) (e.g. `2.3.0`)
- Affected Jellyfin server version(s) (e.g. `10.11.8`)
- Steps to reproduce (PoC welcome)
- Impact assessment (auth bypass, RCE, info disclosure, DoS, etc.)
- Suggested fix or mitigation if you have one

### What to expect

- Initial acknowledgement within **72 hours**
- Confirmation or "not a vuln" verdict within **7 days**
- Coordinated disclosure window: typically **30 days** between fix and
  public disclosure, longer for severe issues if a coordinated patch
  cycle is required
- CVE assignment for confirmed vulnerabilities (via GitHub Security
  Advisories)
- Credit in the release notes and advisory unless you ask to remain
  anonymous

### Out of scope

The following are generally **not** treated as vulnerabilities in this
plugin:

- Issues that require an attacker to already be a Jellyfin administrator
- Issues caused by misconfigured deployments (e.g. running Jellyfin
  without HTTPS in front of it, missing `TrustForwardedFor` +
  `TrustedProxyCidrs` behind a reverse proxy)
- Self-XSS or theoretical timing attacks against TOTP without a working
  PoC
- Reports against unsupported plugin versions (see table below)
- Findings from automated scanners with no exploitable PoC

## Supported versions

Only the latest minor release receives security updates. Older releases
may receive a backport on a case-by-case basis if the severity warrants
it.

| Version  | Status                          |
| -------- | ------------------------------- |
| 2.3.x    | :white_check_mark: Supported    |
| 2.2.x    | :warning: Security fixes only   |
| 2.1.x    | :x: Unsupported — please upgrade |
| 2.0.x    | :x: Unsupported — please upgrade |
| < 2.0    | :x: Unsupported — please upgrade |

## Threat model — what this plugin defends against

In scope:

- Password compromise — blocked by 2FA / passkey / OIDC requirement
- Brute-force login — blocked by per-IP rate limit + IP ban
- Stolen session cookie replay — bound to device, revocable
- Trusted-browser cookie forgery — HMAC-SHA256 signed, length-checked
- Replay of recovery codes — single-use, marked used on validation
- TOTP code replay across restarts — persisted last-used time-step floor
- TOTP secret swap between users on disk — AES-GCM with userId as AAD
- OIDC token forgery — signature + issuer + audience + nonce validated
- Stolen X-Forwarded-For header — only honoured when peer is a trusted
  proxy CIDR; real client picked right-to-left
- Impossible travel — notification when consecutive sign-ins exceed
  cruise-jet speed
- IP allowlist bypass — high-value accounts can be pinned to CIDRs

Out of scope (intentional limitations):

- Endpoint compromise (keylogger reads the user's TOTP code before they
  type it)
- Server compromise (root on the Jellyfin host)
- Browser-extension compromise stealing the trust cookie
- Side-channel attacks on the underlying OS / crypto primitives
- Native client compromise (a malicious Swiftfin fork that exfiltrates
  app passwords)

## Notes on cryptography

- TOTP secret encryption: AES-GCM with a persistent 32-byte key,
  userId as AAD (v2 format)
- Trust cookie signing: HMAC-SHA256 with persistent key, length-checked
  before `CryptographicOperations.FixedTimeEquals`
- Recovery code hashing: PBKDF2-SHA256, 100k iterations, per-code salt
- App password hashing: PBKDF2-SHA256
- API key hashing: SHA-256 (raw key is 256 bits of entropy, no PBKDF2
  needed)
- Audit log integrity: per-entry hash chain (`prev_hash || entry`)
- Constant-time comparison for every secret-bearing path

If you find a deviation from any of the above, that itself is in scope.

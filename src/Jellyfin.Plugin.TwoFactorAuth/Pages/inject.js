(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js v1.4.0 loaded');

    // Build server URLs without assuming Jellyfin is mounted at the origin
    // root. ApiClient.getUrl is canonical once jellyfin-web has initialised;
    // the pathname fallback also works during this script's early <head>
    // execution and in native-app WebViews.
    function jellyfinBasePath() {
        try {
            var path = window.location.pathname || '';
            var lower = path.toLowerCase();
            var markers = ['/web', '/twofactorauth'];
            var cut = -1;
            for (var i = 0; i < markers.length; i++) {
                var at = lower.indexOf(markers[i]);
                if (at >= 0 && (cut < 0 || at < cut)) cut = at;
            }
            return cut >= 0 ? path.substring(0, cut).replace(/\/+$/, '') : '';
        } catch (e) { return ''; }
    }
    function serverUrl(path) {
        var clean = String(path || '').replace(/^\/+/, '');
        try {
            if (window.ApiClient && typeof window.ApiClient.getUrl === 'function') {
                return window.ApiClient.getUrl(clean);
            }
        } catch (e) { /* use the early-load fallback */ }
        return jellyfinBasePath() + '/' + clean;
    }
    function stripJellyfinBasePath(path) {
        var base = jellyfinBasePath();
        if (base && String(path).toLowerCase().indexOf(base.toLowerCase()) === 0) {
            return String(path).substring(base.length) || '/';
        }
        return String(path);
    }

    // [v2.5.11] (ZEROX7) Capture an OIDC sign-in error from the redirect hash
    // IMMEDIATELY at script load — BEFORE Jellyfin's SPA router can bounce to
    // the user-select screen and strip the query string. A failed SSO sign-in
    // (no matching account, ambiguous email, not-in-group, MFA required, …)
    // used to vanish silently. handleOidcCallback() surfaces this as a toast
    // on whatever screen the SPA settles on.
    var _tfaOidcError = (function () {
        try {
            var h = window.location.hash || '';
            var q = h.indexOf('?');
            if (q < 0) return null;
            var pairs = h.substring(q + 1).split('&');
            for (var i = 0; i < pairs.length; i++) {
                var kv = pairs[i].split('=');
                if (decodeURIComponent(kv[0]) === 'oidcError') {
                    return decodeURIComponent((kv[1] || '').replace(/\+/g, ' '));
                }
            }
        } catch (e) {}
        return null;
    })();
    var _tfaOidcErrorShown = false;

    // ============================================================
    // [v2.5.12] (#79, ZEROX7) i18n for the login page.
    //   The injected login UI (SSO buttons, 2FA/passkey buttons, the
    //   forgot-password panel, the OIDC modal) was hardcoded English. The rest
    //   of the plugin already localizes via the shared tfa-i18n.js helper, which
    //   now follows Jellyfin's own UI language pre-auth. Load that helper here
    //   and translate the injected strings through it.
    //
    //   T(key, fallback) returns the localized string, falling back to the
    //   English literal until the bundle has loaded (tfa-i18n is async). Static
    //   injected elements also carry data-i18n-key so the 'tfa-i18n-ready' hook
    //   can re-translate them once the bundle arrives.
    function ensureI18n() {
        try {
            if (window.tfaI18n) return;
            if (document.getElementById('__tfa_i18n_js')) return;
            var s = document.createElement('script');
            s.id = '__tfa_i18n_js';
            s.src = serverUrl('TwoFactorAuth/tfa-i18n');
            s.async = true;
            (document.head || document.documentElement).appendChild(s);
        } catch (e) { /* ignore — strings fall back to English */ }
    }
    function T(key, fallback) {
        try {
            if (window.tfaI18n && typeof window.tfaI18n.tr === 'function') {
                return window.tfaI18n.tr(key, fallback);
            }
        } catch (e) { /* ignore */ }
        return fallback;
    }
    // Interpolate "{name}"-style placeholders into a translated template.
    function Tf(key, fallback, vars) {
        var s = T(key, fallback);
        if (vars) {
            for (var k in vars) {
                if (Object.prototype.hasOwnProperty.call(vars, k)) {
                    s = s.split('{' + k + '}').join(String(vars[k]));
                }
            }
        }
        return s;
    }
    // Re-translate the [data-i18n-key] nodes we injected, once the bundle loads.
    document.addEventListener('tfa-i18n-ready', function () {
        try { if (window.tfaI18n) window.tfaI18n.applyTranslations(document); } catch (e) { /* ignore */ }
    });

    // [v2.5.12] (#79) Carry Jellyfin's UI language to our STANDALONE pages.
    //   jellyfin-web sets <html lang> to the active UI culture on its OWN pages
    //   (where inject.js runs) but does NOT persist it to a localStorage key we
    //   can read, and our standalone pages (Setup/Login/Challenge) aren't
    //   rendered by jellyfin-web so they never see that <html lang>. So read the
    //   culture HERE and pass it through as ?lang=, which tfa-i18n honours first.
    function jfUiLang() {
        try { var h = (document.documentElement.getAttribute('lang') || '').split('-')[0].toLowerCase(); if (h) return h; } catch (e) {}
        try { return (navigator.language || '').split('-')[0].toLowerCase(); } catch (e) {}
        return '';
    }
    function withLang(url) {
        var l = jfUiLang();
        if (!l) return url;
        return url + (url.indexOf('?') >= 0 ? '&' : '?') + 'lang=' + encodeURIComponent(l);
    }

    // ============================================================
    // 1a. v2.4.12 — TFA-pending sessionStorage flag + client-side
    //     short-circuit. Issue #36 (Wibbles42 / SWAG fail2ban):
    //     once the server has signalled "two-factor authentication
    //     required" for this tab, suppress subsequent non-allowlisted
    //     API calls so the browser stops hammering the server with
    //     blocked-token requests while the user completes the
    //     challenge. Without this, Jellyfin Web fires ~15 parallel
    //     API calls post-login (Sessions/Capabilities/Full,
    //     DisplayPreferences, socket, System/Endpoint, …) and each
    //     trips fail2ban's nginx-unauthorized jail. The server-side
    //     401->403 change (RequestBlockerMiddleware) covers the few
    //     calls that race ahead of this short-circuit so fail2ban's
    //     status-401-only failregex never matches.
    // ============================================================
    var TFA_PENDING_KEY = '__tfa_pending';
    var TFA_PENDING_TTL_MS = 5 * 60 * 1000;
    // Mirror RequestBlockerMiddleware.AlwaysAllowedPaths[] verbatim —
    // any divergence soft-locks users mid-2FA. Lowercase + trailing-
    // slash-normalised match.
    var TFA_ALWAYS_ALLOWED = [
        '/twofactorauth/login',
        '/twofactorauth/setup',
        '/twofactorauth/authenticate',
        '/twofactorauth/verify',
        '/twofactorauth/email/send',
        '/twofactorauth/challenge',
        '/twofactorauth/inject.js',
        '/twofactorauth/pairconfirm'
    ];
    function isExplicitLoginRoute() {
        try {
            return (window.location.hash || '').toLowerCase().indexOf('login') >= 0;
        } catch (e) { return false; }
    }
    function isTfaPending() {
        try {
            // The stock #/login route is the user's escape hatch to choose a
            // different account. An interrupted mobile challenge can leave
            // this session flag behind; treating the user picker as a blocked
            // authenticated page redirects straight back to the 2FA portal
            // before Jellyfin can render its users.
            if (isExplicitLoginRoute()) {
                sessionStorage.removeItem(TFA_PENDING_KEY);
                return false;
            }
            var v = sessionStorage.getItem(TFA_PENDING_KEY);
            if (!v) return false;
            var ts = parseInt(v, 10);
            if (!ts || isNaN(ts)) return false;
            if (Date.now() - ts > TFA_PENDING_TTL_MS) {
                sessionStorage.removeItem(TFA_PENDING_KEY);
                return false;
            }
            return true;
        } catch (e) { return false; }
    }
    function setTfaPending() {
        try { sessionStorage.setItem(TFA_PENDING_KEY, String(Date.now())); } catch (e) {}
    }
    function clearTfaPending() {
        try { sessionStorage.removeItem(TFA_PENDING_KEY); } catch (e) {}
    }
    // [v2.5.14] (#99/#98) Escape hatch for the soft-lock. When the pending flag
    // is armed, every non-auth fetch/XHR is short-circuited with a synthetic 403.
    // If the user is NOT actively on a 2FA page completing the challenge, that
    // means the whole app's bootstrap API calls fail and Jellyfin Web reports
    // "server cannot be reached" (issue #99) — a dead-end the user could only
    // escape by restarting the server (which cleared the in-memory blocked token)
    // or waiting out the 5-min TTL. Instead, navigate ONCE to the 2FA portal so
    // there is always a forward path to complete (or recover from) 2FA. One-shot
    // + skip when already on a /TwoFactorAuth/* page so it can never loop, and
    // inject.js is not loaded on those pages so no further interception fires.
    var __tfaRedirecting = false;
    function redirectToTfaPortal() {
        if (__tfaRedirecting) return;
        try {
            var p = (window.location.pathname || '').toLowerCase();
            if (stripJellyfinBasePath(p).indexOf('/twofactorauth/') === 0) return;
        } catch (e) { return; }
        __tfaRedirecting = true;
        try {
            // A native Jellyfin client can reopen with a stored user/token and
            // trigger SessionStarted before the stock user picker is shown.
            // Sending that client to the standalone portal pins it to the
            // stored account. Use Jellyfin's own credential owner to sign out
            // locally, retain the saved server, and return to account choice.
            // Selecting a protected user still follows the normal auth-path
            // response into TwoFactorAuth/Challenge.
            if (inEmbeddedWebView()
                && window.ApiClient
                && typeof window.ApiClient.logout === 'function') {
                clearTfaPending();
                var openUserPicker = function () {
                    window.location.href = serverUrl('web/index.html#/login');
                };
                Promise.resolve(window.ApiClient.logout()).then(openUserPicker, openUserPicker);
                return;
            }
        } catch (e) { /* fall back to the standalone portal */ }
        try { window.location.href = serverUrl('TwoFactorAuth/Login'); } catch (e) {}
    }
    // [v2.5.16] (#100, Re4mstr) Enforce the OIDC force-password-onboarding step so
    // a flagged user can't escape it by pressing Back. The OIDC bridge sets
    // localStorage['__tfa_set_pw_required'] before landing a flagged user on
    // /TwoFactorAuth/SetPassword; if they instead reach /web (Back button, typed
    // URL, an existing session), bounce them straight back to the set-password
    // page. One-shot + skipped on /TwoFactorAuth/* so it can't loop, and the
    // set-password page clears the flag on a successful set (or if the server says
    // no setup is pending), so a stale flag self-heals.
    function enforceForcedPasswordSetup() {
        if (__tfaRedirecting) return;
        try {
            if (stripJellyfinBasePath((window.location.pathname || '').toLowerCase()).indexOf('/twofactorauth/') === 0) return;
            if (localStorage.getItem('__tfa_set_pw_required') !== '1') return;
        } catch (e) { return; }
        __tfaRedirecting = true;
        try { window.location.href = serverUrl('TwoFactorAuth/SetPassword'); } catch (e) {}
    }
    function isAlwaysAllowedPath(url) {
        if (!url) return true;
        try {
            var pathname = stripJellyfinBasePath(
                new URL(String(url), window.location.origin).pathname.toLowerCase());
            if (pathname.length > 1 && pathname.charAt(pathname.length - 1) === '/') {
                pathname = pathname.substring(0, pathname.length - 1);
            }
            for (var i = 0; i < TFA_ALWAYS_ALLOWED.length; i++) {
                if (pathname === TFA_ALWAYS_ALLOWED[i]) return true;
            }
            return false;
        } catch (e) { return false; }
    }
    // Build a Response that mirrors what RequestBlockerMiddleware would
    // have returned — same status (403), same body shape, plus a
    // _tfaShortCircuit:true marker for devtools visibility. Calling
    // code that inspects body.twoFactorRequired sees the same value.
    function syntheticTfaBlockedResponse() {
        var body = '{"message":"Two-factor authentication required. Visit /TwoFactorAuth/Login to complete sign in.","twoFactorRequired":true,"_tfaShortCircuit":true}';
        return new Response(body, {
            status: 403,
            statusText: 'Forbidden',
            headers: { 'Content-Type': 'application/json' }
        });
    }
    function isTfaCompletionPath(url) {
        if (!url) return false;
        var u = String(url).toLowerCase();
        return u.indexOf('/twofactorauth/verify') >= 0
            || u.indexOf('/twofactorauth/authenticate') >= 0;
    }

    var BUTTON_ID = '__twofactor_login_btn';
    var STYLE_ID = '__twofactor_styles';
    var SIDEBAR_ID = '__twofactor_sidebar';
    var SETTINGS_TILE_ID = '__twofactor_settings_tile';

    // ============================================================
    // 1. Intercept fetch + XHR. If Jellyfin's auth endpoint returns
    //    401 with twoFactorRequired:true, redirect to the challenge
    //    page. Catches all login paths (manual, avatar quick-login,
    //    Quick Connect).
    // ============================================================

    function isAuthPath(url) {
        if (!url) return false;
        // Issue #49: also accept URLs without a leading slash. Jellyfin's
        // ApiClient sometimes constructs auth calls as relative paths
        // ("Users/AuthenticateByName") rather than absolute ("/Users/...").
        // The prior strict leading-slash substring check missed the relative
        // form, the response slipped through unhandled, and Jellyfin Web
        // showed the generic "incorrect username or password" error instead
        // of redirecting to the challenge page.
        var u = String(url).toLowerCase();
        return /(?:^|\/)users\/authenticatebyname(?:\?|\/|$)/.test(u)
            || /(?:^|\/)users\/authenticatewithquickconnect(?:\?|\/|$)/.test(u)
            || /(?:^|\/)users\/[0-9a-f-]+\/authenticate(?:\?|\/|$)/.test(u);
    }
    function handleTwoFactorBody(body) {
        if (!body || typeof body !== 'object') return false;
        if (!body.TwoFactorRequired && !body.twoFactorRequired) return false;
        // Hardcode the redirect path — never trust the server-supplied URL
        // (a malicious/compromised plugin or MITM could return an off-origin
        // ChallengePageUrl and steal the 2FA flow). The challenge token is
        // the only variable part.
        var token = body.ChallengeToken || body.challengeToken || '';
        var url = serverUrl('TwoFactorAuth/Challenge?token=' + encodeURIComponent(token));
        console.log('[2FA] Server requested 2FA challenge — redirecting');
        window.location.href = url;
        return true;
    }
    // Ensure every auth request carries a STABLE DeviceId even when the user
    // signs in via stock Jellyfin UI on LAN (which doesn't set one, so Jellyfin
    // falls back to a UserAgent-hash that differs from what the Cloudflare /
    // plugin login page sent — same browser ends up with multiple deviceIds,
    // one trusted, another pending, forever.)
    function getStableDeviceId() {
        var id = null;
        try { id = localStorage.getItem('_deviceId2'); } catch (e) {}
        if (!id) {
            try {
                id = crypto.getRandomValues
                    ? Array.from(crypto.getRandomValues(new Uint8Array(16)))
                        .map(function(b){return b.toString(16).padStart(2,'0');}).join('')
                    : String(Date.now()) + Math.random().toString(36).slice(2);
                localStorage.setItem('_deviceId2', id);
            } catch (e) {}
        }
        return id;
    }
    function rewriteAuthorizationDeviceId(value, id) {
        if (!value || !id || !/DeviceId=/i.test(value)) return value;
        return String(value).replace(
            /DeviceId\s*=\s*"[^"]*"/i,
            'DeviceId="' + id + '"');
    }
    function injectDeviceId(headers) {
        if (!headers) return headers;
        var id = getStableDeviceId();
        if (!id) return headers;
        try {
            if (headers instanceof Headers) {
                // Jellyfin 10.11 gives the standard Authorization header
                // precedence over legacy X-Emby-Authorization. Rewrite both
                // so the plugin and the SessionStarted event see one identity.
                function rewriteHeader(name) {
                    var existing = headers.get(name);
                    if (existing) {
                        headers.set(name, rewriteAuthorizationDeviceId(existing, id));
                    }
                }
                rewriteHeader('Authorization');
                rewriteHeader('X-Emby-Authorization');
                headers.set('X-Emby-Device-Id', id);
            } else if (typeof headers === 'object') {
                headers['X-Emby-Device-Id'] = id;
                Object.keys(headers).forEach(function (name) {
                    var lower = name.toLowerCase();
                    if (lower === 'authorization' || lower === 'x-emby-authorization') {
                        headers[name] = rewriteAuthorizationDeviceId(headers[name], id);
                    }
                });
            }
        } catch (e) {}
        return headers;
    }
    function authRequestHeaders(input, init) {
        try {
            if (init && init.headers) return new Headers(init.headers);
            if (typeof Request !== 'undefined' && input instanceof Request) {
                return new Headers(input.headers);
            }
        } catch (e) {
            if (init && init.headers) return init.headers;
        }
        return new Headers();
    }
    function isSameOriginUrl(url) {
        try { return new URL(String(url || ''), window.location.href).origin === window.location.origin; }
        catch (e) { return false; }
    }
    function getTrustedDeviceToken() {
        try { return localStorage.getItem('twofactor_device_token') || ''; }
        catch (e) { return ''; }
    }
    function injectTrustedDeviceToken(headers, url) {
        // This token can bypass the second factor, so never attach it to an
        // off-origin request even if a URL happens to end in an auth path.
        if (!headers || !isSameOriginUrl(url)) return headers;
        var token = getTrustedDeviceToken();
        if (!token) return headers;
        try {
            if (headers instanceof Headers) headers.set('X-TwoFactor-Token', token);
            else if (typeof headers === 'object') headers['X-TwoFactor-Token'] = token;
        } catch (e) {}
        return headers;
    }

    // [v2.5.10] (#55) Show a clear "account temporarily locked" toast on the
    // login page. The server (LockoutMessageMiddleware) returns a 401 with
    // {accountLocked:true,message} when a locked account tries to sign in;
    // Jellyfin's own UI would otherwise show only its generic
    // "Invalid username or password".
    function showLockoutToast(msg) {
        try {
            var text = msg || 'Your account is temporarily locked due to too many failed sign-in attempts. Please try again later.';
            var existing = document.getElementById('tfa-lockout-toast');
            if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
            var d = document.createElement('div');
            d.id = 'tfa-lockout-toast';
            d.setAttribute('role', 'alert');
            d.textContent = text;
            d.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);' +
                'z-index:99999;background:#b00020;color:#fff;padding:14px 22px;border-radius:8px;' +
                'font-size:15px;line-height:1.4;font-family:inherit;box-shadow:0 4px 16px rgba(0,0,0,.45);' +
                'max-width:90%;text-align:center;';
            document.body.appendChild(d);
            setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 8000);
        } catch (e) {}
    }

    var origFetch = window.fetch ? window.fetch.bind(window) : null;
    if (origFetch) {
        window.fetch = function (input, init) {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';

            // v2.4.12: short-circuit when 2FA is pending. Always allow the
            // auth paths through (so the user can re-authenticate) and the
            // /TwoFactorAuth/* paths that complete the challenge.
            if (isTfaPending() && !isAlwaysAllowedPath(url) && !isAuthPath(url)) {
                // [v2.5.14] (#99) Don't just dead-end every call with a synthetic
                // 403 (which Jellyfin Web surfaces as "server cannot be reached");
                // move the user to the 2FA portal so they can actually complete it.
                redirectToTfaPortal();
                return Promise.resolve(syntheticTfaBlockedResponse());
            }

            if (isAuthPath(url)) {
                init = init || {};
                init.headers = injectDeviceId(authRequestHeaders(input, init));
                init.headers = injectTrustedDeviceToken(init.headers, url);
            }
            var p = origFetch(input, init);
            return p.then(function (resp) {
                // v2.4.12: clear the pending flag once the user has successfully
                // completed 2FA — the Verify/Authenticate endpoints respond 200
                // on success, and that's our signal that the rest of the app's
                // API calls can flow again.
                if (resp.ok && isTfaCompletionPath(url)) {
                    clearTfaPending();
                    return resp;
                }
                // v2.4.12: also handle 403 (RequestBlockerMiddleware now returns
                // 403 instead of 401 for blocked-token-2FA-pending). Auth paths
                // still get 401 with the TwoFactorRequired marker.
                if (resp.status !== 401 && resp.status !== 403) return resp;
                var clone = resp.clone();
                return clone.json().then(function (body) {
                    // Any 2FA-required marker (from any endpoint) sets the flag
                    // so subsequent calls short-circuit. Without this, the
                    // first batch of post-login API calls all leak through
                    // before the redirect happens.
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        setTfaPending();
                        // [v2.5.14] (#99) A non-auth endpoint reporting 2FA-required
                        // (RequestBlockerMiddleware 403, no challenge token) means the
                        // user has a blocked session with no in-band way forward.
                        // handleTwoFactorBody() below only redirects auth-path
                        // responses (those carry a ChallengeToken); for everything
                        // else, send them to the portal instead of silently arming
                        // the flag and freezing the app.
                        if (!isAuthPath(url)) {
                            redirectToTfaPortal();
                        }
                    }
                    // [v2.5.10] (#55) account-lockout message on the login page.
                    if (body && (body.accountLocked || body.AccountLocked)) {
                        showLockoutToast(body.message || body.Message);
                    }
                    // [v2.5.10] (#68) empty-password blocked message.
                    if (body && (body.emptyPasswordBlocked || body.EmptyPasswordBlocked)) {
                        showLockoutToast(body.message || body.Message);
                    }
                    if (isAuthPath(url) && handleTwoFactorBody(body)) {
                        return new Promise(function () {});
                    }
                    return resp;
                }).catch(function () { return resp; });
            });
        };
    }
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    var origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function (method, url) {
        this.__tfa_url = url;
        this.__tfa_authHeaders = {};
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
        // Defer auth identity headers until send(). Calling setRequestHeader
        // twice appends instead of replacing, producing two conflicting
        // DeviceId values in native WebViews.
        if (typeof name === 'string' && isAuthPath(this.__tfa_url)) {
            var lower = name.toLowerCase();
            if (lower === 'authorization' || lower === 'x-emby-authorization') {
                this.__tfa_authHeaders[lower] = { name: name, value: value };
                return;
            }
        }
        return origSetHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        if (isAuthPath(xhr.__tfa_url)) {
            try {
                var id = getStableDeviceId();
                if (id) {
                    Object.keys(xhr.__tfa_authHeaders || {}).forEach(function (key) {
                        var entry = xhr.__tfa_authHeaders[key];
                        origSetHeader.call(
                            xhr,
                            entry.name,
                            rewriteAuthorizationDeviceId(entry.value, id));
                    });
                    origSetHeader.call(xhr, 'X-Emby-Device-Id', id);
                }
                if (isSameOriginUrl(xhr.__tfa_url)) {
                    var trustedToken = getTrustedDeviceToken();
                    if (trustedToken) {
                        origSetHeader.call(xhr, 'X-TwoFactor-Token', trustedToken);
                    }
                }
            } catch (e) {}
            xhr.addEventListener('readystatechange', function () {
                if (xhr.readyState !== 4) return;
                // v2.4.12: also recognise 403 (RequestBlockerMiddleware) in
                // addition to 401 (auth-path challenge response).
                if (xhr.status !== 401 && xhr.status !== 403) return;
                try {
                    var body = JSON.parse(xhr.responseText || '{}');
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        setTfaPending();
                    }
                    handleTwoFactorBody(body);
                } catch (e) {}
            });
        } else {
            // v2.4.12: non-auth XHR — we don't short-circuit (faking XHR
            // completion events is too brittle and risks confusing
            // jellyfin-apiclient consumers), but if the response carries
            // the 2FA-pending marker, set the flag so subsequent fetch()
            // calls short-circuit cleanly. The server-side 401->403 change
            // means even these uninterceptable XHRs don't get counted by
            // fail2ban's status-401-only failregex.
            xhr.addEventListener('readystatechange', function () {
                if (xhr.readyState !== 4) return;
                if (xhr.status !== 401 && xhr.status !== 403) return;
                try {
                    var body = JSON.parse(xhr.responseText || '{}');
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        setTfaPending();
                        // [v2.5.14] (#99) Same soft-lock escape as the fetch path —
                        // a non-auth XHR reporting 2FA-required has no challenge
                        // token to redirect to, so route the user to the portal.
                        redirectToTfaPortal();
                    }
                    // Clear flag on a successful 2FA completion observed via XHR.
                    if (xhr.status >= 200 && xhr.status < 300 && isTfaCompletionPath(xhr.__tfa_url)) {
                        clearTfaPending();
                    }
                } catch (e) {}
            });
        }
        return origSend.apply(this, arguments);
    };

    // ============================================================
    // 2. Sidebar entry — copies AchievementBadges' proven pattern.
    //    Find any .navMenuOption, copy its className so we inherit
    //    Jellyfin's emby-button styling, insert as a sibling.
    // ============================================================

    var DASHBOARD_NAV_ID = '__twofactor_dashnav';
    var dashboardNavBundles = {};
    var dashboardNavLanguageRequest = 0;
    function currentDashboardLanguage() {
        var supported = ['en', 'de', 'es', 'fr', 'it', 'ja', 'pt', 'zh'];
        try {
            var lang = String(document.documentElement.getAttribute('lang') || '')
                .split('-')[0]
                .toLowerCase();
            return supported.indexOf(lang) >= 0 ? lang : 'en';
        } catch (e) {
            return 'en';
        }
    }
    function setDashboardNavLabel(entry, value) {
        if (!entry || !value) return;
        var label = entry.querySelector('.MuiListItemText-primary, .navMenuOptionText');
        if (label) label.textContent = value;
    }
    function syncDashboardNavLanguage(entry) {
        entry = entry || document.getElementById(DASHBOARD_NAV_ID);
        if (!entry) return;
        var lang = currentDashboardLanguage();
        var cached = dashboardNavBundles[lang];
        if (cached) {
            setDashboardNavLabel(entry, cached);
            return;
        }

        var requestId = ++dashboardNavLanguageRequest;
        fetch(serverUrl('TwoFactorAuth/translations/' + encodeURIComponent(lang)), {
            credentials: 'include'
        }).then(function (r) {
            return r.ok ? r.json() : null;
        }).then(function (bundle) {
            if (requestId !== dashboardNavLanguageRequest
                || lang !== currentDashboardLanguage()) return;
            var translated = bundle && bundle['tfa.login.nav_entry'];
            if (!translated) return;
            dashboardNavBundles[lang] = translated;
            setDashboardNavLabel(
                document.getElementById(DASHBOARD_NAV_ID) || entry,
                translated);
        }).catch(function () { /* keep authored fallback */ });
    }
    /// Inject a "Two-Factor Auth" item into the admin Dashboard left sidebar
    /// (where Achievements, File Transformation, etc live). Only fires when
    /// the user is on a /web/#!/dashboard route — out on the main app drawer
    /// the existing injectSidebar adds a user-facing entry instead.
    function injectDashboardNav() {
        try {
            var hash = (window.location.hash || '').toLowerCase();
            // Jellyfin admin dashboard hash routes look like #!/dashboard,
            // #!/plugins, #!/scheduledtasks etc. Match anything under
            // /web/#!/dashboard or the plugin pages it generates.
            if (hash.indexOf('dashboard') < 0 && hash.indexOf('plugin') < 0
                && hash.indexOf('scheduledtask') < 0 && hash.indexOf('users') < 0
                && hash.indexOf('library') < 0 && hash.indexOf('configuration') < 0
                && hash.indexOf('serveractivity') < 0 && hash.indexOf('apikeys') < 0) {
                return;
            }
            // SEC-L5: gate on admin status — non-admins shouldn't see the
            // entry at all (clicking it just lands on a "no permission" page,
            // but cosmetic-only links to admin pages are still confusing for
            // regular users). ApiClient.getCurrentUser is async; bail early
            // if it's not yet available.
            try {
                if (window.ApiClient && ApiClient.getCurrentUser) {
                    ApiClient.getCurrentUser().then(function(u) {
                        var isAdmin = u && u.Policy && u.Policy.IsAdministrator;
                        if (!isAdmin) return;
                        injectDashboardNavInner();
                    });
                    return;
                }
            } catch (e) { /* fall through */ }
            injectDashboardNavInner();
        } catch (outerE) {
            console.error('[2FA] injectDashboardNav outer error:', outerE);
        }
    }
    function injectDashboardNavInner() {
        try {
            // Dashboard sidebar uses .adminDrawerLogo + nav links with
            // class .navMenuOption inside .mainDrawerScrollSlider OR
            // newer Jellyfin 10.11: a React/MUI drawer whose rows are anchors
            // below a <ul>. Mobile and desktop can leave older, hidden drawer
            // trees mounted at the same time, so prefer the currently visible
            // Plugins/Extensions route instead of the first DOM match.
            var anchor = null;
            var fallbackAnchor = null;
            var navLinks = document.querySelectorAll('a.navMenuOption, a.navDrawer-button, a[href*="/dashboard"]');
            for (var i = 0; i < navLinks.length; i++) {
                var href = (navLinks[i].getAttribute('href') || '').toLowerCase();
                var t = (navLinks[i].textContent || '').trim().toLowerCase();
                // The route is locale-stable; the label is not ("Extensions"
                // in French, for example). Prefer href and retain the English
                // text fallback for older dashboard markup.
                if (href.indexOf('dashboard/plugins') >= 0
                    || href.indexOf('/plugins') >= 0
                    || t === 'plugins'
                    || t.indexOf('plugins') === 0) {
                    if (!fallbackAnchor) fallbackAnchor = navLinks[i];
                    if (navLinks[i].getClientRects().length > 0) {
                        anchor = navLinks[i];
                        break;
                    }
                }
            }
            anchor = anchor || fallbackAnchor;
            if (!anchor) return;

            var parent = anchor.parentElement;
            if (!parent) return;

            // A hidden legacy drawer and the active React drawer can coexist.
            // Keep exactly one entry, but move/recreate it beside the active
            // route when Jellyfin swaps drawer implementations.
            var existing = document.getElementById(DASHBOARD_NAV_ID);
            if (existing && existing.parentElement === parent
                && existing.previousElementSibling === anchor) {
                syncDashboardNavLanguage(existing);
                return;
            }
            if (existing) existing.remove();

            // Clone Jellyfin's native row so React/MUI spacing, touch target,
            // typography and responsive behavior remain identical to Plugins.
            var a = anchor.cloneNode(true);
            a.id = DASHBOARD_NAV_ID;
            a.href = serverUrl('web/index.html#/configurationpage?name=TwoFactorAuth');
            a.className = (anchor.className || 'navMenuOption emby-button')
                .replace(/\bMui-selected\b/g, '')
                .replace(/\s{2,}/g, ' ')
                .trim();
            a.removeAttribute('aria-current');
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
            a.addEventListener('click', function (e) {
                e.preventDefault();
                // Plugin admin config page lives at the standard plugin
                // configuration URL — this drops into Jellyfin's normal
                // plugin-config view of our admin tabs.
                window.location.assign(serverUrl('web/index.html#/configurationpage?name=TwoFactorAuth'));
            });

            var label = a.querySelector('.MuiListItemText-primary, .navMenuOptionText');
            if (label) {
                label.textContent = T('tfa.login.nav_entry', 'Two-Factor Auth');
                label.setAttribute('data-i18n-key', 'tfa.login.nav_entry');
            } else {
                a.innerHTML =
                    '<span class="material-icons navMenuOptionIcon" style="font-family:Material Icons;" aria-hidden="true">security</span>' +
                    '<span class="navMenuOptionText" data-i18n-key="tfa.login.nav_entry">' + T('tfa.login.nav_entry', 'Two-Factor Auth') + '</span>';
            }

            var muiIcon = a.querySelector('.MuiListItemIcon-root');
            if (muiIcon) {
                muiIcon.innerHTML =
                    '<span class="material-icons" style="font-family:Material Icons;" aria-hidden="true">security</span>';
            } else {
                var legacyIcon = a.querySelector('.navMenuOptionIcon');
                if (legacyIcon) legacyIcon.textContent = 'security';
            }

            if (anchor.nextSibling) parent.insertBefore(a, anchor.nextSibling);
            else parent.appendChild(a);
            // [v2.5.12] (#79) translate the just-injected entry once the bundle
            // is available (it may have loaded after the i18n-ready event fired).
            try { if (window.tfaI18n) window.tfaI18n.applyTranslations(a); } catch (e) { /* ignore */ }
            syncDashboardNavLanguage(a);
        } catch (e) {
            console.error('[2FA] injectDashboardNav error:', e);
        }
    }

    function injectSidebar() {
        try {
            if (document.getElementById(SIDEBAR_ID)) return;
            var allItems = document.querySelectorAll('.navMenuOption');
            if (!allItems.length) return;

            // Anchor: prefer "Settings" / "User" related items, fall back to first nav item
            var anchorItem = null;
            var placement = 'after';
            for (var i = 0; i < allItems.length; i++) {
                var txt = (allItems[i].textContent || '').trim().toLowerCase();
                if (txt === 'settings' || txt === 'preferences' || txt === 'profile') {
                    anchorItem = allItems[i]; placement = 'after'; break;
                }
            }
            if (!anchorItem) {
                for (var j = 0; j < allItems.length; j++) {
                    var href = (allItems[j].getAttribute('href') || '').toLowerCase();
                    if (href.indexOf('mypreferencesmenu') >= 0 || href.indexOf('myprofile') >= 0) {
                        anchorItem = allItems[j]; placement = 'after'; break;
                    }
                }
            }
            if (!anchorItem) { anchorItem = allItems[0]; placement = 'before'; }

            var parent = anchorItem.parentElement;
            if (!parent) return;

            var a = document.createElement('a');
            a.id = SIDEBAR_ID;
            a.href = withLang(serverUrl('TwoFactorAuth/Setup'));
            a.className = anchorItem.className || 'navMenuOption emby-button';
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
            // [v2.5.12] (#79) Recompute ?lang at CLICK time — the entry may be
            // injected before jellyfin-web finishes localizing (cold load), which
            // would otherwise bake in a stale ?lang=en.
            a.addEventListener('click', function () { try { a.href = withLang(serverUrl('TwoFactorAuth/Setup')); } catch (e) {} });
            a.innerHTML =
                '<span class="material-icons navMenuOptionIcon" style="font-family:Material Icons;" aria-hidden="true">security</span>' +
                '<span class="navMenuOptionText" data-i18n-key="tfa.login.nav_entry">' + T('tfa.login.nav_entry', 'Two-Factor Auth') + '</span>';

            if (placement === 'after') {
                if (anchorItem.nextSibling) parent.insertBefore(a, anchorItem.nextSibling);
                else parent.appendChild(a);
            } else {
                parent.insertBefore(a, anchorItem);
            }
            // [v2.5.12] (#79) translate the just-injected entry once the bundle
            // is available (it may have loaded after the i18n-ready event fired).
            try { if (window.tfaI18n) window.tfaI18n.applyTranslations(a); } catch (e) { /* ignore */ }

            console.log('[2FA] Sidebar entry inserted (anchor:', (anchorItem.textContent || '').trim(), placement + ')');
        } catch (e) {
            console.error('[2FA] injectSidebar error:', e);
        }
    }

    // ============================================================
    // 3. Settings page tile — for users who land on the user
    //    preferences page rather than open the side drawer.
    // ============================================================

    function injectSettingsTile() {
        try {
            var hash = (window.location.hash || '').toLowerCase();
            var onPrefsPage = hash.indexOf('mypreferencesmenu') >= 0
                || hash.indexOf('userprofile') >= 0
                || hash.indexOf('myprofile') >= 0
                || hash.indexOf('preferences') >= 0;
            if (!onPrefsPage) return;
            if (document.getElementById(SETTINGS_TILE_ID)) return;

            // Find Profile to anchor placement. We intentionally do NOT clone
            // any sibling tile's markup — themes (JellyFlare / StarTrack /
            // KefinTweaks) inject extra glyphs via CSS selectors matched on
            // href, class, or inner material-icons text. Every clone we tried
            // leaked at least one decorative icon. Building from scratch with
            // only Jellyfin's base classes avoids all theme targeting.
            var profile = null;
            // [v2.5.14] (#101) Anchor primarily by HREF, not by the literal English
            // word "profile". The text-only match silently failed on every
            // non-English Jellyfin UI (e.g. "Profil"/"Perfil"/"プロフィール"), which
            // is why the "Two-Factor Authentication" entry went missing from the
            // user-preferences list for affected users. Hrefs are locale-stable.
            var hrefAnchor = document.querySelector(
                'a[href*="myprofile"], a[href*="mypreferencesmenu"], a[href*="userprofile"]');
            if (hrefAnchor) {
                profile = hrefAnchor;
            }
            if (!profile) {
                var all = document.querySelectorAll('a, button');
                for (var i = 0; i < all.length; i++) {
                    var txt = (all[i].textContent || '').trim().toLowerCase();
                    if (txt === 'profile' || txt.indexOf('profile') === 0) {
                        profile = all[i];
                        break;
                    }
                }
            }
            if (!profile) {
                // Last resort: anchor to any other preferences sub-page link so the
                // tile still lands in the list even when neither href nor English
                // text matched.
                profile = document.querySelector(
                    'a[href*="mypreferences"], a[href*="#/myprofile"], a[href*="quickconnect"]');
            }
            if (!profile) {
                console.warn('[2FA] injectSettingsTile: no profile/preferences anchor found — '
                    + 'Two-Factor entry not injected (issue #101). hash=' + (window.location.hash || ''));
                return;
            }

            // Walk up from Profile to the real row (direct child of the list).
            var template = profile;
            var container = profile.parentElement;
            while (container && container !== document.body) {
                var siblingTiles = 0;
                var children = container.children || [];
                for (var j = 0; j < children.length; j++) {
                    var c = children[j];
                    if (c === template) continue;
                    var tn = c.tagName ? c.tagName.toLowerCase() : '';
                    if (tn === 'a' || tn === 'button' || (c.className && /listItem|cardBox|button-link/i.test(c.className))) {
                        siblingTiles++;
                        if (siblingTiles >= 1) break;
                    }
                }
                if (siblingTiles >= 1) break;
                template = container;
                container = container.parentElement;
            }
            if (!container || container === document.body) return;

            // Build from scratch. Use Jellyfin's base listItem classes (the
            // same set the stock UI uses when themes aren't active) so layout
            // inherits the drawer's row spacing without matching theme rules.
            var tile = document.createElement('a');
            tile.id = SETTINGS_TILE_ID;
            // Don't set href — Jellyfin's emby-linkbutton + router would
            // rewrite /TwoFactorAuth/Setup to /web/index.html#/TwoFactorAuth/Setup,
            // which is a SPA route and 404s. Use a click handler for a hard
            // navigation that leaves the SPA entirely.
            tile.style.cursor = 'pointer';
            tile.addEventListener('click', function (e) {
                e.preventDefault();
                window.location.assign(withLang(serverUrl('TwoFactorAuth/Setup')));
            });
            tile.className = 'listItem listItem-border listItem-button';
            tile.innerHTML =
                '<span class="material-icons listItemIcon listItemIcon-transparent" aria-hidden="true" style="font-family:\'Material Icons\';">security</span>' +
                '<div class="listItemBody">' +
                    '<div class="listItemBodyText" data-i18n-key="tfa.login.settings_tile">' + T('tfa.login.settings_tile', 'Two-Factor Authentication') + '</div>' +
                '</div>' +
                '<span class="material-icons" aria-hidden="true" style="font-family:\'Material Icons\';margin-left:auto;opacity:0.5;">chevron_right</span>';

            if (template.nextSibling) container.insertBefore(tile, template.nextSibling);
            else container.appendChild(tile);
            try { if (window.tfaI18n) window.tfaI18n.applyTranslations(tile); } catch (e) { /* ignore */ }
            console.log('[2FA] Settings tile inserted next to Profile');
        } catch (e) {
            console.error('[2FA] injectSettingsTile error:', e);
        }
    }

    // ============================================================
    // 4. (Existing) Login-form button — backup affordance
    // ============================================================

    function addStyles() {
        if (document.getElementById(STYLE_ID)) return;
        var style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent =
            '#' + BUTTON_ID + ' {' +
                'display:block;box-sizing:border-box;width:100%;' +
                'padding:0.9em 1em;margin-top:0.5em;' +
                'background:transparent;color:inherit;' +
                'border:1px solid rgba(255,255,255,0.2);border-radius:0.2em;' +
                'font-family:inherit;font-size:inherit;font-weight:inherit;line-height:inherit;letter-spacing:inherit;' +
                'text-transform:inherit;text-decoration:none;text-align:center;' +
                'cursor:pointer;-webkit-appearance:none;appearance:none;' +
                'transition:background-color 0.15s ease;' +
            '}' +
            '#' + BUTTON_ID + ':hover { background:rgba(255,255,255,0.08); }' +
            '#' + BUTTON_ID + ' .tfa-icon { margin-right:0.4em;vertical-align:middle; }';
        document.head.appendChild(style);
    }
    function isLoginPage() {
        var hash = window.location.hash || '';
        return hash.indexOf('login') >= 0 || hash === '' || hash === '#';
    }
    function findUsername() {
        var input = document.querySelector('input#txtManualName, input[name="username"], input#username, .manualLoginForm input[type="text"]:not([type="password"])');
        return input && input.value ? input.value.trim() : '';
    }
    // [v2.5.7] (issue #48 feature, Gaarindor): lazy-fetch the anonymous
    // public-config so addLoginButton can honour HideBuiltInLoginButtons.
    // First call kicks off the fetch and returns early; subsequent polling
    // ticks (tryInject runs every ~250ms) re-enter and either render or
    // skip based on the flag.
    var _tfaPublicCfg = null;
    var _tfaPublicCfgPromise = null;
    function fetchTfaPublicConfig() {
        if (_tfaPublicCfgPromise) return _tfaPublicCfgPromise;
        _tfaPublicCfgPromise = fetch(serverUrl('TwoFactorAuth/public-config'), { credentials: 'omit' })
            .then(function (r) { return r.ok ? r.json() : {}; })
            .then(function (j) { _tfaPublicCfg = j || {}; return _tfaPublicCfg; })
            .catch(function () { _tfaPublicCfg = {}; return _tfaPublicCfg; });
        return _tfaPublicCfgPromise;
    }

    // [v2.5.11] (#69, ZEROX7) hide the username/password form when password
    // sign-in is disabled for this client — leaving only the SSO + Quick Connect
    // affordances. A discreet "sign in with a password instead" link reveals it
    // again (the server still allows admins / LAN / exempt IPs via the escape
    // hatches; everyone else gets a clear 403 if they submit).
    function _tfaFieldWrap(form, sel) {
        var el = form.querySelector(sel);
        if (!el) return null;
        return el.closest('.inputContainer') || el;
    }
    function applyPasswordLoginGate() {
        if (!isLoginPage() || _tfaPublicCfg === null) return;
        var form = document.querySelector('.manualLoginForm') || document.querySelector('form');
        if (!form) return;
        var REVEAL_ID = '__tfa_pw_reveal';
        var wraps = [
            _tfaFieldWrap(form, 'input#txtManualName, input[name="username"], input#username'),
            _tfaFieldWrap(form, 'input[type="password"], input#txtManualPassword, input[name="password"]'),
            form.querySelector('button[type="submit"]')
        ];
        if (!_tfaPublicCfg.passwordLoginDisabled || window.__tfaPwRevealed) {
            // Not gated (or the user revealed it): make sure everything is visible.
            wraps.forEach(function (w) { if (w) w.style.display = ''; });
            var ex0 = document.getElementById(REVEAL_ID); if (ex0 && _tfaPublicCfg.passwordLoginDisabled !== true) ex0.remove();
            return;
        }
        wraps.forEach(function (w) { if (w) w.style.display = 'none'; });
        if (!document.getElementById(REVEAL_ID)) {
            var link = document.createElement('a');
            link.id = REVEAL_ID;
            link.href = '#';
            link.textContent = (_tfaPublicCfg.passwordLoginRevealText || T('tfa.login.pw_reveal', 'Sign in with a password instead'));
            link.style.cssText = 'display:block;margin-top:12px;text-align:center;color:#7d828b;font-size:13px;cursor:pointer;';
            link.addEventListener('click', function (e) {
                e.preventDefault();
                window.__tfaPwRevealed = true;
                wraps.forEach(function (w) { if (w) w.style.display = ''; });
                link.remove();
            });
            form.appendChild(link);
        }
    }

    // [v2.5.11] (#71, ZEROX7) "Forgot password?" link → reveals a small inline
    // form that emails a one-time reset link. Shown only when the server reports
    // recovery is enabled (EnablePasswordRecovery + SMTP configured). The
    // response is always generic, so this can't be used to probe for accounts.
    function addForgotPasswordLink() {
        if (!isLoginPage() || _tfaPublicCfg === null) return;
        if (!_tfaPublicCfg.passwordRecoveryEnabled) return;
        var form = document.querySelector('.manualLoginForm') || document.querySelector('form');
        if (!form || document.getElementById('__tfa_forgot')) return;
        var wrap = document.createElement('div');
        wrap.id = '__tfa_forgot';
        wrap.style.cssText = 'margin-top:12px;text-align:center;';
        var link = document.createElement('a');
        link.href = '#';
        link.setAttribute('data-i18n-key', 'tfa.login.forgot');
        link.textContent = T('tfa.login.forgot', 'Forgot password?');
        link.style.cssText = 'color:#7d828b;font-size:13px;cursor:pointer;';
        var panel = document.createElement('div');
        panel.style.cssText = 'display:none;margin-top:10px;text-align:left;';
        panel.innerHTML =
            '<input id="__tfa_forgot_id" type="text" placeholder="' + T('tfa.login.forgot_id_ph', 'Username or email') + '" data-i18n-placeholder="tfa.login.forgot_id_ph" autocomplete="username" style="width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #2a2d33;background:#0e1014;color:#e6e6e6;" />'
            + '<button id="__tfa_forgot_send" type="button" class="raised block emby-button" data-i18n-key="tfa.login.forgot_send" style="margin-top:8px;width:100%;">' + T('tfa.login.forgot_send', 'Email me a reset link') + '</button>'
            + '<div id="__tfa_forgot_msg" style="margin-top:8px;font-size:13px;color:#aeb4bd;"></div>';
        link.addEventListener('click', function (e) {
            e.preventDefault();
            panel.style.display = (panel.style.display === 'none') ? 'block' : 'none';
        });
        wrap.appendChild(link);
        wrap.appendChild(panel);
        form.appendChild(wrap);
        panel.querySelector('#__tfa_forgot_send').addEventListener('click', function () {
            var idv = (panel.querySelector('#__tfa_forgot_id').value || '').trim();
            var m = panel.querySelector('#__tfa_forgot_msg');
            if (!idv) { m.textContent = T('tfa.login.forgot_enter_id', 'Enter your username or email first.'); return; }
            m.textContent = T('tfa.login.sending', 'Sending…');
            fetch(serverUrl('TwoFactorAuth/PasswordReset/Request'), {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit',
                body: JSON.stringify({ Identifier: idv })
            }).then(function (r) { return r.json().catch(function () { return {}; }); })
              .then(function (j) { m.textContent = (j && j.message) || T('tfa.login.reset_sent', 'If an account exists, a reset link has been sent.'); })
              .catch(function () { m.textContent = T('tfa.login.reset_sent', 'If an account exists, a reset link has been sent.'); });
        });
    }

    // [v2.5.12] (#80, ZEROX7) When the plugin offers its OWN password recovery
    // (#71 reset-link flow, surfaced by addForgotPasswordLink), Jellyfin's native
    // "Forgot password?" link is redundant and confusing — it kicks off Jellyfin's
    // built-in reset which the admin may not have wired up. Hide the native link
    // whenever our recovery is enabled, leaving only the plugin's flow. Our own
    // link lives inside #__tfa_forgot, so it is never matched here.
    function hideNativeForgotPassword() {
        if (!isLoginPage() || _tfaPublicCfg === null) return;
        // [v2.5.12] (#80) only when our recovery is on AND the admin left the
        // "hide built-in link" sub-option enabled (default on).
        if (!_tfaPublicCfg.passwordRecoveryEnabled) return;
        if (_tfaPublicCfg.hideBuiltInForgotPassword === false) return;
        try {
            var native = document.querySelectorAll('.btnForgotPassword');
            for (var i = 0; i < native.length; i++) {
                if (!native[i].closest('#__tfa_forgot')) native[i].style.display = 'none';
            }
            // Fallback: themes/older builds may not use .btnForgotPassword — match
            // an anchor whose visible text is the native "Forgot password" label,
            // skipping our own injected link.
            var anchors = document.querySelectorAll('.manualLoginForm a, form a, a[is="emby-linkbutton"]');
            for (var j = 0; j < anchors.length; j++) {
                var a = anchors[j];
                if (a.closest('#__tfa_forgot')) continue;
                var t = (a.textContent || '').trim().toLowerCase();
                if (t === 'forgot password' || t === 'forgot password?') a.style.display = 'none';
            }
        } catch (e) { /* ignore */ }
    }

    // [v2.5.16] (#79, ZEROX7) Hide the native "Forgot password" control when there
    // is no visible password field to recover — e.g. password login is hidden
    // (OIDC-only mode) or collapsed behind "Sign in with a password instead". A
    // reset link is meaningless when the user has no password box to type into.
    // Only acts when NO visible password input exists, so normal password logins
    // are untouched.
    function hideForgotPasswordWhenNoPassword() {
        if (!isLoginPage()) return;
        try {
            var pw = document.querySelector('input[type="password"]');
            if (pw && pw.offsetParent !== null) return; // a password field is visible — leave it
            var native = document.querySelectorAll('.btnForgotPassword');
            for (var i = 0; i < native.length; i++) {
                if (!native[i].closest('#__tfa_forgot')) native[i].style.display = 'none';
            }
        } catch (e) { /* ignore */ }
    }

    // [v2.5.16] (#79, ZEROX7) Opt-in: move the injected login links (OIDC / 2FA /
    // passkey) to just below Jellyfin's "Use Quick Connect" button, in that order.
    // Default off (flag from public config). Idempotent + theme-safe: if Quick
    // Connect isn't found it leaves the links where they are. Runs each inject tick.
    function repositionLinksBelowQuickConnect() {
        try {
            if (!_tfaPublicCfg || !_tfaPublicCfg.loginLinksBelowQuickConnect) return;
            var qc = document.querySelector('.btnQuick');
            if (!qc || qc.offsetParent === null || !qc.parentNode) return;
            var after = qc;
            [OIDC_BUTTONS_ID, BUTTON_ID, '__twofactor_passkey_btn'].forEach(function (id) {
                var el = document.getElementById(id);
                if (!el) return;
                if (after.nextSibling !== el) { after.parentNode.insertBefore(el, after.nextSibling); }
                after = el;
            });
        } catch (e) { /* ignore */ }
    }

    function addLoginButton() {
        if (!isLoginPage()) return;
        // [v2.5.7] (issue #48 feature, Gaarindor): while the public-config
        // fetch is in flight (_tfaPublicCfg === null) skip injecting — the
        // next polling tick will re-enter once the response arrives.
        if (_tfaPublicCfg === null) { fetchTfaPublicConfig(); return; }
        // [v2.5.11] (#69) hide/reveal the password form per the public-config gate.
        applyPasswordLoginGate();
        // [v2.5.11] (#71) add the "Forgot password?" affordance when enabled.
        addForgotPasswordLink();
        // [v2.5.12] (#80) hide Jellyfin's native forgot-password link when ours is active.
        hideNativeForgotPassword();
        // [v2.5.16] (#79) also hide it when there's no visible password field at all.
        hideForgotPasswordWhenNoPassword();
        var hideTwoFa = !!_tfaPublicCfg.hideBuiltInTwoFactorButton;
        var hidePasskey = !!_tfaPublicCfg.hideBuiltInPasskeyButton;
        var signInBtn = document.querySelector('.manualLoginForm button[type="submit"], .manualLoginForm .raised, form button[type="submit"]');
        if (!signInBtn) return;
        // [v2.5.7] (issue #48): if the admin re-enabled a button on a page
        // that already rendered with it hidden (or vice versa) the existing
        // node needs to be torn down before we re-evaluate. Cheap idempotent
        // cleanup — removes only if present.
        var existingTwoFa = document.getElementById(BUTTON_ID);
        var existingPasskey = document.getElementById('__twofactor_passkey_btn');
        if (hideTwoFa && existingTwoFa) existingTwoFa.remove();
        if (hidePasskey && existingPasskey) existingPasskey.remove();

        if (!hideTwoFa && !existingTwoFa) {
            addStyles();
            var btn = document.createElement('a');
            btn.id = BUTTON_ID;
            btn.setAttribute('is', 'emby-linkbutton');
            btn.className = (signInBtn.className || 'raised block').replace(/button-submit|button-cancel|emby-button/g, '').trim();
            btn.innerHTML = '<span class="tfa-icon">🔐</span><span data-i18n-key="tfa.login.btn_2fa">' + T('tfa.login.btn_2fa', 'Sign in with Two-Factor Authentication') + '</span>';
            btn.href = withLang(serverUrl('TwoFactorAuth/Login'));
            (function () {
                function updateHref() {
                    var u = findUsername();
                    btn.href = withLang(serverUrl(u
                        ? 'TwoFactorAuth/Login?username=' + encodeURIComponent(u)
                        : 'TwoFactorAuth/Login'));
                }
                btn.addEventListener('click', function (e) { e.preventDefault(); updateHref(); window.location.assign(btn.href); });
                var userInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
                if (userInput) ['input', 'change', 'blur'].forEach(function (ev) { userInput.addEventListener(ev, updateHref); });
            })();
            var parent = signInBtn.parentNode;
            if (signInBtn.nextSibling) parent.insertBefore(btn, signInBtn.nextSibling);
            else parent.appendChild(btn);
        }

        // Passkey button: anchor below the 2FA button when present, else
        // below the Jellyfin sign-in button directly. addPasskeyButton
        // returns early if the existing node is already present.
        if (!hidePasskey) {
            var anchorAbove = document.getElementById(BUTTON_ID) || signInBtn;
            addStyles();
            addPasskeyButton(signInBtn, anchorAbove);
        }

        // [v2.5.16] (#79) optionally relocate the injected links below Quick Connect.
        repositionLinksBelowQuickConnect();
    }

    // v2.1: passkey primary login button — sits below the 2FA button. Click
    // takes the username from the form, asks the server for assertion options,
    // runs navigator.credentials.get, posts the signed assertion back, gets a
    // bridge token, fills it in as the password and submits the form.
    function addPasskeyButton(signInBtn, twoFaBtn) {
        if (document.getElementById('__twofactor_passkey_btn')) return;
        // Only show when WebAuthn is available in a secure context.
        if (!(window.isSecureContext && window.PublicKeyCredential)) return;

        var btn = document.createElement('a');
        btn.id = '__twofactor_passkey_btn';
        btn.setAttribute('is', 'emby-linkbutton');
        btn.className = twoFaBtn.className;
        btn.innerHTML = '<span class="tfa-icon">🔑</span><span data-i18n-key="tfa.login.btn_passkey">' + T('tfa.login.btn_passkey', 'Sign in with passkey') + '</span>';
        btn.style.cursor = 'pointer';
        btn.href = '#';
        btn.addEventListener('click', async function(e) {
            e.preventDefault();
            var u = findUsername();
            if (!u) { alert(T('tfa.login.passkey_enter_user', 'Enter your username first, then click Sign in with passkey.')); return; }
            var orig = btn.innerHTML;
            btn.innerHTML = '<span class="tfa-icon">🔑</span>Waiting for authenticator…';
            try {
                var begin = await fetch(serverUrl('TwoFactorAuth/Passkey/LoginBegin'), {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ Username: u }),
                });
                if (!begin.ok) {
                    var err = await begin.json().catch(function(){return{};});
                    throw new Error(err.message || ('HTTP ' + begin.status));
                }
                var beginBody = await begin.json();
                var opts = JSON.parse(beginBody.options);
                opts.challenge = b64uToBytes(opts.challenge);
                if (opts.allowCredentials) opts.allowCredentials.forEach(function(c){ c.id = b64uToBytes(c.id); });
                var assertion = await navigator.credentials.get({ publicKey: opts });
                var resp = {
                    id: assertion.id, rawId: bytesToB64u(assertion.rawId), type: assertion.type,
                    response: {
                        authenticatorData: bytesToB64u(assertion.response.authenticatorData),
                        clientDataJSON: bytesToB64u(assertion.response.clientDataJSON),
                        signature: bytesToB64u(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? bytesToB64u(assertion.response.userHandle) : null,
                    },
                };
                var complete = await fetch(serverUrl('TwoFactorAuth/Passkey/LoginComplete'), {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ Username: u, Nonce: beginBody.nonce, Response: JSON.stringify(resp) }),
                });
                if (!complete.ok) {
                    var err2 = await complete.json().catch(function(){return{};});
                    throw new Error(err2.message || 'Passkey verification failed');
                }
                var data = await complete.json();
                // Stuff the bridge token into the password field and submit the
                // standard Jellyfin form — TwoFactorAuthProvider sees the token
                // prefix and accepts the login with no further challenge.
                var passInput = document.querySelector('input#txtManualPassword, input[name="password"], input#password');
                if (!passInput) throw new Error('Password field not found');
                passInput.value = data.token;
                passInput.dispatchEvent(new Event('input', { bubbles: true }));
                signInBtn.click();
            } catch (err) {
                btn.innerHTML = orig;
                alert('Passkey sign-in failed: ' + (err && err.message ? err.message : err));
            }
        });
        var parent = twoFaBtn.parentNode;
        if (twoFaBtn.nextSibling) parent.insertBefore(btn, twoFaBtn.nextSibling);
        else parent.appendChild(btn);
    }

    // Base64url ⇔ ArrayBuffer — same helpers as challenge.html.
    function b64uToBytes(s) { s = s.replace(/-/g,'+').replace(/_/g,'/'); while (s.length % 4) s += '='; var b = atob(s); var a = new Uint8Array(b.length); for (var i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a.buffer; }
    function bytesToB64u(buf) { var b = new Uint8Array(buf); var s=''; for (var i=0;i<b.length;i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

    // ============================================================
    // Bootstrap — combine MutationObserver + 1s polling for 60s,
    //             matching AchievementBadges' battle-tested approach.
    // ============================================================

    // ============================================================
    // 5. (v2.0) OIDC sign-in — render provider buttons on login,
    //    auto-submit when redirected back from a provider.
    // ============================================================

    var OIDC_BUTTONS_ID = '__twofactor_oidc_buttons';
    var OIDC_AUTOSUBMIT_FLAG = '__twofactor_oidc_autosubmitted';

    function getQueryParam(name) {
        // Login page params live in the hash, e.g. /web/index.html#!/login.html?oidcUser=...
        var hash = window.location.hash || '';
        var qIdx = hash.indexOf('?');
        if (qIdx < 0) return null;
        var pairs = hash.substring(qIdx + 1).split('&');
        for (var i = 0; i < pairs.length; i++) {
            var p = pairs[i].split('=');
            if (decodeURIComponent(p[0]) === name) return decodeURIComponent((p[1] || '').replace(/\+/g, ' '));
        }
        return null;
    }

    // ---------------------------------------------------------------------
    // [v2.5.9] (issue #64): in-page OIDC for embedded app webviews.
    //
    // The Jellyfin Android app's webview bounces to its server-select screen
    // whenever the page navigates off /web/ — so the old full-page redirect to
    // /Oidc/Login dead-ended, and even after NativeShell opened the browser,
    // the polling page had been destroyed. Instead, when the app's native
    // shell is present we keep the web client loaded and run the whole flow in
    // an in-page modal: open the consent in the system browser via
    // NativeShell.openUrl, poll the server for completion, then sign in using
    // the existing form-fill + bridge-token path. /web/ never unloads, so the
    // poller survives the trip to the browser and back.
    var OIDC_MODAL_ID = '__twofactor_oidc_modal';

    function hasNativeShell() {
        try {
            return (window.NativeShell && typeof window.NativeShell.openUrl === 'function')
                || (window.NativeInterface && typeof window.NativeInterface.openUrl === 'function');
        } catch (e) { return false; }
    }

    // Intercept in ANY embedded app webview — not only when the native shell
    // is detected at the click instant (it can attach late). Inside the modal
    // we still prefer NativeShell.openUrl, then window.open, then copy-link, so
    // the popup works even without a native bridge. Plain desktop/mobile
    // browsers fall through to the normal full-page redirect (which works).
    function inEmbeddedWebView() {
        try {
            // window.NativeShell / NativeInterface are injected by Jellyfin
            // NATIVE clients (Android app, Media Player) and are ABSENT in a
            // plain desktop/mobile browser — the most reliable "I'm inside an
            // app webview" signal. Check EXISTENCE (not a specific method
            // signature) so a differing shape still triggers the in-page popup
            // rather than falling through to the bouncing full-page redirect.
            if (typeof window.NativeShell !== 'undefined' && window.NativeShell) return true;
            if (typeof window.NativeInterface !== 'undefined' && window.NativeInterface) return true;
            var ua = navigator.userAgent || '';
            if (ua.indexOf('; wv') !== -1 || ua.indexOf('(wv)') !== -1) return true;
        } catch (e) {}
        return false;
    }

    // [v2.5.12] (#64) Returns true only if a NATIVE bridge handled the open (which
    // hands off to the real external browser). Returns false if we could only fall
    // back to window.open — on an Android app WebView that loads the URL IN the
    // WebView, which Google rejects with "disallowed_useragent". Callers use the
    // result to steer the user to the copy-link fallback. Try multiple bridge
    // shapes/arities since app builds differ (some expose openUrl(url) 1-arg).
    function openExternalUrl(url) {
        try { if (window.NativeShell && typeof window.NativeShell.openUrl === 'function') { window.NativeShell.openUrl(url, '_blank'); return true; } } catch (e) {}
        try { if (window.NativeShell && typeof window.NativeShell.openUrl === 'function') { window.NativeShell.openUrl(url); return true; } } catch (e) {}
        try { if (window.NativeInterface && typeof window.NativeInterface.openUrl === 'function') { window.NativeInterface.openUrl(url); return true; } } catch (e) {}
        try { if (window.NativeShell && typeof window.NativeShell.openExternalUrl === 'function') { window.NativeShell.openExternalUrl(url); return true; } } catch (e) {}
        // Last resort — may open inside the WebView (Google "disallowed_useragent").
        try { window.open(url, '_blank', 'noopener'); } catch (e) {}
        return false;
    }

    function closeOidcModal() {
        window.__tfaOidcPolling = false;
        var m = document.getElementById(OIDC_MODAL_ID);
        if (m && m.parentNode) m.parentNode.removeChild(m);
    }

    function oidcModalStatus(msg) {
        var s = document.getElementById(OIDC_MODAL_ID + '_st');
        if (s) s.textContent = msg;
    }

    function showOidcModal(name, authUrl) {
        closeOidcModal();
        var safeName = String(name || 'your provider').replace(/[<>&"]/g, '');
        var ov = document.createElement('div');
        ov.id = OIDC_MODAL_ID;
        ov.style.cssText = 'position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,0.72);display:flex;align-items:center;justify-content:center;padding:24px;';
        ov.innerHTML = '<div style="background:#16181c;border:1px solid #2a2d33;border-radius:14px;max-width:420px;width:100%;padding:24px;box-sizing:border-box;color:#e6e6e6;font-family:system-ui,-apple-system,sans-serif;">'
            + '<h2 style="font-size:19px;margin:0 0 10px;">' + Tf('tfa.login.oidc_title', 'Sign in with {name}', { name: safeName }) + '</h2>'
            + '<p style="color:#aeb4bd;font-size:14px;line-height:1.5;margin:0 0 14px;">' + T('tfa.login.oidc_help', 'Your browser will open to finish sign-in. Approve there, then come back to this screen — it completes automatically.') + '</p>'
            + '<button id="' + OIDC_MODAL_ID + '_open" style="width:100%;padding:13px;border-radius:10px;border:0;background:#00a4dc;color:#fff;font-weight:600;font-size:15px;cursor:pointer;">' + T('tfa.login.oidc_open', 'Open sign-in in browser') + '</button>'
            + '<button id="' + OIDC_MODAL_ID + '_copy" style="width:100%;padding:12px;border-radius:10px;border:1px solid #2a2d33;background:#23262c;color:#e6e6e6;font-weight:600;font-size:14px;cursor:pointer;margin-top:10px;">' + T('tfa.login.oidc_copy', 'Copy sign-in link') + '</button>'
            + '<div id="' + OIDC_MODAL_ID + '_st" style="font-size:13px;color:#9aa0a8;margin-top:14px;min-height:18px;"></div>'
            + '<button id="' + OIDC_MODAL_ID + '_cancel" style="width:100%;padding:10px;border-radius:10px;border:0;background:transparent;color:#7d828b;font-size:13px;cursor:pointer;margin-top:6px;">' + T('tfa.login.cancel', 'Cancel') + '</button>'
            + '</div>';
        document.body.appendChild(ov);
        document.getElementById(OIDC_MODAL_ID + '_open').addEventListener('click', function () {
            oidcModalStatus(T('tfa.login.oidc_opening', 'Opening your browser…'));
            // [v2.5.12] (#64) if no native bridge handled it, window.open may have
            // loaded inside the WebView (Google blocks that) — point the user at
            // the copy-link path, which always opens a real browser.
            if (!openExternalUrl(authUrl)) {
                oidcModalStatus(T('tfa.login.oidc_use_copy', 'If your browser shows a security error, tap "Copy sign-in link" and open it in Chrome.'));
            }
        });
        document.getElementById(OIDC_MODAL_ID + '_copy').addEventListener('click', function () {
            function ok() { oidcModalStatus(T('tfa.login.oidc_copied', 'Link copied — paste it into Chrome, sign in, then return here.')); }
            try { navigator.clipboard.writeText(authUrl).then(ok, ok); } catch (e) { ok(); }
        });
        document.getElementById(OIDC_MODAL_ID + '_cancel').addEventListener('click', closeOidcModal);
    }

    function completeWithBridgeToken(user, token) {
        // [v2.5.9] (issue #64): authenticate exactly like the proven DESKTOP
        // OIDC bridge page — direct AuthenticateByName with a self-managed
        // device id, then store credentials and reload /web/. This matters for
        // 2FA BYPASS: the provider pre-verifies the *device id used at
        // AuthenticateByName* (TwoFactorAuthProvider → MarkDevicePreVerified),
        // and the resulting session carries that same device id, so the
        // SessionStarted handler skips the 2FA challenge. Filling + submitting
        // the login form instead went through a different device-id path and
        // lost the bypass (landed on the 2FA code screen).
        var did = (function () {
            try {
                var x = localStorage.getItem('_deviceId2');
                if (!x) {
                    x = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
                    localStorage.setItem('_deviceId2', x);
                }
                return x;
            } catch (e) { return 'bridge-' + Date.now(); }
        })();
        var auth = 'MediaBrowser Client="Jellyfin Web", Device="Browser", DeviceId="' + did + '", Version="10.11.0"';
        fetch(serverUrl('Users/AuthenticateByName'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Emby-Authorization': auth, 'Authorization': auth },
            body: JSON.stringify({ Username: user, Pw: token })
        })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(function (res) {
                var address = window.location.origin + jellyfinBasePath();
                try {
                    if (window.ApiClient && typeof window.ApiClient.serverAddress === 'function') {
                        address = window.ApiClient.serverAddress();
                    }
                } catch (e) { /* use origin + base path */ }
                var server = { Id: res.ServerId, Name: 'Jellyfin', AccessToken: res.AccessToken, UserId: res.User.Id, Type: 'Server', DateLastAccessed: Date.now(), LastConnectionMode: 1, ManualAddress: address, LocalAddress: address };
                localStorage.setItem('jellyfin_credentials', JSON.stringify({ Servers: [server] }));
                oidcModalStatus(Tf('tfa.login.oidc_signed_as', 'Signed in as {name} — opening Jellyfin…', { name: (res.User && res.User.Name ? res.User.Name : user) }));
                setTimeout(function () { closeOidcModal(); window.location.href = serverUrl('web/index.html'); }, 300);
            })
            .catch(function (e) {
                var msg = (e && e.message ? e.message : 'error');
                // [v2.5.16] (#64) The bridge token is single-use + short-lived. A
                // 401/403 here means it was already consumed, has expired, or a
                // reverse proxy (e.g. Cloudflare) blocked the call — retrying the
                // SAME token can never succeed, so don't tell the user to "retry".
                // Steer them to restart, which mints a fresh token via startInAppOidc.
                if (/HTTP 40[13]/.test(msg)) {
                    oidcModalStatus(T('tfa.login.oidc_expired', 'That sign-in code expired or was blocked. Close this and tap “Sign in with your provider” again to restart. If it keeps failing, a reverse proxy (e.g. Cloudflare) may be blocking the request.'));
                } else {
                    oidcModalStatus(Tf('tfa.login.oidc_failed', 'Sign-in failed: {msg}. Tap the button to retry.', { msg: msg }));
                }
            });
    }

    function pollDeviceFlow(pollToken) {
        window.__tfaOidcPolling = true;
        var tries = 0, MAX = 150;
        (function tick() {
            if (!window.__tfaOidcPolling) return;
            if (tries++ > MAX) { oidcModalStatus(T('tfa.login.oidc_timeout', 'Timed out — tap “Open sign-in in browser” to try again.')); return; }
            fetch(serverUrl('TwoFactorAuth/Oidc/DevicePoll?pt=' + encodeURIComponent(pollToken)), { headers: { 'Accept': 'application/json' } })
                .then(function (r) { return r.json(); })
                .then(function (j) {
                    if (j && j.ready) { window.__tfaOidcPolling = false; oidcModalStatus(T('tfa.login.oidc_signing', 'Signing you in…')); completeWithBridgeToken(j.username, j.token); }
                    else { setTimeout(tick, 2500); }
                })
                .catch(function () { setTimeout(tick, 2500); });
        })();
    }

    function startInAppOidc(id, name) {
        showOidcModal(name, '#');
        oidcModalStatus(T('tfa.login.oidc_starting', 'Starting…'));
        fetch(serverUrl('TwoFactorAuth/Oidc/LoginInfo/' + encodeURIComponent(id)), { headers: { 'Accept': 'application/json' } })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(function (info) {
                if (!info || !info.authUrl || !info.pollToken) throw new Error('bad response');
                showOidcModal(name, info.authUrl);
                oidcModalStatus(T('tfa.login.oidc_opening', 'Opening your browser…'));
                // [v2.5.12] (#64) if no native bridge opened a real browser, the
                // auto window.open likely loaded inside the WebView (Google
                // "disallowed_useragent") — guide the user to the copy-link path.
                if (!openExternalUrl(info.authUrl)) {
                    oidcModalStatus(T('tfa.login.oidc_use_copy', 'If your browser shows a security error, tap "Copy sign-in link" and open it in Chrome.'));
                }
                pollDeviceFlow(info.pollToken);
            })
            .catch(function () { oidcModalStatus(T('tfa.login.oidc_could_not_start', 'Could not start sign-in. Please try again.')); });
    }

    function injectOidcButtons() {
        if (!isLoginPage()) return;
        if (document.getElementById(OIDC_BUTTONS_ID)) return;
        var anchor = document.querySelector('.manualLoginForm button[type="submit"], .manualLoginForm .raised, form button[type="submit"]');
        if (!anchor) return;

        // Fetch providers (anonymous via the public list — but we don't have
        // an anon endpoint; fall back to graceful empty if request fails).
        // Use the admin Providers endpoint with no auth — it returns 401 if
        // not logged in, which we silently swallow. A better approach would
        // be a dedicated public listing endpoint; for v2.0 we make providers
        // visible only to authenticated browsers (so admins testing config
        // see them; first-time users still log in via password initially).
        // For unauthenticated render: show buttons we know of based on a
        // small fixed list, OR fetch from anonymous /Login endpoint when we
        // add one. For now: skip rendering if no enabled providers known.

        var container = document.createElement('div');
        container.id = OIDC_BUTTONS_ID;
        container.style.cssText = 'display:flex;flex-direction:column;gap:8px;margin-top:14px;';
        anchor.parentNode.insertBefore(container, anchor.nextSibling);

        // PublicProviders is the AllowAnonymous slice — id + display name only,
        // never secrets or discovery URLs. Safe to fetch with no auth from the
        // login page.
        fetch(serverUrl('TwoFactorAuth/Oidc/PublicProviders')).then(function(r) {
            if (!r.ok) return [];
            return r.json();
        }).then(function(rows) {
            (rows || []).filter(function(p) { return p.enabled; }).forEach(function(p) {
                var btn = document.createElement('a');
                btn.className = 'raised block emby-button';
                btn.style.cssText = 'display:flex;align-items:center;justify-content:center;gap:8px;padding:0.9em 1em;text-decoration:none;';
                btn.href = serverUrl('TwoFactorAuth/Oidc/Login/' + encodeURIComponent(p.id));
                // [v2.5.11] (#69, ZEROX7): honor the provider's custom button
                // text + icon. Label defaults to "Sign in with {name}". Icon is
                // an <img> when an https/data: URL is configured (server already
                // restricts the scheme), else the default login glyph.
                var _esc = function (s) { return String(s || '').replace(/[<>&"]/g, ''); };
                var _label = p.buttonText ? _esc(p.buttonText) : Tf('tfa.login.oidc_title', 'Sign in with {name}', { name: _esc(p.displayName || p.id) });
                var _iconUrl = p.buttonIconUrl || '';
                var _icon = (/^https:\/\//i.test(_iconUrl) || /^data:image\//i.test(_iconUrl))
                    ? '<img src="' + _iconUrl.replace(/"/g, '%22') + '" alt="" style="width:18px;height:18px;object-fit:contain;border-radius:3px;" />'
                    : '<span class="material-icons" style="font-family:Material Icons;font-size:18px;">login</span>';
                btn.innerHTML = _icon + '<span>' + _label + '</span>';
                // [v2.5.9] (issue #64): in an embedded app webview, a full-page
                // nav off /web/ bounces the app to server-select. Detect the
                // native shell and run the flow in-page (modal + device-poll)
                // instead. Regular browsers fall through to the normal redirect.
                (function (pid, pname) {
                    btn.addEventListener('click', function (e) {
                        if (inEmbeddedWebView()) { e.preventDefault(); startInAppOidc(pid, pname); }
                    });
                })(p.id, p.displayName || p.id);
                container.appendChild(btn);
            });
        }).catch(function() { /* silent */ });
    }

    function handleOidcCallback() {
        // [v2.5.11] Surface a failed OIDC sign-in on ANY screen the SPA lands on
        // (the login form OR the user-select grid), using the early-captured
        // _tfaOidcError so it survives the router stripping the hash query. The
        // toast (showLockoutToast) is fixed-position and works regardless of
        // which view rendered; when the login form is present we also drop an
        // inline banner above it for good measure.
        if (_tfaOidcError && !_tfaOidcErrorShown) {
            _tfaOidcErrorShown = true;
            showLockoutToast(T('tfa.login.signin_failed_prefix', 'Sign-in failed: ') + _tfaOidcError);
            try {
                var efForm = document.querySelector('.manualLoginForm') || document.querySelector('form');
                if (efForm && efForm.parentNode && !document.getElementById('__twofactor_oidc_error')) {
                    var box = document.createElement('div');
                    box.id = '__twofactor_oidc_error';
                    box.style.cssText = 'background:rgba(244,67,54,0.15);border:1px solid rgba(244,67,54,0.4);color:#f44336;padding:10px 14px;border-radius:4px;margin:0 0 14px;font-size:14px;';
                    box.textContent = T('tfa.login.signin_failed_prefix', 'Sign-in failed: ') + _tfaOidcError;
                    efForm.parentNode.insertBefore(box, efForm);
                }
            } catch (e) {}
            return;
        }
        if (!isLoginPage()) return;
        var user = getQueryParam('oidcUser');
        var token = getQueryParam('oidcToken');
        if (!user || !token) return;
        if (window[OIDC_AUTOSUBMIT_FLAG]) return;
        window[OIDC_AUTOSUBMIT_FLAG] = true;

        // Auto-fill the Jellyfin login form and submit. The TwoFactorAuthProvider
        // recognises the bridge-token prefix, validates it via OidcLoginTokenStore,
        // and authorises the session without ever calling the password backend.
        var nameInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
        var passInput = document.querySelector('input#txtManualPassword, input[name="password"], input#password');
        var submit = document.querySelector('.manualLoginForm button[type="submit"], .manualLoginForm .raised, form button[type="submit"]');
        if (!nameInput || !passInput || !submit) {
            // Form not ready yet — try again on next tick.
            window[OIDC_AUTOSUBMIT_FLAG] = false;
            setTimeout(handleOidcCallback, 250);
            return;
        }
        nameInput.value = user;
        nameInput.dispatchEvent(new Event('input', { bubbles: true }));
        passInput.value = token;
        passInput.dispatchEvent(new Event('input', { bubbles: true }));
        // Stripping the query params keeps the bridge token out of the
        // history/back button. Done before submit so a failed login leaves
        // the form clean rather than auto-resubmitting on reload.
        try { history.replaceState(null, '', '#!/login.html'); } catch (e) {}
        submit.click();
    }

    function tryInject() {
        addLoginButton();
        injectSidebar();
        injectDashboardNav();
        injectSettingsTile();
        injectOidcButtons();
        handleOidcCallback();
    }

    function start() {
        // [v2.5.16] (#100) Enforce force-password-onboarding before anything else,
        // so a flagged user who lands on /web (e.g. via Back) is bounced to the
        // set-password page instead of slipping past the forced step.
        enforceForcedPasswordSetup();
        ensureI18n();
        tryInject();

        var attempts = 0;
        var maxAttempts = 60;
        var poll = setInterval(function () {
            attempts++;
            tryInject();
            if (attempts >= maxAttempts || (document.getElementById(SIDEBAR_ID))) clearInterval(poll);
        }, 1000);

        var moPending = false;
        var mo = new MutationObserver(function () {
            if (moPending) return;
            moPending = true;
            setTimeout(function () { moPending = false; tryInject(); }, 250);
        });
        mo.observe(document.body, { childList: true, subtree: true });

        // Jellyfin changes <html lang> in place when the user switches their
        // interface language. The shared plugin bundle was resolved at initial
        // load, so watch this authoritative UI signal and refresh only the
        // injected dashboard label without requiring a hard reload.
        var langObserver = new MutationObserver(function () {
            syncDashboardNavLanguage();
        });
        langObserver.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['lang']
        });

        window.addEventListener('hashchange', tryInject);
        window.addEventListener('popstate', tryInject);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();

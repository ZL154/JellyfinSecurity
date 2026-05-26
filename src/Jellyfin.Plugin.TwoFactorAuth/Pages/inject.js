(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js v1.4.0 loaded');

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
    function isTfaPending() {
        try {
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
    function isAlwaysAllowedPath(url) {
        if (!url) return true;
        try {
            var pathname = new URL(String(url), window.location.origin).pathname.toLowerCase();
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
        var u = String(url).toLowerCase();
        return u.indexOf('/users/authenticatebyname') >= 0
            || u.indexOf('/users/authenticatewithquickconnect') >= 0
            || /\/users\/[0-9a-f-]+\/authenticate(\?|$)/i.test(u);
    }
    function handleTwoFactorBody(body) {
        if (!body || typeof body !== 'object') return false;
        if (!body.TwoFactorRequired && !body.twoFactorRequired) return false;
        // Hardcode the redirect path — never trust the server-supplied URL
        // (a malicious/compromised plugin or MITM could return an off-origin
        // ChallengePageUrl and steal the 2FA flow). The challenge token is
        // the only variable part.
        var token = body.ChallengeToken || body.challengeToken || '';
        var url = '/TwoFactorAuth/Challenge?token=' + encodeURIComponent(token);
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
    function injectDeviceId(headers) {
        if (!headers) return headers;
        var id = getStableDeviceId();
        if (!id) return headers;
        try {
            if (headers instanceof Headers) {
                // Overwrite any existing UA-hash deviceId with our stable one.
                var existing = headers.get('X-Emby-Authorization') || '';
                if (existing && /DeviceId=/i.test(existing)) {
                    existing = existing.replace(/DeviceId="[^"]*"/i, 'DeviceId="' + id + '"');
                    headers.set('X-Emby-Authorization', existing);
                }
                headers.set('X-Emby-Device-Id', id);
            } else if (typeof headers === 'object') {
                headers['X-Emby-Device-Id'] = id;
                if (headers['X-Emby-Authorization'] && /DeviceId=/i.test(headers['X-Emby-Authorization'])) {
                    headers['X-Emby-Authorization'] = headers['X-Emby-Authorization']
                        .replace(/DeviceId="[^"]*"/i, 'DeviceId="' + id + '"');
                }
            }
        } catch (e) {}
        return headers;
    }

    var origFetch = window.fetch ? window.fetch.bind(window) : null;
    if (origFetch) {
        window.fetch = function (input, init) {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';

            // v2.4.12: short-circuit when 2FA is pending. Always allow the
            // auth paths through (so the user can re-authenticate) and the
            // /TwoFactorAuth/* paths that complete the challenge.
            if (isTfaPending() && !isAlwaysAllowedPath(url) && !isAuthPath(url)) {
                return Promise.resolve(syntheticTfaBlockedResponse());
            }

            if (isAuthPath(url)) {
                init = init || {};
                init.headers = injectDeviceId(init.headers || new Headers());
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
        this.__tfa_authHeader = null;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
        // Capture existing X-Emby-Authorization so we can mutate the DeviceId
        // substring before it hits the wire (Jellyfin stock UI on LAN sets it
        // with a UA-hash deviceId; we overwrite with our stable one).
        if (typeof name === 'string' && name.toLowerCase() === 'x-emby-authorization') {
            this.__tfa_authHeader = value;
        }
        return origSetHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        if (isAuthPath(xhr.__tfa_url)) {
            try {
                var id = getStableDeviceId();
                if (id) {
                    origSetHeader.call(xhr, 'X-Emby-Device-Id', id);
                    if (xhr.__tfa_authHeader && /DeviceId=/i.test(xhr.__tfa_authHeader)) {
                        var patched = xhr.__tfa_authHeader.replace(/DeviceId="[^"]*"/i, 'DeviceId="' + id + '"');
                        origSetHeader.call(xhr, 'X-Emby-Authorization', patched);
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
            if (document.getElementById(DASHBOARD_NAV_ID)) return;
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
            if (document.getElementById(DASHBOARD_NAV_ID)) return;

            // Dashboard sidebar uses .adminDrawerLogo + nav links with
            // class .navMenuOption inside .mainDrawerScrollSlider OR
            // newer Jellyfin: .navDrawer-button rows. Try to find the
            // "Plugins" link as anchor.
            var anchor = null;
            var navLinks = document.querySelectorAll('a.navMenuOption, a.navDrawer-button, a[href*="/dashboard"]');
            for (var i = 0; i < navLinks.length; i++) {
                var t = (navLinks[i].textContent || '').trim().toLowerCase();
                if (t === 'plugins' || t.indexOf('plugins') === 0) { anchor = navLinks[i]; break; }
            }
            if (!anchor) return;

            var parent = anchor.parentElement;
            if (!parent) return;

            var a = document.createElement('a');
            a.id = DASHBOARD_NAV_ID;
            a.href = '#';
            a.className = anchor.className || 'navMenuOption emby-button';
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
            a.addEventListener('click', function (e) {
                e.preventDefault();
                // Plugin admin config page lives at the standard plugin
                // configuration URL — this drops into Jellyfin's normal
                // plugin-config view of our admin tabs.
                window.location.assign('/web/index.html#!/configurationpage?name=TwoFactorAuth');
            });
            a.innerHTML =
                '<span class="material-icons navMenuOptionIcon" style="font-family:Material Icons;" aria-hidden="true">security</span>' +
                '<span class="navMenuOptionText">Two-Factor Auth</span>';

            if (anchor.nextSibling) parent.insertBefore(a, anchor.nextSibling);
            else parent.appendChild(a);
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
            a.href = '/TwoFactorAuth/Setup';
            a.className = anchorItem.className || 'navMenuOption emby-button';
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
            a.innerHTML =
                '<span class="material-icons navMenuOptionIcon" style="font-family:Material Icons;" aria-hidden="true">security</span>' +
                '<span class="navMenuOptionText">Two-Factor Auth</span>';

            if (placement === 'after') {
                if (anchorItem.nextSibling) parent.insertBefore(a, anchorItem.nextSibling);
                else parent.appendChild(a);
            } else {
                parent.insertBefore(a, anchorItem);
            }

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
            var all = document.querySelectorAll('a, button');
            for (var i = 0; i < all.length; i++) {
                var txt = (all[i].textContent || '').trim().toLowerCase();
                if (txt === 'profile' || txt.indexOf('profile') === 0) {
                    profile = all[i];
                    break;
                }
            }
            if (!profile) return;

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
                window.location.assign('/TwoFactorAuth/Setup');
            });
            tile.className = 'listItem listItem-border listItem-button';
            tile.innerHTML =
                '<span class="material-icons listItemIcon listItemIcon-transparent" aria-hidden="true" style="font-family:\'Material Icons\';">security</span>' +
                '<div class="listItemBody">' +
                    '<div class="listItemBodyText">Two-Factor Authentication</div>' +
                '</div>' +
                '<span class="material-icons" aria-hidden="true" style="font-family:\'Material Icons\';margin-left:auto;opacity:0.5;">chevron_right</span>';

            if (template.nextSibling) container.insertBefore(tile, template.nextSibling);
            else container.appendChild(tile);
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
    function addLoginButton() {
        if (!isLoginPage()) return;
        if (document.getElementById(BUTTON_ID)) return;
        var signInBtn = document.querySelector('.manualLoginForm button[type="submit"], .manualLoginForm .raised, form button[type="submit"]');
        if (!signInBtn) return;
        addStyles();
        var btn = document.createElement('a');
        btn.id = BUTTON_ID;
        btn.setAttribute('is', 'emby-linkbutton');
        btn.className = (signInBtn.className || 'raised block').replace(/button-submit|button-cancel|emby-button/g, '').trim();
        btn.innerHTML = '<span class="tfa-icon">🔐</span>Sign in with Two-Factor Authentication';
        btn.href = '/TwoFactorAuth/Login';
        function updateHref() {
            var u = findUsername();
            btn.href = u ? '/TwoFactorAuth/Login?username=' + encodeURIComponent(u) : '/TwoFactorAuth/Login';
        }
        btn.addEventListener('click', function (e) { e.preventDefault(); updateHref(); window.location.assign(btn.href); });
        var userInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
        if (userInput) ['input', 'change', 'blur'].forEach(function (ev) { userInput.addEventListener(ev, updateHref); });
        var parent = signInBtn.parentNode;
        if (signInBtn.nextSibling) parent.insertBefore(btn, signInBtn.nextSibling);
        else parent.appendChild(btn);

        addPasskeyButton(signInBtn, btn);
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
        btn.innerHTML = '<span class="tfa-icon">🔑</span>Sign in with passkey';
        btn.style.cursor = 'pointer';
        btn.href = '#';
        btn.addEventListener('click', async function(e) {
            e.preventDefault();
            var u = findUsername();
            if (!u) { alert('Enter your username first, then click Sign in with passkey.'); return; }
            var orig = btn.innerHTML;
            btn.innerHTML = '<span class="tfa-icon">🔑</span>Waiting for authenticator…';
            try {
                var begin = await fetch('/TwoFactorAuth/Passkey/LoginBegin', {
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
                var complete = await fetch('/TwoFactorAuth/Passkey/LoginComplete', {
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
        fetch('/TwoFactorAuth/Oidc/PublicProviders').then(function(r) {
            if (!r.ok) return [];
            return r.json();
        }).then(function(rows) {
            (rows || []).filter(function(p) { return p.enabled; }).forEach(function(p) {
                var btn = document.createElement('a');
                btn.className = 'raised block emby-button';
                btn.style.cssText = 'display:flex;align-items:center;justify-content:center;gap:8px;padding:0.9em 1em;text-decoration:none;';
                btn.href = '/TwoFactorAuth/Oidc/Login/' + encodeURIComponent(p.id);
                btn.innerHTML = '<span class="material-icons" style="font-family:Material Icons;font-size:18px;">login</span><span>Sign in with ' + (p.displayName || p.id).replace(/[<>&"]/g, '') + '</span>';
                container.appendChild(btn);
            });
        }).catch(function() { /* silent */ });
    }

    function handleOidcCallback() {
        if (!isLoginPage()) return;
        var err = getQueryParam('oidcError');
        if (err) {
            // Show error banner once.
            var existing = document.getElementById('__twofactor_oidc_error');
            if (existing) return;
            var box = document.createElement('div');
            box.id = '__twofactor_oidc_error';
            box.style.cssText = 'background:rgba(244,67,54,0.15);border:1px solid rgba(244,67,54,0.4);color:#f44336;padding:10px 14px;border-radius:4px;margin-bottom:14px;font-size:14px;';
            box.textContent = 'Sign-in failed: ' + err;
            var form = document.querySelector('.manualLoginForm') || document.querySelector('form');
            if (form && form.parentNode) form.parentNode.insertBefore(box, form);
            return;
        }
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

        window.addEventListener('hashchange', tryInject);
        window.addEventListener('popstate', tryInject);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();

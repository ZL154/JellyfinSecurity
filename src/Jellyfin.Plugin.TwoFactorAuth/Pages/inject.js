(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js v1.3.0 loaded');

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
            if (isAuthPath(url)) {
                init = init || {};
                init.headers = injectDeviceId(init.headers || new Headers());
            }
            var p = origFetch(input, init);
            if (!isAuthPath(url)) return p;
            return p.then(function (resp) {
                if (resp.status !== 401) return resp;
                var clone = resp.clone();
                return clone.json().then(function (body) {
                    if (handleTwoFactorBody(body)) return new Promise(function () {});
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
                if (xhr.status !== 401) return;
                try { handleTwoFactorBody(JSON.parse(xhr.responseText || '{}')); } catch (e) {}
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
    }

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

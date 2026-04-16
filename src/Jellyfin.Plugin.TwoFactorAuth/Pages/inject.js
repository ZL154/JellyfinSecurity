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
        var url = body.ChallengePageUrl || body.challengePageUrl;
        if (!url) return false;
        console.log('[2FA] Server requested 2FA challenge — redirecting to', url);
        window.location.href = url;
        return true;
    }
    var origFetch = window.fetch ? window.fetch.bind(window) : null;
    if (origFetch) {
        window.fetch = function (input, init) {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
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
    XMLHttpRequest.prototype.open = function (method, url) {
        this.__tfa_url = url;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        if (isAuthPath(xhr.__tfa_url)) {
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
            if (hash.indexOf('mypreferencesmenu') < 0) return;
            if (document.getElementById(SETTINGS_TILE_ID)) return;

            // Find the preferences list — try several common containers
            var list = document.querySelector(
                '.preferencesContainer .readOnlyContent,' +
                ' .userPreferencesPage .readOnlyContent,' +
                ' .preferencesContainer,' +
                ' .userPreferencesPage'
            );
            // Fallback: find any list of user-pref links
            if (!list) {
                var prefLink = document.querySelector('a[href*="myprofile"], a[href*="userpasswordpage"]');
                if (prefLink) list = prefLink.parentElement;
            }
            if (!list) return;

            var template = list.querySelector('a.listItem, a.cardBox, a.button-link, a');
            if (!template) return;

            var tile = document.createElement('a');
            tile.id = SETTINGS_TILE_ID;
            tile.href = '/TwoFactorAuth/Setup';
            tile.className = template.className;

            // Mirror the template's inner structure if it uses the listItem layout
            var hadIconAndBody = template.querySelector('.listItemBody');
            if (hadIconAndBody) {
                tile.innerHTML =
                    '<span class="material-icons listItemIcon listItemIcon-transparent" aria-hidden="true">security</span>' +
                    '<div class="listItemBody">' +
                        '<div class="listItemBodyText">Two-Factor Authentication</div>' +
                        '<div class="listItemBodyText secondary">Manage TOTP, recovery codes, paired devices, and app passwords</div>' +
                    '</div>' +
                    '<span class="material-icons" aria-hidden="true" style="margin-left:auto;opacity:0.4;">chevron_right</span>';
            } else {
                tile.innerHTML =
                    '<span class="material-icons" style="margin-right:8px;vertical-align:middle;">security</span>' +
                    'Two-Factor Authentication';
            }

            list.appendChild(tile);
            console.log('[2FA] Settings tile inserted');
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

    function tryInject() {
        addLoginButton();
        injectSidebar();
        injectSettingsTile();
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

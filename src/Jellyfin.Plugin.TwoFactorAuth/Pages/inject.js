(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js loaded');

    var BUTTON_ID = '__twofactor_login_btn';
    var STYLE_ID = '__twofactor_styles';
    var MENU_ITEM_ID = '__twofactor_menu_item';

    // ============================================================
    // 1. Intercept fetch + XHR. If Jellyfin's auth endpoint returns
    //    401 with twoFactorRequired:true, redirect to the challenge
    //    page. Otherwise pass through. This catches the manual login
    //    form, the avatar/quick-login flow, and any other auth path.
    // ============================================================

    function isAuthPath(url) {
        if (!url) return false;
        var u = String(url).toLowerCase();
        return u.indexOf('/users/authenticatebyname') >= 0
            || u.indexOf('/users/authenticatewithquickconnect') >= 0
            || u.match(/\/users\/[0-9a-f-]+\/authenticate(\?|$)/i);
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

    // -- fetch() interception --
    var origFetch = window.fetch ? window.fetch.bind(window) : null;
    if (origFetch) {
        window.fetch = function (input, init) {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            var p = origFetch(input, init);
            if (!isAuthPath(url)) return p;
            return p.then(function (resp) {
                if (resp.status !== 401) return resp;
                // Clone so the caller can still consume the body
                var clone = resp.clone();
                return clone.json().then(function (body) {
                    if (handleTwoFactorBody(body)) {
                        // Return a never-resolving promise so the caller's
                        // .then doesn't fire and trigger an error popup.
                        // We're navigating away anyway.
                        return new Promise(function () {});
                    }
                    return resp;
                }).catch(function () { return resp; });
            });
        };
    }

    // -- XMLHttpRequest interception (Jellyfin's ApiClient uses XHR) --
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
                try {
                    var body = JSON.parse(xhr.responseText || '{}');
                    handleTwoFactorBody(body);
                    // Note: we can't stop the caller from seeing the 401,
                    // but the navigation kicks in immediately, replacing
                    // the page before any error UI renders.
                } catch (e) { /* not JSON */ }
            });
        }
        return origSend.apply(this, arguments);
    };

    // ============================================================
    // 2. Add a "Two-Factor Authentication" link to the user menu
    //    so signed-in users can find /TwoFactorAuth/Setup.
    // ============================================================

    // Find every "Settings"-style link Jellyfin renders and inject our 2FA
    // entry next to each one. Themed Jellyfin skins often relocate the
    // settings link, and there can be multiple drawers visible at once
    // (main left drawer + the per-user settings drawer on the right), so
    // we don't try to be clever about which one is "the" menu — we just
    // mirror every settings anchor we find.
    function addUserMenuLink() {
        // Match any anchor whose href targets the user preferences pages.
        // Covers vanilla Jellyfin, Jellyfin-Vue, and most themed skins.
        var anchors = document.querySelectorAll(
            'a[href*="mypreferencesmenu"],' +
            ' a[href*="myprofile"],' +
            ' a[href*="userprofile"],' +
            ' a[href*="useredit"],' +
            ' a[href*="quickconnect"]'
        );

        if (!anchors.length) return;

        var added = 0;
        anchors.forEach(function (anchor) {
            // Don't double-inject in the same container
            var siblingContainer = anchor.parentNode;
            if (!siblingContainer) return;
            if (siblingContainer.querySelector('[data-tfa-link="1"]')) return;

            var item = document.createElement('a');
            item.setAttribute('data-tfa-link', '1');
            item.id = MENU_ITEM_ID + '_' + (added++);
            item.className = anchor.className;
            item.href = '/TwoFactorAuth/Setup';

            // Mirror the anchor's inner structure so themes style it consistently
            var innerHtml = anchor.innerHTML;
            // Replace any text label with "Two-Factor Auth"
            // Try common label patterns: <span class="...text...">Label</span>,
            // or just trailing text after an icon.
            var labelReplaced = false;
            var withTextSpan = innerHtml.replace(
                /(<span[^>]*(?:text|label|name)[^>]*>)([^<]+)(<\/span>)/i,
                function (_, open, _label, close) { labelReplaced = true; return open + 'Two-Factor Auth' + close; }
            );
            if (labelReplaced) {
                // Also swap the icon if there is a material-icons span
                item.innerHTML = withTextSpan.replace(
                    /(<span[^>]*material-icons[^>]*>)([^<]*)(<\/span>)/i,
                    '$1security$3'
                );
            } else {
                item.innerHTML = '<span class="material-icons" aria-hidden="true" style="margin-right:0.5em;">security</span>Two-Factor Auth';
            }

            // Insert right after the anchor so it groups with Settings
            if (anchor.nextSibling) {
                siblingContainer.insertBefore(item, anchor.nextSibling);
            } else {
                siblingContainer.appendChild(item);
            }
        });

        if (added > 0) {
            console.log('[2FA] Injected', added, 'menu link(s)');
        }
    }

    // The Jellyfin settings page (#!/mypreferencesmenu.html) is a list of
    // big tile links. Drop a "Two-Factor Auth" tile into that list too.
    function addSettingsPageTile() {
        var hash = window.location.hash || '';
        if (hash.indexOf('mypreferencesmenu') < 0) return;

        var list = document.querySelector(
            '.preferencesContainer .readOnlyContent,' +
            ' .preferencesContainer,' +
            ' .userPreferencesPage .readOnlyContent,' +
            ' .userPreferencesPage'
        );
        if (!list) return;
        if (list.querySelector('[data-tfa-tile="1"]')) return;

        var tile = document.createElement('a');
        tile.setAttribute('data-tfa-tile', '1');
        tile.href = '/TwoFactorAuth/Setup';

        // Try to copy an existing tile's classes so it inherits theme styling
        var template = list.querySelector('a.listItem, a.cardBox, a.button-link, a');
        if (template) tile.className = template.className;

        tile.innerHTML =
            '<span class="material-icons listItemIcon listItemIcon-transparent" aria-hidden="true">security</span>' +
            '<div class="listItemBody">' +
                '<div class="listItemBodyText">Two-Factor Authentication</div>' +
                '<div class="listItemBodyText secondary">Manage your TOTP, recovery codes, and trusted devices</div>' +
            '</div>';

        list.appendChild(tile);
        console.log('[2FA] Added Settings page tile');
    }

    // ============================================================
    // 3. (Existing) Add "Sign in with Two-Factor" button under the
    //    standard login form. Kept as a backup affordance — the
    //    interception above handles the normal flow automatically.
    // ============================================================

    function addStyles() {
        if (document.getElementById(STYLE_ID)) return;
        var style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent =
            '#' + BUTTON_ID + ' {' +
                'display:block;box-sizing:border-box;' +
                'width:100%;padding:0.9em 1em;margin-top:0.5em;' +
                'background:transparent;color:inherit;' +
                'border:1px solid rgba(255,255,255,0.2);border-radius:0.2em;' +
                'font-family:inherit;font-size:inherit;font-weight:inherit;line-height:inherit;letter-spacing:inherit;' +
                'text-transform:inherit;text-decoration:none;text-align:center;' +
                'cursor:pointer;-webkit-appearance:none;appearance:none;' +
                'transition:background-color 0.15s ease;' +
            '}' +
            '#' + BUTTON_ID + ':hover { background:rgba(255,255,255,0.08); }' +
            '#' + BUTTON_ID + ' span.tfa-icon { margin-right:0.4em;vertical-align:middle; }';
        document.head.appendChild(style);
    }

    function isLoginPage() {
        var hash = window.location.hash || '';
        return hash.indexOf('login') >= 0 || hash === '' || hash === '#';
    }

    function findUsername() {
        var sel = 'input#txtManualName, input[name="username"], input#username, .manualLoginForm input[type="text"]:not([type="password"])';
        var input = document.querySelector(sel);
        if (input && input.value) return input.value.trim();
        return '';
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

        btn.addEventListener('click', function (e) {
            e.preventDefault();
            updateHref();
            window.location.assign(btn.href);
        });

        var userInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
        if (userInput) {
            userInput.addEventListener('input', updateHref);
            userInput.addEventListener('change', updateHref);
            userInput.addEventListener('blur', updateHref);
        }

        var parent = signInBtn.parentNode;
        if (signInBtn.nextSibling) {
            parent.insertBefore(btn, signInBtn.nextSibling);
        } else {
            parent.appendChild(btn);
        }

        console.log('[2FA] Added "Sign in with 2FA" button after', signInBtn);
    }

    // ============================================================
    // Bootstrap
    // ============================================================

    var mo = new MutationObserver(function () {
        try {
            addLoginButton();
            addUserMenuLink();
            addSettingsPageTile();
        } catch (e) {}
    });

    function start() {
        addLoginButton();
        addUserMenuLink();
        addSettingsPageTile();
        mo.observe(document.body, { childList: true, subtree: true });
        window.addEventListener('hashchange', function () {
            addLoginButton();
            addUserMenuLink();
            addSettingsPageTile();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();

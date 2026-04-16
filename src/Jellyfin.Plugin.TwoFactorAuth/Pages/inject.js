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

    function addUserMenuLink() {
        // Jellyfin's user drawer is in .userMenuOptions or similar
        var menu = document.querySelector('.userMenuOptions, .navMenuOption-list, .mainDrawer-scrollContainer');
        if (!menu) return;
        if (document.getElementById(MENU_ITEM_ID)) return;

        // Find the "Settings" or similar item to anchor near
        var anchor = menu.querySelector('a[href*="mypreferencesmenu"], a[href*="useredit"]');
        if (!anchor) return;

        var item = document.createElement('a');
        item.id = MENU_ITEM_ID;
        item.className = anchor.className;
        item.href = '/TwoFactorAuth/Setup';
        item.innerHTML = (anchor.innerHTML.indexOf('<span') >= 0)
            ? '<span class="material-icons" aria-hidden="true">security</span><span class="navMenuOption-text">Two-Factor Auth</span>'
            : '🔐 Two-Factor Auth';
        anchor.parentNode.insertBefore(item, anchor.nextSibling);
        console.log('[2FA] Added user menu link');
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
        } catch (e) {}
    });

    function start() {
        addLoginButton();
        addUserMenuLink();
        mo.observe(document.body, { childList: true, subtree: true });
        window.addEventListener('hashchange', function () {
            addLoginButton();
            addUserMenuLink();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();

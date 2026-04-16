(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js loaded');

    var BUTTON_ID = '__twofactor_login_btn';
    var STYLE_ID = '__twofactor_styles';

    function addStyles() {
        if (document.getElementById(STYLE_ID)) return;
        var style = document.createElement('style');
        style.id = STYLE_ID;
        // Match Jellyfin's emby-button "raised" style — same dimensions, padding, font
        style.textContent =
            '#' + BUTTON_ID + ' {' +
                'display:block;box-sizing:border-box;' +
                'width:100%;padding:0.9em 1em;margin-top:0.5em;' +
                'background:transparent;color:inherit;' +
                'border:1px solid rgba(255,255,255,0.2);border-radius:0.2em;' +
                'font-family:inherit;font-size:inherit;font-weight:inherit;line-height:inherit;letter-spacing:inherit;' +
                'text-transform:inherit;text-decoration:none;text-align:center;' +
                'cursor:pointer;' +
                '-webkit-appearance:none;appearance:none;' +
                'transition:background-color 0.15s ease;' +
            '}' +
            '#' + BUTTON_ID + ':hover {' +
                'background:rgba(255,255,255,0.08);' +
            '}' +
            '#' + BUTTON_ID + ' span.tfa-icon {' +
                'margin-right:0.4em;vertical-align:middle;' +
            '}';
        document.head.appendChild(style);
    }

    function isLoginPage() {
        var hash = window.location.hash || '';
        return hash.indexOf('login') >= 0 || hash === '' || hash === '#';
    }

    function findUsername() {
        // Common Jellyfin username input selectors across versions
        var sel = 'input#txtManualName, input[name="username"], input#username, .manualLoginForm input[type="text"]:not([type="password"])';
        var input = document.querySelector(sel);
        if (input && input.value) return input.value.trim();
        return '';
    }

    function addLoginButton() {
        if (!isLoginPage()) return;
        if (document.getElementById(BUTTON_ID)) return;

        // Look for Jellyfin's Sign In button — it's usually a .raised or button[type=submit]
        var signInBtn = document.querySelector('.manualLoginForm button[type="submit"], .manualLoginForm .raised, form button[type="submit"]');
        if (!signInBtn) return;

        addStyles();

        var btn = document.createElement('a');
        btn.id = BUTTON_ID;
        btn.setAttribute('is', 'emby-linkbutton');
        btn.className = signInBtn.className || 'raised block';
        // Remove bg color classes Jellyfin uses (button-submit, etc) so our neutral style applies
        btn.className = btn.className.replace(/button-submit|button-cancel|emby-button/g, '').trim();
        btn.innerHTML = '<span class="tfa-icon">🔐</span>Sign in with Two-Factor Authentication';
        btn.href = '/TwoFactorAuth/Login';

        function updateHref() {
            var u = findUsername();
            btn.href = u ? '/TwoFactorAuth/Login?username=' + encodeURIComponent(u) : '/TwoFactorAuth/Login';
        }

        // Click handler: always fetch the current username right before navigation
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            updateHref();
            window.location.assign(btn.href);
        });

        // Also update as user types
        var userInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
        if (userInput) {
            userInput.addEventListener('input', updateHref);
            userInput.addEventListener('change', updateHref);
            userInput.addEventListener('blur', updateHref);
        }

        // Insert immediately after the Sign In button
        var parent = signInBtn.parentNode;
        if (signInBtn.nextSibling) {
            parent.insertBefore(btn, signInBtn.nextSibling);
        } else {
            parent.appendChild(btn);
        }

        console.log('[2FA] Added "Sign in with 2FA" button after', signInBtn);
    }

    var mo = new MutationObserver(function () {
        try { addLoginButton(); } catch (e) {}
    });

    function start() {
        addLoginButton();
        mo.observe(document.body, { childList: true, subtree: true });
        window.addEventListener('hashchange', addLoginButton);
        window.addEventListener('popstate', addLoginButton);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();

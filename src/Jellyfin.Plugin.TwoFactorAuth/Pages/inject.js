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
        style.textContent =
            '#' + BUTTON_ID + ' {' +
                'display:flex;align-items:center;justify-content:center;gap:8px;' +
                'width:100%;padding:14px;margin-top:14px;' +
                'background:linear-gradient(135deg,#00a4dc 0%,#0087b3 100%);' +
                'color:#fff;border:none;border-radius:6px;' +
                'font-size:15px;font-weight:600;cursor:pointer;' +
                'text-decoration:none;' +
                'box-shadow:0 4px 12px rgba(0,164,220,0.3);' +
                'transition:transform 0.15s ease, box-shadow 0.15s ease;' +
            '}' +
            '#' + BUTTON_ID + ':hover {' +
                'transform:translateY(-1px);' +
                'box-shadow:0 6px 16px rgba(0,164,220,0.4);' +
            '}';
        document.head.appendChild(style);
    }

    function isLoginPage() {
        var hash = window.location.hash || '';
        var path = window.location.pathname || '';
        return hash.indexOf('login') >= 0 || path.indexOf('login') >= 0;
    }

    function addLoginButton() {
        if (!isLoginPage()) return;
        if (document.getElementById(BUTTON_ID)) return;

        // Find the form or login container
        var form = document.querySelector('form.loginForm, form[name="loginForm"], form');
        var insertAfter = null;
        if (form) {
            // Insert after the submit button if we can find it
            var submit = form.querySelector('button[type="submit"], .raised.button-submit, .raised.emby-button');
            insertAfter = submit ? submit.parentNode : form;
        }
        if (!insertAfter) return;

        addStyles();

        var btn = document.createElement('a');
        btn.id = BUTTON_ID;
        btn.href = '/TwoFactorAuth/Login';
        // Try to pre-fill username
        var userInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
        if (userInput && userInput.value && userInput.value.trim()) {
            btn.href = '/TwoFactorAuth/Login?username=' + encodeURIComponent(userInput.value.trim());
        }
        btn.innerHTML = '🔐 Sign in with Two-Factor Authentication';

        // Update href as user types username
        if (userInput) {
            userInput.addEventListener('input', function () {
                var u = userInput.value && userInput.value.trim();
                btn.href = u
                    ? '/TwoFactorAuth/Login?username=' + encodeURIComponent(u)
                    : '/TwoFactorAuth/Login';
            });
        }

        if (insertAfter.nextSibling) {
            insertAfter.parentNode.insertBefore(btn, insertAfter.nextSibling);
        } else {
            insertAfter.parentNode.appendChild(btn);
        }
        console.log('[2FA] Added "Sign in with 2FA" button to login page');
    }

    // Watch for the login page being shown (Jellyfin is a SPA, routes change)
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

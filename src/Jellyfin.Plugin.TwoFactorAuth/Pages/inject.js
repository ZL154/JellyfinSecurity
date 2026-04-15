(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js loaded');

    var AUTH_PATH = '/Users/AuthenticateByName';

    function getUrl(input) {
        if (typeof input === 'string') return input;
        if (input && input.url) return input.url;
        return '';
    }

    function redirectToLogin(username) {
        var target = '/TwoFactorAuth/Login';
        if (username) target += '?username=' + encodeURIComponent(username);
        console.log('[2FA] Redirecting to', target);
        window.location.assign(target);
    }

    function checkAndRedirect(username, continueCallback) {
        if (!username) return continueCallback();
        fetch('/TwoFactorAuth/UserStatus?username=' + encodeURIComponent(username))
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (status) {
                if (status && status.totpEnabled === true) {
                    redirectToLogin(username);
                } else {
                    continueCallback();
                }
            })
            .catch(continueCallback);
    }

    // --- Strategy 1: fetch interceptor ---
    var originalFetch = window.fetch;
    if (originalFetch) {
        window.fetch = function (input, init) {
            var url = getUrl(input);
            if (!url || url.indexOf(AUTH_PATH) < 0) {
                return originalFetch.apply(this, arguments);
            }

            var username = '';
            try {
                var body = init && init.body;
                if (typeof body === 'string') {
                    var parsed = JSON.parse(body);
                    username = parsed.Username || parsed.username || '';
                }
            } catch (e) {}

            console.log('[2FA] fetch intercepted for auth, username=', username);

            if (!username) {
                return originalFetch.apply(this, arguments);
            }

            var self = this;
            var self_args = arguments;

            return fetch('/TwoFactorAuth/UserStatus?username=' + encodeURIComponent(username))
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (status) {
                    if (status && status.totpEnabled === true) {
                        redirectToLogin(username);
                        return new Promise(function () {});
                    }
                    return originalFetch.apply(self, self_args);
                })
                .catch(function () {
                    return originalFetch.apply(self, self_args);
                });
        };
        console.log('[2FA] fetch interceptor installed');
    }

    // --- Strategy 2: XHR interceptor (Jellyfin ApiClient uses XHR historically) ---
    var OrigXHR = window.XMLHttpRequest;
    if (OrigXHR) {
        var origOpen = OrigXHR.prototype.open;
        var origSend = OrigXHR.prototype.send;
        OrigXHR.prototype.open = function (method, url) {
            this.__2fa_url = url;
            this.__2fa_method = method;
            return origOpen.apply(this, arguments);
        };
        OrigXHR.prototype.send = function (body) {
            var xhr = this;
            if (xhr.__2fa_url && xhr.__2fa_url.indexOf(AUTH_PATH) >= 0) {
                console.log('[2FA] XHR intercepted for auth');
                try {
                    var parsed = typeof body === 'string' ? JSON.parse(body) : null;
                    var username = parsed && (parsed.Username || parsed.username);
                    if (username) {
                        // Block the request, ask the server about 2FA status, redirect if needed
                        var args = arguments;
                        fetch('/TwoFactorAuth/UserStatus?username=' + encodeURIComponent(username))
                            .then(function (r) { return r.ok ? r.json() : null; })
                            .then(function (status) {
                                if (status && status.totpEnabled === true) {
                                    redirectToLogin(username);
                                } else {
                                    origSend.apply(xhr, args);
                                }
                            })
                            .catch(function () { origSend.apply(xhr, args); });
                        return;
                    }
                } catch (e) {}
            }
            return origSend.apply(this, arguments);
        };
        console.log('[2FA] XHR interceptor installed');
    }

    // --- Strategy 3: listen for form submit on login page as final fallback ---
    function attachFormListener() {
        var forms = document.querySelectorAll('form');
        forms.forEach(function (form) {
            if (form.__2fa_listener) return;
            form.__2fa_listener = true;
            form.addEventListener('submit', function (e) {
                var userInput = form.querySelector('input[name="username"], input#username, input[type="text"]');
                var username = userInput && userInput.value && userInput.value.trim();
                if (!username) return;
                console.log('[2FA] form submit intercepted, username=', username);
                // Don't prevent — let Jellyfin's normal flow try; our fetch/XHR interceptors will catch it
            }, true);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachFormListener);
    } else {
        attachFormListener();
    }

    var mo = new MutationObserver(attachFormListener);
    mo.observe(document.documentElement, { childList: true, subtree: true });
})();

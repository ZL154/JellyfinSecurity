(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    var AUTH_PATH = '/Users/AuthenticateByName';

    function getUrl(input) {
        if (typeof input === 'string') return input;
        if (input && input.url) return input.url;
        return '';
    }

    function isAuthRequest(input) {
        var url = getUrl(input);
        return url && url.indexOf(AUTH_PATH) >= 0;
    }

    function extractUsername(input, init) {
        try {
            var body = init && init.body;
            if (typeof body === 'string') {
                var parsed = JSON.parse(body);
                return parsed.Username || parsed.username || '';
            }
        } catch (e) {}
        return '';
    }

    function redirectToLogin(username) {
        var target = '/TwoFactorAuth/Login';
        if (username) target += '?username=' + encodeURIComponent(username);
        window.location.assign(target);
    }

    // Intercept fetch calls to the auth endpoint. Before letting the POST go through,
    // check if the user has 2FA enabled. If they do, redirect to our login page instead.
    var originalFetch = window.fetch;
    if (originalFetch) {
        window.fetch = function (input, init) {
            if (!isAuthRequest(input)) {
                return originalFetch.apply(this, arguments);
            }

            var username = extractUsername(input, init);
            if (!username) {
                return originalFetch.apply(this, arguments);
            }

            var self = this;
            var self_args = arguments;

            return originalFetch.call(this, '/TwoFactorAuth/UserStatus?username=' + encodeURIComponent(username))
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (status) {
                    if (status && status.totpEnabled === true) {
                        redirectToLogin(username);
                        return new Promise(function () {}); // hang — we're navigating
                    }
                    return originalFetch.apply(self, self_args);
                })
                .catch(function () {
                    return originalFetch.apply(self, self_args);
                });
        };
    }
})();

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

    function redirectToChallenge(challengeToken) {
        var target = '/TwoFactorAuth/Challenge?token=' + encodeURIComponent(challengeToken);
        try {
            var returnUrl = window.location.pathname + window.location.hash;
            target += '&return=' + encodeURIComponent(returnUrl);
        } catch (e) {}
        window.location.assign(target);
    }

    var originalFetch = window.fetch;
    if (originalFetch) {
        window.fetch = function (input, init) {
            var isAuth = isAuthRequest(input);
            var promise = originalFetch.apply(this, arguments);
            if (!isAuth) return promise;

            return promise.then(function (response) {
                if (response && response.status === 401) {
                    var cloned;
                    try { cloned = response.clone(); } catch (e) { return response; }
                    return cloned.json().then(function (data) {
                        if (data && (data.TwoFactorRequired === true || data.twoFactorRequired === true)) {
                            redirectToChallenge(data.ChallengeToken || data.challengeToken);
                            return new Promise(function () {}); // hang — page will navigate away
                        }
                        return response;
                    }).catch(function () { return response; });
                }
                return response;
            });
        };
    }

    var OrigXHR = window.XMLHttpRequest;
    if (OrigXHR) {
        var origOpen = OrigXHR.prototype.open;
        var origSend = OrigXHR.prototype.send;
        OrigXHR.prototype.open = function (method, url) {
            this.__2fa_url = url;
            return origOpen.apply(this, arguments);
        };
        OrigXHR.prototype.send = function () {
            var xhr = this;
            if (xhr.__2fa_url && xhr.__2fa_url.indexOf(AUTH_PATH) >= 0) {
                xhr.addEventListener('load', function () {
                    if (xhr.status === 401) {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            if (data && (data.TwoFactorRequired === true || data.twoFactorRequired === true)) {
                                redirectToChallenge(data.ChallengeToken || data.challengeToken);
                            }
                        } catch (e) {}
                    }
                });
            }
            return origSend.apply(this, arguments);
        };
    }
})();

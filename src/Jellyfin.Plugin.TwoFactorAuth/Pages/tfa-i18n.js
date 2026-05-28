// v2.5.0 shared i18n helper. Served at /TwoFactorAuth/tfa-i18n.js.
//
// Public API on window.tfaI18n:
//   - tr(key, fallback)                 — translate a key, falling back to literal English
//   - loadTranslations()                — async; resolves the effective language and fetches the bundle
//   - applyTranslations(root)           — walks [data-i18n-key] / [data-i18n-placeholder] descendants
//   - renderLanguagePicker(host, opts)  — appends a <select> styled for the host page
//   - getEffectiveLanguage()            — returns the resolved language code (after loadTranslations)
//
// Resolution order (most specific wins): per-user preference (if signed in) → URL ?lang=
//   → localStorage["tfa.lang"] → /public-config defaultLanguage → "en".

(function () {
    var SUPPORTED = ['en', 'de', 'es', 'fr', 'it', 'ja', 'pt', 'zh'];
    var LANG_LABELS = {
        en: 'English', de: 'Deutsch', es: 'Español', fr: 'Français',
        it: 'Italiano', ja: '日本語', pt: 'Português', zh: '中文'
    };
    var STORAGE_KEY = 'tfa.lang';

    var _bundle = null;
    var _lang = 'en';
    var _loaded = false;

    function hasApiClient() {
        return typeof window.ApiClient !== 'undefined' && window.ApiClient &&
            typeof window.ApiClient.getUrl === 'function';
    }

    function buildUrl(path) {
        if (hasApiClient()) return window.ApiClient.getUrl(path);
        // For plain pages, controller routes are mounted at /TwoFactorAuth/...
        return '/' + path.replace(/^\/+/, '');
    }

    function sanitizeLang(lang) {
        var s = String(lang || '').toLowerCase().replace(/[^a-z-]/g, '');
        return s && SUPPORTED.indexOf(s) >= 0 ? s : '';
    }

    function readQueryLang() {
        try {
            var m = window.location.search.match(/[?&]lang=([^&]+)/);
            return m ? sanitizeLang(decodeURIComponent(m[1])) : '';
        } catch (e) { return ''; }
    }

    function readStorageLang() {
        try { return sanitizeLang(window.localStorage.getItem(STORAGE_KEY)); }
        catch (e) { return ''; }
    }

    function writeStorageLang(lang) {
        try { window.localStorage.setItem(STORAGE_KEY, lang); }
        catch (e) { /* private mode etc. — ignore */ }
    }

    function getCurrentUserId() {
        if (hasApiClient() && typeof window.ApiClient.getCurrentUserId === 'function') {
            try { return window.ApiClient.getCurrentUserId(); } catch (e) { return null; }
        }
        return null;
    }

    function fetchJson(url) {
        return fetch(url, { credentials: 'include' }).then(function (r) {
            return r.ok ? r.json() : null;
        }).catch(function () { return null; });
    }

    function resolveLanguage() {
        // Resolution order per the helper docstring: URL ?lang= (most
        // explicit "right now I want X") → per-user pref → localStorage →
        // /public-config admin default → "en". URL beats the saved pref so
        // QA/share-links can preview another language without nuking the
        // user's stored choice.
        var urlLang = readQueryLang();
        if (urlLang) return Promise.resolve(urlLang);

        var uid = getCurrentUserId();
        var prefP = uid
            ? fetchJson(buildUrl('TwoFactorAuth/users/' + uid + '/preferences'))
            : Promise.resolve(null);
        var pubP = fetchJson(buildUrl('TwoFactorAuth/public-config'));
        return Promise.all([prefP, pubP]).then(function (parts) {
            var pref = parts[0], pub = parts[1];
            var pubDefault = sanitizeLang(pub && pub.defaultLanguage) || 'en';
            if (pref && pref.language) {
                var prefLang = sanitizeLang(pref.language);
                if (prefLang) return prefLang;
            }
            return readStorageLang() || pubDefault;
        });
    }

    function tr(key, fallback) {
        if (_bundle && Object.prototype.hasOwnProperty.call(_bundle, key)) {
            return _bundle[key];
        }
        return fallback != null ? fallback : key;
    }

    function applyTranslations(root) {
        var scope = root || document;
        var nodes = scope.querySelectorAll('[data-i18n-key]');
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            var key = el.getAttribute('data-i18n-key');
            var v = tr(key, null);
            if (v != null) el.textContent = v;
        }
        var phs = scope.querySelectorAll('[data-i18n-placeholder]');
        for (var j = 0; j < phs.length; j++) {
            var pel = phs[j];
            var pkey = pel.getAttribute('data-i18n-placeholder');
            var pv = tr(pkey, null);
            if (pv != null) pel.setAttribute('placeholder', pv);
        }
        // Update <html lang> for assistive tech.
        try { document.documentElement.setAttribute('lang', _lang); } catch (e) { /* ignore */ }
    }

    function loadTranslations() {
        return resolveLanguage().then(function (lang) {
            _lang = lang || 'en';
            return fetch(buildUrl('TwoFactorAuth/translations/' + encodeURIComponent(_lang)), {
                credentials: 'include'
            }).then(function (r) { return r.ok ? r.json() : null; });
        }).then(function (bundle) {
            _bundle = bundle || {};
            _loaded = true;
            applyTranslations();
            return _lang;
        }).catch(function () {
            _bundle = {};
            _loaded = true;
            return _lang;
        });
    }

    function persistLanguage(lang) {
        writeStorageLang(lang);
        var uid = getCurrentUserId();
        if (!uid) return Promise.resolve();
        return fetch(buildUrl('TwoFactorAuth/users/' + uid + '/preferences'), {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ language: lang })
        }).then(function () { /* fire-and-forget */ }).catch(function () { /* ignore */ });
    }

    function renderLanguagePicker(host, opts) {
        if (!host) return null;
        opts = opts || {};
        var select = document.createElement('select');
        select.className = opts.className || 'tfa-lang-picker';
        select.setAttribute('aria-label', 'Language');
        for (var i = 0; i < SUPPORTED.length; i++) {
            var code = SUPPORTED[i];
            var opt = document.createElement('option');
            opt.value = code;
            opt.textContent = LANG_LABELS[code] || code;
            if (code === _lang) opt.selected = true;
            select.appendChild(opt);
        }
        select.addEventListener('change', function () {
            var lang = sanitizeLang(select.value) || 'en';
            persistLanguage(lang).then(function () {
                _lang = lang;
                return fetch(buildUrl('TwoFactorAuth/translations/' + encodeURIComponent(_lang)), {
                    credentials: 'include'
                }).then(function (r) { return r.ok ? r.json() : null; });
            }).then(function (bundle) {
                _bundle = bundle || {};
                applyTranslations();
                if (typeof opts.onChange === 'function') opts.onChange(_lang);
            });
        });
        host.appendChild(select);
        return select;
    }

    function getEffectiveLanguage() { return _lang; }

    window.tfaI18n = {
        tr: tr,
        loadTranslations: loadTranslations,
        applyTranslations: applyTranslations,
        renderLanguagePicker: renderLanguagePicker,
        getEffectiveLanguage: getEffectiveLanguage,
        SUPPORTED: SUPPORTED.slice(),
        LANG_LABELS: LANG_LABELS
    };

    // Auto-load when the document is ready.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { loadTranslations(); });
    } else {
        loadTranslations();
    }
})();

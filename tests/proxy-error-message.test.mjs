// Run with Node.js 18+: node --test tests/proxy-error-message.test.mjs
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {test} from 'node:test';
import {createContext, runInContext} from 'node:vm';

const pages = new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/', import.meta.url);
const read = name => readFileSync(new URL(name, pages), 'utf8');
const i18nSource = read('tfa-i18n.js');
const english = JSON.parse(read('translations/en.json'));
const portuguese = JSON.parse(read('translations/pt.json'));

// What the browser hands the page. The bodies and content types are the ones
// measured on Jellyfin 12.2 directly and behind nginx with ModSecurity (#320).
// `reads` counts body reads across clones, so a test can prove the helper
// never consumes the body.
function response(status, contentType, body) {
    const reads = {count: 0};
    const make = () => ({
        ok: status >= 200 && status < 300,
        status,
        reads,
        headers: {get: name => (name.toLowerCase() === 'content-type' ? contentType : null)},
        json: async () => { reads.count++; return JSON.parse(body); },
        text: async () => { reads.count++; return body; },
        clone: make,
    });
    return make();
}
const proxyPage = status => response(status, 'text/html', '<!doctype html><html><body><h1>Sorry, this request was blocked.</h1></body></html>');
const stepUp403 = () => response(403, 'application/json; charset=utf-8',
    JSON.stringify({message: 'A current authenticator or recovery code is required to modify two-factor settings.', stepUpRequired: true, twoFactorRequired: true}));

// Loads tfa-i18n.js the way a page does; ?lang= picks the bundle it fetches.
async function loadI18n(context, lang) {
    const bundles = {en: english, pt: portuguese};
    Object.assign(context, {
        document: {readyState: 'complete', documentElement: {getAttribute: () => '', setAttribute() {}}, querySelectorAll: () => []},
        localStorage: {getItem: () => null, setItem() {}, removeItem() {}},
        console: {log() {}, warn() {}, error() {}},
    });
    context.window = context;
    context.location = {pathname: '/TwoFactorAuth/Setup', search: lang ? '?lang=' + lang : ''};
    context.navigator = {language: 'en-US'};
    const pageFetch = context.fetch;
    context.fetch = async (url, options) => {
        const match = String(url).match(/TwoFactorAuth\/translations\/(\w+)$/);
        if (match) return response(200, 'application/json', JSON.stringify(bundles[match[1]] || {}));
        if (/TwoFactorAuth\/public-config$/.test(String(url))) return response(200, 'application/json', '{}');
        return pageFetch(url, options);
    };
    runInContext(i18nSource, context);
    await context.tfaI18n.ready;
    return context.tfaI18n;
}

test('a 4xx HTML page from a proxy is named as such, with its status', async () => {
    const i18n = await loadI18n(createContext({fetch: async () => { throw new Error('unexpected request'); }}));
    for (const status of [401, 403, 404]) {
        const page = proxyPage(status);
        const text = i18n.proxyErrorMessage(page);
        assert.match(text, new RegExp('\\b' + status + '\\b'));
        assert.match(text, /proxy/i);
        assert.match(text, /\/TwoFactorAuth\//);
        assert.equal(page.reads.count, 0, 'the helper must leave the body to the caller');
    }
    assert.notEqual(i18n.proxyErrorMessage(response(403, 'Text/HTML; charset=UTF-8', '<html></html>')), '');
    assert.notEqual(i18n.proxyErrorMessage(response(403, 'application/xhtml+xml; charset=utf-8', '<html></html>')), '');
});

test('answers from Jellyfin or the plugin keep their own handling', async () => {
    const i18n = await loadI18n(createContext({fetch: async () => { throw new Error('unexpected request'); }}));
    // The plugin's JSON errors, Jellyfin's empty 401 and 404, Jellyfin's own
    // plain text errors ("Error processing request."), and the HTML 503 page
    // Jellyfin itself serves while it starts.
    for (const r of [stepUp403(), response(401, null, ''), response(404, null, ''),
        response(400, 'application/json; charset=utf-8', '{"title":"One or more validation errors occurred."}'),
        response(401, 'text/plain', 'Error processing request.'),
        response(503, 'text/html', '<!DOCTYPE html><html></html>'),
        response(302, 'text/html', '<html></html>'),
        response(200, 'text/html', '<!DOCTYPE html><html></html>')]) {
        assert.equal(i18n.proxyErrorMessage(r), '', 'status ' + r.status);
    }
});

test('the message follows the page language', async () => {
    const i18n = await loadI18n(createContext({fetch: async () => { throw new Error('unexpected request'); }}), 'pt');
    const text = i18n.proxyErrorMessage(proxyPage(403));
    assert.equal(text, portuguese['tfa.error.proxy_replaced'].replace('{status}', '403'));
    assert.notEqual(text, english['tfa.error.proxy_replaced'].replace('{status}', '403'));
});

test('every translation carries the status and the path to check', () => {
    const dir = new URL('translations/', pages);
    const files = readdirSync(dir).filter(name => name.endsWith('.json'));
    assert.equal(files.length, 8);
    for (const name of files) {
        const text = JSON.parse(readFileSync(new URL(name, dir), 'utf8'))['tfa.error.proxy_replaced'];
        assert.equal(typeof text, 'string', name);
        assert.match(text, /\{status\}/, name);
        assert.match(text, /\/TwoFactorAuth\//, name);
    }
});

// The Setup page's own transport, run as written in setup.html: the passkey
// registration in #320 goes through api() and mutateWithStepUp().
function setupTransport(source) {
    const slice = (start, end) => {
        const from = source.indexOf(start);
        const to = source.indexOf(end, from);
        assert(from >= 0 && to > from, 'setup.html section ' + start);
        return source.slice(from, to);
    };
    return slice('function tfaBasePath()', 'function escapeHtml(') + slice('async function mutateWithStepUp(', '// DELETE-style');
}

async function setupPage(answers) {
    const requests = [];
    const prompts = [];
    const context = createContext({
        fetch: async (url, options) => {
            requests.push({url, body: options && options.body});
            return answers.shift()();
        },
    });
    await loadI18n(context);
    context.tfaPromptForCode = async opts => { prompts.push(opts); return {code: '123456'}; };
    runInContext(setupTransport(read('setup.html')) + '\nthis.mutateWithStepUp = mutateWithStepUp;', context);
    return {context, requests, prompts};
}

test('Setup: a proxy page in place of the step-up answer says so instead of HTTP 403', async () => {
    const {context, requests, prompts} = await setupPage([() => proxyPage(403)]);
    await assert.rejects(
        context.mutateWithStepUp('POST', 'TwoFactorAuth/Passkeys/RegisterBegin', {}, {}),
        error => {
            assert.equal(error.status, 403);
            assert.equal(error.message, english['tfa.error.proxy_replaced'].replace('{status}', '403'));
            return true;
        });
    assert.equal(prompts.length, 0);
    assert.equal(requests.length, 1);
});

test('Setup: the plugin\'s own step-up answer still opens the code prompt', async () => {
    const {context, requests, prompts} = await setupPage([stepUp403, () => response(200, 'application/json', '{"nonce":"n","options":{}}')]);
    const begin = await context.mutateWithStepUp('POST', 'TwoFactorAuth/Passkeys/RegisterBegin', {}, {});
    assert.equal(begin.nonce, 'n');
    assert.equal(prompts.length, 1);
    assert.equal(JSON.parse(requests[1].body).code, '123456');
});

test('Setup: a plugin error without a proxy keeps the server message', async () => {
    const {context} = await setupPage([() => response(403, 'application/json; charset=utf-8', '{"message":"Account is locked out."}')]);
    await assert.rejects(context.mutateWithStepUp('POST', 'TwoFactorAuth/Passkeys/RegisterBegin', {}, {}), /Account is locked out\./);
});

// The admin page's step-up modal and its fetch helpers, run as written in
// admin-script.js: from getHeaders() to the end of stepUpFetch().
function adminHelpers(source) {
    const from = source.indexOf('function getHeaders() {');
    const to = source.indexOf("page.querySelectorAll('.tfa-tab').forEach", from);
    assert(from >= 0 && to > from, 'admin-script.js helper section');
    const importFrom = source.indexOf("document.getElementById('btnImportConfig')");
    const importTo = source.indexOf('// ---- v2.0 SSO PROVIDERS ----', importFrom);
    assert(importFrom >= 0 && importTo > importFrom, 'admin-script.js import handler');
    return source.slice(from, to) + source.slice(importFrom, importTo);
}

async function adminPage(answers) {
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) {
            const classes = new Set();
            elements.set(id, {
                id, textContent: '', value: '', disabled: false, style: {}, handlers: {},
                classList: {add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c)},
                addEventListener(type, fn) { this.handlers[type] = fn; },
                focus() {},
            });
        }
        return elements.get(id);
    };
    const requests = [];
    const context = createContext({
        fetch: async (url, options) => {
            requests.push(String(url));
            const key = Object.keys(answers).find(k => String(url).includes(k));
            assert(key, 'unexpected request ' + url);
            return answers[key]();
        },
    });
    await loadI18n(context);
    Object.assign(context, {
        atob, btoa, setTimeout,
        isSecureContext: true,
        PublicKeyCredential: function () {},
        pluginId: 'test',
        page: {},
        ApiClient: {serverAddress: () => 'https://jf.test', accessToken: () => 'token', getUrl: path => 'https://jf.test/' + path, getPluginConfiguration: async () => ({})},
        alert() {},
        _tr: (key, fallback) => context.tfaI18n.tr(key, fallback),
    });
    context.navigator.credentials = {
        get: async () => ({
            id: 'cred', rawId: new Uint8Array([1]).buffer, type: 'public-key',
            response: {clientDataJSON: new Uint8Array([2]).buffer, authenticatorData: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer, userHandle: null},
        }),
    };
    context.document.getElementById = element;
    context.document.addEventListener = () => {};
    runInContext(adminHelpers(read('admin-script.js'))
        + '\nthis.failureMessage = failureMessage; this.stepUpFetch = stepUpFetch; this.closeStepUpModal = closeStepUpModal;', context);
    return {context, element, requests};
}
const settle = () => new Promise(resolve => setTimeout(resolve, 20));
const proxyText = status => english['tfa.error.proxy_replaced'].replace('{status}', String(status));

test('Admin: a WAF block on the passkey step-up names the proxy', async () => {
    const {element} = await adminPage({
        'StepUp/UserPasskeyBegin': () => response(200, 'application/json', '{"nonce":"n","options":{"challenge":"AAAA","allowCredentials":[]}}'),
        'StepUp/UserPasskeyVerify': () => proxyPage(403),
    });
    await element('tfa-stepup-passkey').handlers.click();
    await settle();
    assert.equal(element('tfa-stepup-error').textContent, proxyText(403));
});

test('Admin: a proxy page in place of the step-up email answer names the proxy', async () => {
    const {element} = await adminPage({'StepUp/UserEmailSend': () => proxyPage(403)});
    element('tfa-stepup-email').handlers.click();
    await settle();
    assert.equal(element('tfa-stepup-error').textContent, proxyText(403));
});

test('Admin: failure reasons keep the server message first, then the proxy, then the status', async () => {
    const {context} = await adminPage({});
    assert.equal(await context.failureMessage(response(403, 'application/json', '{"message":"Locked out."}')), 'Locked out.');
    assert.equal(await context.failureMessage(proxyPage(404)), proxyText(404));
    assert.equal(await context.failureMessage(response(500, 'text/plain', 'Error processing request.')), 'HTTP 500');
});

test('Admin: the plugin\'s own step-up answer still opens the code prompt', async () => {
    const {context, element} = await adminPage({
        'Admin/HardeningConfig': stepUp403,
        'TwoFactorAuth/MyStatus': () => response(200, 'application/json', '{"passkeyCount":0}'),
    });
    const pending = context.stepUpFetch('TwoFactorAuth/Admin/HardeningConfig', {method: 'POST'});
    await settle();
    assert(element('tfa-stepup-overlay').classList.contains('active'), 'the code prompt opens');
    context.closeStepUpModal();
    assert.equal((await pending).status, 403);
});

// The 2FA challenge page's passkey button, run as written in challenge.html.
function challengePasskey(source) {
    const slice = (start, end) => {
        const from = source.indexOf(start);
        const to = source.indexOf(end, from);
        assert(from >= 0 && to > from, 'challenge.html section ' + start);
        return source.slice(from, to);
    };
    return slice('function proxyError(r) {', 'var params = new URLSearchParams')
        + slice("document.getElementById('btnPasskey').addEventListener('click'", '// [v2.5.21] (#137/#98)');
}

async function challengePage(beginAnswer) {
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) elements.set(id, {id, textContent: '', disabled: false, handlers: {}, addEventListener(type, fn) { this.handlers[type] = fn; }});
        return elements.get(id);
    };
    const shown = [];
    const context = createContext({fetch: async url => { assert.match(String(url), /Verify\/Passkey\/Begin$/); return beginAnswer(); }});
    await loadI18n(context);
    context.tfaUrl = path => '/' + path;
    context.document.getElementById = element;
    Object.assign(context, {
        challengeToken: 'challenge', returnUrl: '/web/',
        _tr: (key, fallback) => context.tfaI18n.tr(key, fallback),
        clearError() {}, showError: message => shown.push(message),
    });
    runInContext(challengePasskey(read('challenge.html')), context);
    await element('btnPasskey').handlers.click();
    return shown;
}

test('Challenge: the passkey step shows the plugin\'s reason or names the proxy', async () => {
    assert.deepEqual(await challengePage(() => response(403, 'application/json; charset=utf-8', '{"message":"This IP address is temporarily blocked."}')),
        [english['tfa.challenge.passkey_error_prefix'] + 'This IP address is temporarily blocked.']);
    assert.deepEqual(await challengePage(() => proxyPage(403)), [english['tfa.challenge.passkey_error_prefix'] + proxyText(403)]);
});

test('Admin: a proxy page in place of the import answer names the proxy', async () => {
    const {element} = await adminPage({'Config/Import': () => proxyPage(403)});
    element('importEnvelope').value = '{"envelope":true}';
    await element('btnImportConfig').handlers.click();
    assert.match(element('importResult').innerHTML, /A reverse proxy or firewall replaced the answer from the server \(HTTP 403\)/);
});

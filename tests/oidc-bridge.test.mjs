// Run with Node.js 18+: node --test tests/oidc-bridge.test.mjs
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const source = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Api/SecurityController.cs', import.meta.url), 'utf8');
const responseHandler = source.match(/OidcAuthResponseHandler = """([\s\S]*?)""";/)?.[1] ?? '';

// Execute the emitted fetch/then/catch chains, including their real error handlers.
// These sections contain C# string literals plus the shared raw-string constant.
function bridgeScript(startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    assert(start >= 0 && end > start, 'OIDC bridge script boundaries must exist');
    return source.slice(start, end).split('\n')
        .filter(line => line.trimStart().startsWith('+'))
        .map(line => {
            const fragment = line.trim().slice(1).trim();
            return fragment === 'OidcAuthResponseHandler' ? responseHandler : JSON.parse(fragment);
        }).join('\n');
}

const bridges = {
    callback: bridgeScript('+ "fetch(authPath,', '+ "})();"'),
    webview: bridgeScript('+ "fetch(su(\'Users/AuthenticateByName\'),', '\n            + "}"'),
};

async function authenticate(script, body, basePath) {
    const elements = new Map();
    const element = () => ({textContent: '', style: {}, children: [], appendChild(child) { this.children.push(child); }});
    const storage = new Map();
    let requests = 0;
    const context = {
        u: 'test-user', t: 'test-bridge-token', auth: 'test-authorization',
        bp: basePath, authPath: basePath + '/Users/AuthenticateByName',
        land: basePath + '/web/index.html', loginPath: basePath + '/TwoFactorAuth/Login',
        forcePw: false, rpLogoutId: null,
        su: p => basePath + '/' + p,
        window: {location: {origin: 'https://example.test', href: 'https://example.test/callback'}},
        localStorage: {
            getItem: key => storage.get(key) ?? null,
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key),
        },
        sessionStorage: {setItem() {}, removeItem() {}},
        document: {
            getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
            querySelector: () => null,
            createElement: element,
        },
        console: {error() {}},
        st: message => context.document.getElementById('st').textContent = message,
        fetch: async (url, options) => {
            requests++;
            assert.equal(url, basePath + '/Users/AuthenticateByName');
            assert.equal(options.method, 'POST');
            assert.deepEqual(JSON.parse(options.body), {Username: 'test-user', Pw: 'test-bridge-token'});
            return {ok: false, status: 401, json: async () => body};
        },
    };
    await runInNewContext(script, context);
    assert.equal(requests, 1);
    assert.equal(storage.has('jellyfin_credentials'), false, '401 must not store session credentials');
    const messages = [...elements.values()].flatMap(e => [e.textContent, ...e.children.map(c => c.textContent)]).join('\n');
    return {href: context.window.location.href, messages};
}

for (const [name, script] of Object.entries(bridges)) {
    for (const basePath of ['', '/jellyfin']) {
        test(`${name} ${basePath || '/'}: 401 with TwoFactorRequired redirects to TOTP`, async () => {
            const result = await authenticate(script, {
                TwoFactorRequired: true, ChallengeToken: 'test&challenge',
                ChallengePageUrl: 'https://untrusted.example/collect',
            }, basePath);
            const redirect = new URL(result.href, 'https://example.test');
            assert.equal(redirect.origin, 'https://example.test');
            assert.equal(redirect.pathname, basePath + '/TwoFactorAuth/Challenge');
            assert.equal(redirect.searchParams.get('token'), 'test&challenge');
            assert.equal(redirect.searchParams.get('return'), basePath + '/web/index.html');
            assert.doesNotMatch(result.messages, /HTTP 401/);
        });

        test(`${name} ${basePath || '/'}: ordinary 401 remains a sign-in failure`, async () => {
            const result = await authenticate(script, {Message: 'Invalid credentials'}, basePath);
            assert.equal(result.href, 'https://example.test/callback');
            assert.match(result.messages, /(?:Error: |Sign-in failed: )HTTP 401/);
        });
    }
}

// [#64] The in-app dialog (inject.js) spends the same bridge token from the
// app's webview. Run its completeWithBridgeToken against a stubbed fetch and
// read what the dialog tells the person signing in.
const inject = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/inject.js', import.meta.url), 'utf8');
const dialogStart = inject.indexOf('function completeWithBridgeToken(');
const dialogEnd = inject.indexOf('\n    function pollDeviceFlow(', dialogStart);
assert(dialogStart >= 0 && dialogEnd > dialogStart, 'completeWithBridgeToken boundaries must exist');
const dialogSource = inject.slice(dialogStart, dialogEnd);

async function completeInApp(response) {
    const statuses = [];
    const storage = new Map();
    const context = {
        TFA_CONNECTION_MODE_MANUAL: 2,
        serverUrl: path => '/jf/' + path,
        jellyfinBasePath: () => '/jf',
        T: (key, fallback) => fallback,
        Tf: (key, fallback, vars) => fallback.replace(/\{(\w+)\}/g, (_, name) => vars[name]),
        oidcModalStatus: message => statuses.push(message),
        clearTfaPending() {},
        closeOidcModal() {},
        setTimeout() {},
        localStorage: {getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value)},
        crypto: {getRandomValues: bytes => bytes},
        window: {location: {origin: 'https://example.test', href: 'https://example.test/web/'}},
        fetch: async (url, options) => {
            assert.equal(url, '/jf/Users/AuthenticateByName');
            assert.equal(options.method, 'POST');
            assert.deepEqual(JSON.parse(options.body), {Username: 'test-user', Pw: 'test-bridge-token'});
            return response;
        },
    };
    runInNewContext(dialogSource + '\ncompleteWithBridgeToken("test-user", "test-bridge-token");', context);
    for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
    return {status: statuses.at(-1), stored: storage.has('jellyfin_credentials')};
}

const refused = (status, text) => ({ok: false, status, text: async () => text});

test('in-app dialog: a 403 that carries the plugin\'s reason shows that reason', async () => {
    const result = await completeInApp(refused(403, JSON.stringify({message: 'This IP address is temporarily blocked.'})));
    assert.equal(result.status, 'This IP address is temporarily blocked.');
    assert.equal(result.stored, false);
});

test('in-app dialog: Jellyfin\'s own 403 is a refused account, not an expired code', async () => {
    const result = await completeInApp(refused(403, 'Error processing request.'));
    assert.match(result.status, /^Jellyfin refused this account here\./);
    assert.match(result.status, /remote connections/);
    assert.doesNotMatch(result.status, /expired/);
    assert.equal(result.stored, false);
});

test('in-app dialog: a reverse proxy\'s HTML 403 gets the same explanation', async () => {
    const result = await completeInApp(refused(403, '<html><body><h1>403 Forbidden</h1></body></html>'));
    assert.match(result.status, /^Jellyfin refused this account here\./);
    assert.match(result.status, /reverse proxy/);
});

test('in-app dialog: a 401 is still an expired or spent code', async () => {
    const result = await completeInApp(refused(401, 'Error processing request.'));
    assert.match(result.status, /^That sign-in code expired or was blocked\./);
    assert.equal(result.stored, false);
});

test('in-app dialog: any other failure keeps the generic message', async () => {
    const result = await completeInApp(refused(500, 'Error processing request.'));
    assert.equal(result.status, 'Sign-in failed: HTTP 500. Tap the button to retry.');
});

test('in-app dialog: a sign-in that works still stores the session', async () => {
    const result = await completeInApp({
        ok: true,
        status: 200,
        json: async () => ({AccessToken: 'test-access-token', ServerId: 'test-server', User: {Id: 'test-id', Name: 'test-user'}}),
    });
    assert.match(result.status, /^Signed in as test-user/);
    assert.equal(result.stored, true);
});

test('in-app dialog: the English translation is the text the dialog falls back to', () => {
    const english = JSON.parse(readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/translations/en.json', import.meta.url), 'utf8'));
    const fallback = dialogSource.match(/T\('tfa\.login\.oidc_refused', '([^']+)'\)/)?.[1];
    assert.ok(fallback, 'the dialog must name tfa.login.oidc_refused with an English fallback');
    assert.equal(english['tfa.login.oidc_refused'], fallback);
});

// [#297] With a provider set to auto-redirect, the login page sends a browser
// straight to that provider's sign-in. Run the decision exactly as inject.js
// defines it.
const autoRule = inject.match(/\n( *)function oidcAutoRedirectTarget\(s\) \{[\s\S]*?\n\1\}/);
assert(autoRule, 'inject.js must define oidcAutoRedirectTarget(s)');
const oidcAutoRedirectTarget = runInNewContext(`(${autoRule[0].trim()})`);

const NOW = 1_800_000_000_000;
const browserOnLoginPage = {
    providers: [{id: 'authentik', enabled: true, autoRedirect: true}],
    embeddedApp: false,
    oidcError: false,
    returningFromProvider: false,
    optedOut: false,
    signedOut: false,
    lastAutoRedirectAt: 0,
    now: NOW,
};
const autoTarget = changes => oidcAutoRedirectTarget({...browserOnLoginPage, ...changes});

test('auto-redirect: a browser goes to the provider that asks for it', () => {
    assert.equal(autoTarget({}), 'authentik');
});

test('auto-redirect: nothing happens while no provider asks for it', () => {
    assert.equal(autoTarget({providers: [{id: 'authentik', enabled: true, autoRedirect: false}]}), null);
    assert.equal(autoTarget({providers: []}), null);
});

test('auto-redirect: the first provider in the list that asks for it wins', () => {
    assert.equal(autoTarget({providers: [
        {id: 'google', enabled: true, autoRedirect: false},
        {id: 'authentik', enabled: true, autoRedirect: true},
        {id: 'keycloak', enabled: true, autoRedirect: true},
    ]}), 'authentik');
});

test('auto-redirect: a disabled provider is never a target', () => {
    assert.equal(autoTarget({providers: [{id: 'authentik', enabled: false, autoRedirect: true}]}), null);
});

test('auto-redirect: the Jellyfin apps keep the button', () => {
    assert.equal(autoTarget({embeddedApp: true}), null);
});

test('auto-redirect: a failed sign-in stays on the page with its message', () => {
    assert.equal(autoTarget({oidcError: true}), null);
});

test('auto-redirect: the return from the provider signs in instead of leaving again', () => {
    assert.equal(autoTarget({returningFromProvider: true}), null);
});

test('auto-redirect: oidcAuto=0 keeps the password form reachable', () => {
    assert.equal(autoTarget({optedOut: true}), null);
});

test('auto-redirect: signing out does not send the browser straight back in', () => {
    assert.equal(autoTarget({signedOut: true}), null);
});

test('auto-redirect: a round trip that ended back here is not repeated for two minutes', () => {
    assert.equal(autoTarget({lastAutoRedirectAt: NOW - 60_000}), null);
    assert.equal(autoTarget({lastAutoRedirectAt: NOW - 119_000}), null);
    assert.equal(autoTarget({lastAutoRedirectAt: NOW - 121_000}), 'authentik');
});

test('auto-redirect: the admin listing returns the option, so the form shows what was saved', () => {
    const listing = source.match(/public ActionResult<IReadOnlyList<object>> ListProviders\(\)[\s\S]*?\.ToList<object>\(\);/)?.[0] ?? '';
    assert.ok(listing, 'ListProviders must project its rows');
    assert.match(listing, /autoRedirect = p\.AutoRedirect,/);
});

test('auto-redirect: creating and editing a provider both keep the option', () => {
    const request = source.match(/public sealed class OidcProviderUpsertRequest[\s\S]*?\n    \}/)?.[0]
        ?? source.match(/class OidcProviderUpsertRequest[\s\S]*?\n    \}/)?.[0] ?? '';
    assert.ok(request, 'the upsert request class must exist');
    assert.match(request, /public bool AutoRedirect \{ get; set; \}/);
    assert.match(source, /\n\s+AutoRedirect = req\.AutoRedirect,/, 'CreateProvider must copy AutoRedirect');
    assert.match(source, /existing\.AutoRedirect = req\.AutoRedirect;/, 'UpdateProvider must copy AutoRedirect');
});

// [#298] A trusted reverse proxy that names the user in a header signs the
// browser in from the login page, through the same bridge token as OIDC.
const proxyRule = inject.match(/\n( *)function proxySignInAction\(s\) \{[\s\S]*?\n\1\}/);
assert(proxyRule, 'inject.js must define proxySignInAction(s)');
const proxySignInAction = runInNewContext(`(${proxyRule[0].trim()})`);

const proxyNamesUser = {
    available: true,
    signedOut: false,
    optedOut: false,
    failedInTab: false,
    oidcError: false,
    returningFromProvider: false,
    lastAutoAt: 0,
    now: 1_000_000,
};
const proxyAction = changes => proxySignInAction({...proxyNamesUser, ...changes});

test('proxy sign-in: a page the proxy names a user for signs in by itself', () => {
    assert.equal(proxyAction({}), 'auto');
});

test('proxy sign-in: nothing is offered when the proxy names nobody', () => {
    assert.equal(proxyAction({available: false}), null);
    assert.equal(proxyAction({available: false, signedOut: true}), null);
});

test('proxy sign-in: after a sign-out it waits for a click instead of signing straight back in', () => {
    assert.equal(proxyAction({signedOut: true}), 'button');
});

test('proxy sign-in: oidcAuto=0 keeps the password form in front, one click from the proxy sign-in', () => {
    assert.equal(proxyAction({optedOut: true}), 'button');
});

test('proxy sign-in: a refusal is not retried by itself in the same tab', () => {
    assert.equal(proxyAction({failedInTab: true}), 'button');
});

test('proxy sign-in: a page that comes back to the login right after signing in by itself waits for a click', () => {
    assert.equal(proxyAction({lastAutoAt: 1_000_000 - 60_000}), 'button');
    assert.equal(proxyAction({lastAutoAt: 1_000_000 - 121_000}), 'auto');
});

test('proxy sign-in: an OIDC error or answer on the page takes precedence', () => {
    assert.equal(proxyAction({oidcError: true}), null);
    assert.equal(proxyAction({returningFromProvider: true}), null);
});

test('auto-redirect: a proxy that names the user keeps the page here instead of leaving for a provider', () => {
    assert.equal(autoTarget({proxySignIn: true}), null);
});

test('proxy sign-in: trust is decided on the raw peer the first middleware records', () => {
    const filter = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Services/TwoFactorStartupFilter.cs', import.meta.url), 'utf8');
    const record = filter.indexOf('HeaderSignIn.RememberRawPeer');
    assert.ok(record >= 0, 'the startup filter must record the raw peer');
    assert.ok(record < filter.indexOf('UseMiddleware<IndexHtmlInjectionMiddleware>'), 'before any other middleware runs');

    const endpoint = source.match(/\[HttpPost\("HeaderSignIn"\)\][\s\S]*?\n    \}\n/)?.[0] ?? '';
    assert.ok(endpoint, 'SecurityController must define the HeaderSignIn endpoint');
    assert.match(endpoint, /var rawPeer = HeaderSignIn\.RawPeer\(HttpContext\);\s+if \(!HeaderSignIn\.FromTrustedProxy\(rawPeer, cfg\.HeaderSignInProxyCidrs\)\)/);
    assert.match(endpoint, /if \(HeaderSignIn\.FromAnotherSite\(Request\.Headers\["Sec-Fetch-Site"\]\)\)/, 'only the login page itself may ask');
});

test('proxy sign-in: an imported configuration keeps only valid, narrow proxy addresses', () => {
    const exporter = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Services/ConfigExportService.cs', import.meta.url), 'utf8');
    assert.match(exporter, /c\.HeaderSignInProxyCidrs = SanitizeCidrArray\(c\.HeaderSignInProxyCidrs, "HeaderSignInProxyCidrs"\);/);
});

// Without `engine` the page has no constructable stylesheets. With it, the page
// has them, and like a real engine it parses :has() only when engine.has is set.
function stockLoginPage(bootstrap, mounted = true, route = {}, engine = null) {
    const classes = new Set();
    const styles = [];
    const listeners = new Map();
    const storage = new Map();
    const requests = new Map();
    const links = new Map();
    const username = {style: {}, closest: () => null, focus() { this.focused = true; }};
    let form = {
        querySelector: selector => selector.includes('txtManualName') ? username : null,
        appendChild: link => links.set(link.id, link),
    };
    const location = new URL('https://jellyfin.test/mount/web/index.html#/login');
    if (route.serverId) location.hash += '?serverid=' + route.serverId;
    if (route.servers) storage.set('jellyfin_credentials', JSON.stringify({Servers: route.servers}));
    const window = {location, __tfaPasswordLoginDisabled: bootstrap};
    const context = {
        window, URL, URLSearchParams, setTimeout, clearTimeout, XMLHttpRequest: class {}, console: {log() {}, warn() {}},
        localStorage: {getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value)},
        document: {
            currentScript: {src: 'https://jellyfin.test/mount/TwoFactorAuth/inject?v=1'},
            readyState: 'loading',
            documentElement: {classList: {
                toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
                remove(name) { classes.delete(name); },
            }},
            addEventListener: (event, handler) => listeners.set(event, handler),
            getElementById: id => links.get(id),
            querySelectorAll: () => [],
            adoptedStyleSheets: [],
            createElement: tag => ({
                get href() { return this.address?.href; },
                set href(value) { this.address = new URL(value, location); },
                style: {}, addEventListener(event, handler) { this[event] = handler; },
                remove() { links.delete(this.id); },
            }),
            head: {appendChild: style => { styles.push(style); links.set(style.id, style); }},
            querySelector: selector => mounted && selector === '.manualLoginForm' ? form : null,
        },
        fetch: url => new Promise(resolve => requests.set(new URL(url, location).href, disabled => {
            resolve({ok: true, json: async () => ({passwordLoginDisabled: disabled})});
        })),
    };
    if (engine) {
        window.CSS = {supports: query => engine.has || !query.includes(':has(')};
        context.CSSStyleSheet = class {
            cssRules = [];
            insertRule(rule) {
                if (!engine.has && rule.includes(':has(')) throw new SyntaxError('Unsupported selector');
                this.cssRules.push(rule);
                return 0;
            }
        };
    }
    const boot = inject.replace("    if (document.readyState === 'loading') {",
        '    window.refresh = fetchTfaPublicConfig; window.gate = applyPasswordLoginGate;\n$&');
    runInNewContext(boot, context);
    return {window, document: context.document, classes, styles, listeners, storage, requests, links, username,
        mount() { form = {...form}; mounted = true; },
    };
}

test('the stock form is gated before it mounts and the admin reveal survives another gate pass', () => {
    const page = stockLoginPage(true, false);
    assert.ok(page.classes.has('tfa-pw-gated'));
    page.mount();
    page.window.gate();
    page.links.get('__tfa_pw_reveal').click({preventDefault() {}});
    assert.equal(page.classes.has('tfa-pw-gated'), false);
    assert.equal(page.username.focused, true);
    page.mount();
    page.window.gate();
    assert.equal(page.classes.has('tfa-pw-gated'), false);
    assert.equal(page.links.has('__tfa_pw_reveal'), false);
});

// Only :has() lets a stylesheet pick each credential wrapper by what it holds.
// The stock form opens with a heading div, so a positional rule misses the
// password wrapper. Without :has() the element fallback must do the hiding.
test('an engine with :has() gates the stock form through one adopted stylesheet', () => {
    const page = stockLoginPage(true, true, {}, {has: true});
    assert.ok(page.classes.has('tfa-pw-gated'));
    assert.equal(page.document.adoptedStyleSheets.length, 1);
});

test('an engine with constructable stylesheets but no :has() gets no positional gate rule', () => {
    const page = stockLoginPage(true, true, {}, {has: false});
    assert.ok(page.classes.has('tfa-pw-gated'));
    assert.deepEqual(page.document.adoptedStyleSheets, []);
});

test('an unbootstrapped script waits for the selected server policy', async () => {
    const page = stockLoginPage(undefined);
    assert.equal(page.classes.has('tfa-pw-gated'), false);
    const ready = page.window.refresh();
    page.requests.get('https://jellyfin.test/mount/TwoFactorAuth/public-config')(true);
    await ready;
    page.window.gate();
    assert.ok(page.classes.has('tfa-pw-gated'));
});

for (const base of ['https://other.test/mount', 'https://jellyfin.test/other']) {
    test('a selected server supplies its own policy at ' + base, async () => {
        const page = stockLoginPage(true);
        const first = page.window.refresh();
        page.window.ApiClient = {getUrl: path => base + '/' + path};
        page.window.gate();
        assert.ok(page.classes.has('tfa-pw-gated'), 'keep the credentials hidden while the selected server answers');
        const second = page.window.refresh();
        page.requests.get(base + '/TwoFactorAuth/public-config')(false);
        await second;
        page.requests.get('https://jellyfin.test/mount/TwoFactorAuth/public-config')(true);
        await first;
        page.window.gate();
        assert.equal(page.classes.has('tfa-pw-gated'), false, 'late previous response must not restore the old gate');
        assert.equal(page.links.has('__tfa_pw_reveal'), false);
    });
}

test('a remember-me change is stored before either OIDC flow can leave the form', () => {
    const page = stockLoginPage(false);
    for (const checked of [false, true]) {
        page.listeners.get('change')({target: {
            checked, matches: selector => selector === '.manualLoginForm .chkRememberLogin',
        }});
        assert.equal(page.storage.get('enableAutoLogin'), String(checked));
    }
    page.listeners.get('change')({target: {checked: false, matches: () => false}});
    assert.equal(page.storage.get('enableAutoLogin'), 'true');
});

test('a login route naming another saved server uses its address before the global client switches', async () => {
    const other = 'https://jellyfin.test/second';
    const page = stockLoginPage(true, true, {serverId: 'second', servers: [
        {Id: 'SECOND', LastConnectionMode: 1, RemoteAddress: other, ManualAddress: 'https://unused.test'},
    ]});
    assert.ok(page.classes.has('tfa-pw-gated'), 'pending before the stock form mounts');
    page.window.ApiClient = {serverId: () => 'first', getUrl: path => 'https://jellyfin.test/mount/' + path};
    page.window.gate();
    const request = page.requests.get(other + '/TwoFactorAuth/public-config');
    assert.ok(request);
    request(true);
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(page.classes.has('tfa-pw-gated'), 'apply the selected policy when it arrives even if polling has stopped');
    assert.ok(page.links.has('__tfa_pw_reveal'));
});

test('an unknown named server never inherits the shell policy', () => {
    const page = stockLoginPage(true, true, {serverId: 'unknown', servers: []});
    page.window.gate();
    assert.equal(page.classes.has('tfa-pw-gated'), false);
    assert.equal(page.links.has('__tfa_pw_reveal'), false);
});

// These functions run inside Chromium. The script under test is a blocking
// external resource and the form follows it in parser order, as in Jellyfin.
function prepareGateBrowser(mode) {
    window.postResult = window.fetch.bind(window);
    window.errors = [];
    window.addEventListener('error', event => window.errors.push(event.message));
    localStorage.setItem('jellyfin_credentials', JSON.stringify({Servers: [
        {Id: 'B', ManualAddress: location.origin + '/b', LastConnectionMode: 2},
    ]}));
    if (mode.startsWith('foreign-entry-')) {
        const active = mode === 'foreign-entry-active' ? 'b' : 'a';
        window.ApiClient = {serverId: () => active, getUrl: path => location.origin + '/' + active + '/' + path};
    }
    if (mode === 'legacy') {
        window.URLSearchParams = undefined;
        window.URL = function () { throw new Error('URL unavailable'); };
        Array.prototype.find = undefined;
    }
    if (mode === 'legacy' || mode.startsWith('older-selector')) {
        const supports = CSS.supports.bind(CSS);
        CSS.supports = (...args) => args[0].includes(':has(') ? false : supports(...args);
        const insert = CSSStyleSheet.prototype.insertRule;
        CSSStyleSheet.prototype.insertRule = function (rule, ...args) {
            if (rule.includes(':has(')) throw new SyntaxError('Unsupported selector');
            return insert.call(this, rule, ...args);
        };
    }
    if (mode.startsWith('element-fallback')) window.CSSStyleSheet = undefined;
    window.fetch = async url => {
        if (String(url).includes('/b/TwoFactorAuth/public-config')) {
            return new Promise(resolve => { window.answerB = value => resolve(new Response(
                JSON.stringify({passwordLoginDisabled: value}), {status: value === 'error' ? 503 : 200})); });
        }
        const body = String(url).includes('public-config') ? {passwordLoginDisabled: true} : [];
        return new Response(JSON.stringify(body));
    };
}

async function exerciseGateBrowser(mode) {
    const check = (value, why) => { if (!value) throw new Error(why); };
    const frame = () => new Promise(resolve => requestAnimationFrame(resolve));
    const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
    const id = name => document.getElementById(name);
    function controls(hidden) {
        check(id('heading').getClientRects().length, 'heading: hidden by the gate');
        for (const name of ['txtManualPassword', 'txtManualName', 'submit', 'remember', 'cancel', 'quick', 'provider', 'passkey', 'extra']) {
            const element = id(name);
            const allowed = !hidden || !['txtManualName', 'txtManualPassword', 'submit'].includes(name);
            const visible = !!element.getClientRects().length;
            element.focus();
            const focused = document.activeElement === element;
            check(visible === allowed && focused === allowed,
                name + ': visible=' + visible + ', focused=' + focused + ', expected both ' + allowed);
        }
    }
    const reveal = () => id('__tfa_pw_reveal');
    try {
        const template = document.querySelector('template');
        if (mode.endsWith('-remount')) template.before(template.content.cloneNode(true));
        if (mode.startsWith('foreign-entry-')) {
            if (document.readyState !== 'complete') await new Promise(resolve => window.addEventListener('load', resolve, {once: true}));
            await frame();
            check(!document.documentElement.classList.contains('tfa-pw-gated'), 'preceding view already gated');
            // Both routes select B. Only the view changes, without firing hashchange.
            history.pushState(null, '', location.hash.replace('/selectserver', '/login'));
            template.replaceWith(template.content);
        }
        await frame();
        controls(true);
        await frame();
        controls(true);
        if (mode.endsWith('-remount')) {
            check(reveal(), 'initial form was not initialized');
            // Mount pristine controls on the same route, without copying the hidden inline styles.
            document.querySelector('.manualLoginForm').replaceWith(template.content.cloneNode(true));
            await frame();
            controls(true);
        }
        if (mode === 'switch') {
            reveal().click();
            controls(false);
            document.querySelector('form').replaceWith(document.querySelector('form').cloneNode(true));
            window.dispatchEvent(new Event('hashchange'));
            await frame();
            controls(false);
            // The stock router can replace the view after pushState without a hashchange event.
            history.pushState(null, '', '#/login?serverid=B');
            document.querySelector('form').replaceWith(document.querySelector('form').cloneNode(true));
            await frame();
            controls(true);
        }
        if (mode.startsWith('foreign') || mode === 'switch' || mode === 'legacy') {
            check(typeof window.answerB === 'function', 'selected server did not receive a policy request');
            check(!reveal(), 'pending server offered a premature reveal');
            if (mode === 'foreign-timeout') {
                await wait(2800);
                controls(false);
            }
            const answer = mode === 'foreign-allowed' ? false : mode === 'foreign-error' ? 'error' : true;
            window.answerB(answer);
            await wait(30);
            controls(answer === true);
            if (answer !== true) check(!reveal(), 'allowed server retained a reveal link');
        }
        if (!['foreign-allowed', 'foreign-error'].includes(mode)) {
            await wait(300);
            controls(true);
            check(reveal(), 'missing reveal link');
            reveal().click();
            check(document.activeElement === id('txtManualName'), 'reveal did not focus username');
            controls(false);
        }
        check(!window.errors.length, window.errors.join('; '));
        await window.postResult('/result', {method: 'POST', body: 'pass'});
    } catch (error) {
        await window.postResult('/result', {method: 'POST', body: error.message + ' ' + window.errors.join('; ')});
    }
}

for (const mode of ['restricted', 'older-selector', 'older-selector-remount', 'element-fallback', 'element-fallback-remount',
    'foreign-allowed', 'foreign-restricted', 'foreign-timeout', 'foreign-error', 'foreign-entry-active', 'foreign-entry-named',
    'switch', 'legacy']) {
    test('rendered stock password form: ' + mode, async t => {
        const profile = mkdtempSync(join(tmpdir(), 'jellyfin-gate-'));
        const entering = mode.startsWith('foreign-entry-');
        const useTemplate = entering || mode.endsWith('-remount');
        const named = (mode.startsWith('foreign') && mode !== 'foreign-entry-active') || mode === 'legacy';
        let finish;
        const result = new Promise(resolve => { finish = resolve; });
        const timer = setTimeout(() => finish('browser timed out'), 15000);
        const server = createServer((req, res) => {
            if (req.url === '/result') {
                let body = '';
                req.setEncoding('utf8').on('data', chunk => { body += chunk; }).on('end', () => { res.end(); finish(body); });
            } else if (req.url === '/a/TwoFactorAuth/inject') {
                res.writeHead(200, {'Content-Type': 'application/javascript'});
                res.end('window.__tfaPasswordLoginDisabled = true;\n' + inject);
            } else if (req.url.startsWith('/a/web/')) {
                const policy = useTemplate || ['restricted', 'older-selector', 'element-fallback'].includes(mode)
                    ? "style-src 'self'" : "style-src 'self' 'unsafe-inline'";
                res.writeHead(200, {'Content-Type': 'text/html', 'Content-Security-Policy': policy});
                // Jellyfin Web 10.11.11 and 12.4 ship this order: a heading div before the
                // two credential wrappers, then Remember Me, submit and Cancel. The controls
                // after Cancel must stay usable while gated, like Remember Me and Cancel.
                res.end(`<!doctype html><head><script>(${prepareGateBrowser})(${JSON.stringify(mode)})</script>
                    <script src="/a/TwoFactorAuth/inject"></script></head><body>
                    ${useTemplate ? '<template>' : ''}<form class="manualLoginForm">
                    <div class="padded-left padded-right flex align-items-center justify-content-center">
                    <h1 id="heading" class="sectionTitle">Please sign in</h1></div>
                    <div class="inputContainer"><input id="txtManualName"></div>
                    <div class="inputContainer"><input id="txtManualPassword" type="password"></div>
                    <label class="checkboxContainer"><input id="remember" type="checkbox" class="chkRememberLogin">Remember Me</label>
                    <button id="submit" type="submit">Sign In</button>
                    <div><button id="cancel" type="button" class="btnCancel">Cancel</button></div>
                    <button id="quick" type="button">Quick Connect</button>
                    <a href="#" id="provider">SSO</a><a href="#" id="passkey">Passkey</a>
                    <div class="inputContainer"><input id="extra" type="search"></div></form>${useTemplate ? '</template>' : ''}
                    <script>(${exerciseGateBrowser})(${JSON.stringify(mode)})</script>`);
            } else { res.writeHead(404); res.end(); }
        });
        let browser;
        t.after(async () => {
            clearTimeout(timer);
            if (browser && browser.exitCode === null && browser.signalCode === null && browser.pid) {
                const exited = new Promise(resolve => browser.once('exit', resolve));
                browser.kill();
                await exited;
            }
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
            rmSync(profile, {recursive: true, force: true, maxRetries: 3});
        });
        await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
        const route = entering ? '/selectserver' : '/login';
        const url = 'http://127.0.0.1:' + server.address().port + '/a/web/index.html#' + route + '?' + (named ? 'serverid=B' : 'redirect=home');
        browser = spawn(process.env.CHROME_BIN || 'google-chrome', ['--headless', '--disable-background-networking',
            '--disable-component-update', '--no-first-run', '--user-data-dir=' + profile, url], {stdio: 'ignore'});
        browser.once('error', error => finish(error.message));
        browser.once('exit', code => finish('browser exited with ' + code));
        assert.equal(await result, 'pass');
    });
}

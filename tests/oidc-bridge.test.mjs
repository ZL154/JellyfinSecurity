// Run with Node.js 18+: node --test tests/oidc-bridge.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
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

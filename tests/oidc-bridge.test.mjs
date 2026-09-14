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

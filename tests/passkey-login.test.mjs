// Run with Node.js 18+: node --test tests/passkey-login.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const inject = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/inject.js', import.meta.url), 'utf8');

// [#319] Run the login page's passkey button exactly as inject.js defines it.
function source(name) {
    const match = inject.match(new RegExp(`\\n( *)function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\1\\}`));
    assert(match, `inject.js must define ${name}`);
    return match[0].trim();
}
const helpers = ['b64uToBytes', 'bytesToB64u'].map(name => inject.match(new RegExp(`function ${name}\\(.*`))[0]);
const script = [source('findUsernameInput'), source('findUsername'), source('addPasskeyButton'), ...helpers, 'addPasskeyButton(signInBtn, twoFaBtn);'].join('\n');

const bytes = text => new TextEncoder().encode(text).buffer;

// Clicks the passkey button on a login form whose username field holds
// `typed`, with the browser either answering or refusing the ceremony. With
// `themed`, the username field has neither the id nor the name Jellyfin uses
// and only the manual form's text input selector finds it.
async function signIn(typed, {refuse = false, themed = false} = {}) {
    const requests = [];
    const alerts = [];
    const ceremonies = [];
    const events = [];
    let submitted = false;
    let click;
    const input = (name, value) => ({
        name, value,
        dispatchEvent(event) { events.push(`${name}:${event.type}`); },
    });
    const nameInput = input('name', typed);
    const passInput = input('password', '');
    const context = {
        window: {isSecureContext: true, PublicKeyCredential: function () {}},
        document: {
            getElementById: () => null,
            createElement: () => ({
                style: {},
                setAttribute() {},
                addEventListener(type, handler) { if (type === 'click') click = handler; },
            }),
            querySelector(selector) {
                if (selector.includes('txtManualPassword')) return passInput;
                if (themed) return selector.includes('.manualLoginForm input[type="text"]') ? nameInput : null;
                if (selector.includes('txtManualName')) return nameInput;
                return null;
            },
        },
        navigator: {
            credentials: {
                async get(request) {
                    ceremonies.push(request.publicKey);
                    if (refuse) throw Object.assign(new Error('The operation was not allowed.'), {name: 'NotAllowedError'});
                    return {
                        id: 'cred', rawId: bytes('cred'), type: 'public-key',
                        response: {
                            authenticatorData: bytes('auth'), clientDataJSON: bytes('client'),
                            signature: bytes('sig'), userHandle: bytes('handle'),
                        },
                    };
                },
            },
        },
        Event: class { constructor(type, init) { this.type = type; this.bubbles = init?.bubbles; } },
        T: (key, fallback) => `[${key}] ${fallback}`,
        serverUrl: path => '/' + path,
        alert: message => alerts.push(message),
        atob, btoa, Uint8Array, JSON,
        fetch: async (url, options) => {
            const body = JSON.parse(options.body);
            requests.push({url, body});
            if (url.endsWith('/LoginBegin')) {
                const options = {challenge: 'AAAA', allowCredentials: body.Username ? [{type: 'public-key', id: 'Y3JlZA'}] : []};
                return {ok: true, json: async () => ({options: JSON.stringify(options), nonce: 'nonce-1'})};
            }
            return {ok: true, json: async () => ({username: 'alice', token: 'oidcbr_token'})};
        },
        signInBtn: {click() { submitted = true; }},
        twoFaBtn: {className: '', nextSibling: null, parentNode: {appendChild() {}}},
    };
    runInNewContext(script, context);
    assert(click, 'the passkey button must have a click handler');
    await click({preventDefault() {}});
    return {requests, alerts, ceremonies, events, submitted, name: nameInput.value, password: passInput.value};
}

test('with the username field empty, the passkey names the account and signs in', async () => {
    const result = await signIn('');

    assert.deepEqual(result.alerts, []);
    assert.deepEqual(result.requests.map(r => r.url), ['/TwoFactorAuth/Passkey/LoginBegin', '/TwoFactorAuth/Passkey/LoginComplete']);
    assert.deepEqual(result.requests[0].body, {Username: ''});
    assert.equal(result.requests[1].body.Username, '');
    assert.equal(result.requests[1].body.Nonce, 'nonce-1');
    assert.equal(result.ceremonies[0].allowCredentials.length, 0);
    assert.equal(result.name, 'alice');
    assert.equal(result.password, 'oidcbr_token');
    assert.deepEqual(result.events, ['name:input', 'password:input']);
    assert.equal(result.submitted, true);
});

test('a themed username field that only the fallback selector finds is filled in', async () => {
    const result = await signIn('', {themed: true});

    assert.deepEqual(result.alerts, []);
    assert.equal(result.name, 'alice');
    assert.equal(result.submitted, true);
});

test('a typed username keeps the existing flow and is not rewritten', async () => {
    const result = await signIn('Alice');

    assert.deepEqual(result.alerts, []);
    assert.deepEqual(result.requests[0].body, {Username: 'Alice'});
    assert.equal(result.requests[1].body.Username, 'Alice');
    assert.equal(result.ceremonies[0].allowCredentials.length, 1);
    assert.equal(result.name, 'Alice');
    assert.equal(result.password, 'oidcbr_token');
    assert.deepEqual(result.events, ['password:input']);
    assert.equal(result.submitted, true);
});

test('without a username, a refused ceremony points to typing the username', async () => {
    const result = await signIn('', {refuse: true});

    assert.equal(result.submitted, false);
    assert.equal(result.alerts.length, 1);
    assert.match(result.alerts[0], /^\[tfa\.login\.passkey_usernameless_failed\] /);
    assert.match(result.alerts[0], /The operation was not allowed\.$/);
});

test('with a username, a refused ceremony keeps the existing message', async () => {
    const result = await signIn('alice', {refuse: true});

    assert.equal(result.submitted, false);
    assert.deepEqual(result.alerts, ['Passkey sign-in failed: The operation was not allowed.']);
});

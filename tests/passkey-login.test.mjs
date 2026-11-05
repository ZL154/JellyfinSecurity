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
const script = [source('findUsernameInput'), source('findUsername'), source('addPasskeyButton'), source('signInWithBridgeToken'), ...helpers, 'addPasskeyButton(signInBtn, twoFaBtn);'].join('\n');

const bytes = text => new TextEncoder().encode(text).buffer;

// A stand-in for Jellyfin Web's ApiClient and Dashboard globals that records
// what the sign-in asks of them. `refuseWith` makes authenticateUserByName
// reject with a response of that status, as the real ApiClient does.
function jellyfinWeb({refuseWith = 0, serverId = 'server-1'} = {}) {
    const calls = [];
    const apiClient = {
        serverId: () => serverId,
        async authenticateUserByName(name, password) {
            calls.push(['authenticateUserByName', name, password]);
            if (refuseWith) throw {status: refuseWith};
            return {User: {Id: 'user-1'}, AccessToken: 'access-1'};
        },
    };
    const dashboard = {
        onServerChanged: (...args) => calls.push(['onServerChanged', ...args]),
        navigate: url => calls.push(['navigate', url]),
        showLoadingMsg: () => calls.push(['showLoadingMsg']),
        hideLoadingMsg: () => calls.push(['hideLoadingMsg']),
    };
    return {apiClient, dashboard, calls};
}

// Clicks the passkey button on a login form whose username field holds
// `typed`, with the browser either answering or refusing the ceremony. With
// `themed`, the username field has neither the id nor the name Jellyfin uses
// and only the manual form's text input selector finds it. `web` is the
// Jellyfin Web the page runs in (null: one without the sign-in API), `hash`
// the login route and `remember` the state of the "Remember me" box.
async function signIn(typed, {refuse = false, themed = false, web = jellyfinWeb(), hash = '#/login', remember = true} = {}) {
    const requests = [];
    const alerts = [];
    const ceremonies = [];
    const events = [];
    const warnings = [];
    const storage = new Map();
    let submitted = false;
    let click;
    // Every write is logged, so a token written and then cleared again is
    // still caught: a password manager may have seen it in between.
    const writes = [];
    const input = (name, initial) => {
        let value = initial;
        return {
            name,
            get value() { return value; },
            set value(next) { writes.push(`${name}:${next}`); value = next; },
            dispatchEvent(event) { events.push(`${name}:${event.type}`); },
        };
    };
    const nameInput = input('name', typed);
    const passInput = input('password', '');
    const form = {
        querySelector: selector => selector === '.chkRememberLogin' ? {checked: remember} : null,
    };
    const context = {
        window: {
            isSecureContext: true, PublicKeyCredential: function () {}, location: {hash},
            ApiClient: web?.apiClient, Dashboard: web?.dashboard,
        },
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
        atob, btoa, Uint8Array, JSON, URLSearchParams, decodeURIComponent, String,
        localStorage: {setItem: (key, value) => storage.set(key, value)},
        console: {warn: message => warnings.push(message)},
        fetch: async (url, options) => {
            const body = JSON.parse(options.body);
            requests.push({url, body});
            if (url.endsWith('/LoginBegin')) {
                const options = {challenge: 'AAAA', allowCredentials: body.Username ? [{type: 'public-key', id: 'Y3JlZA'}] : []};
                return {ok: true, json: async () => ({options: JSON.stringify(options), nonce: 'nonce-1'})};
            }
            return {ok: true, json: async () => ({username: 'alice', token: 'oidcbr_token'})};
        },
        signInBtn: {click() { submitted = true; }, closest: selector => selector === 'form' ? form : null},
        twoFaBtn: {className: '', nextSibling: null, parentNode: {appendChild() {}}},
    };
    runInNewContext(script, context);
    assert(click, 'the passkey button must have a click handler');
    await click({preventDefault() {}});
    return {
        requests, alerts, ceremonies, events, warnings, submitted,
        name: nameInput.value, password: passInput.value,
        passwordWrites: writes.filter(w => w.startsWith('password:')),
        calls: web?.calls, rememberSetting: storage.get('enableAutoLogin'),
    };
}

test('with the username field empty, the passkey names the account and signs in', async () => {
    const result = await signIn('');

    assert.deepEqual(result.alerts, []);
    assert.deepEqual(result.requests.map(r => r.url), ['/TwoFactorAuth/Passkey/LoginBegin', '/TwoFactorAuth/Passkey/LoginComplete']);
    assert.deepEqual(result.requests[0].body, {Username: ''});
    assert.equal(result.requests[1].body.Username, '');
    assert.equal(result.requests[1].body.Nonce, 'nonce-1');
    assert.equal(result.ceremonies[0].allowCredentials.length, 0);
    assert.deepEqual(result.calls[1], ['authenticateUserByName', 'alice', 'oidcbr_token']);
});

// [#NEW_ISSUE] The token goes to Jellyfin Web's sign-in call, never into the
// password field a password manager watches, and the page then does what the
// login form does after it signs in.
test('the passkey signs in through Jellyfin Web without the password field or the form', async () => {
    const result = await signIn('');

    assert.deepEqual(result.passwordWrites, []);
    assert.equal(result.password, '');
    assert.equal(result.name, '');
    assert.deepEqual(result.events, []);
    assert.equal(result.submitted, false);
    assert.deepEqual(result.calls.map(call => call[0]), ['showLoadingMsg', 'authenticateUserByName', 'hideLoadingMsg', 'onServerChanged', 'navigate']);
    assert.deepEqual(result.calls[1], ['authenticateUserByName', 'alice', 'oidcbr_token']);
    const [, userId, accessToken, apiClient] = result.calls[3];
    assert.deepEqual([userId, accessToken], ['user-1', 'access-1']);
    assert.equal(typeof apiClient.authenticateUserByName, 'function');
    assert.deepEqual(result.calls[4], ['navigate', '/home']);
    assert.equal(result.rememberSetting, 'true');
    assert.deepEqual(result.warnings, []);
});

test('a cleared "Remember me" box is saved as the login form saves it', async () => {
    const result = await signIn('', {remember: false});

    assert.equal(result.rememberSetting, 'false');
    assert.deepEqual(result.passwordWrites, []);
    assert.equal(result.submitted, false);
});

test('the page the login route was asked to return to is opened', async () => {
    const result = await signIn('', {hash: '#/login?serverid=server-1&url=%2Fdetails%3Fid%3Dabc'});

    assert.deepEqual(result.calls.at(-1), ['navigate', '/details?id=abc']);
    assert.deepEqual(result.passwordWrites, []);
    assert.equal(result.submitted, false);
});

// Jellyfin Web keeps the last value of a repeated route parameter.
test('a repeated url parameter opens the page the login form would open', async () => {
    const result = await signIn('', {hash: '#/login?url=%2Fhome&url=%2Fmypreferencesmenu'});

    assert.deepEqual(result.calls.at(-1), ['navigate', '/mypreferencesmenu']);
});

test('a repeated serverid naming another server last falls back to the login form', async () => {
    const web = jellyfinWeb();
    const result = await signIn('', {web, hash: '#/login?serverid=server-1&serverid=other-server'});

    assert.deepEqual(web.calls, []);
    assert.equal(result.submitted, true);
});

test('a typed username signs in with the account name the server returned', async () => {
    const result = await signIn('Alice');

    assert.deepEqual(result.alerts, []);
    assert.deepEqual(result.requests[0].body, {Username: 'Alice'});
    assert.equal(result.requests[1].body.Username, 'Alice');
    assert.equal(result.ceremonies[0].allowCredentials.length, 1);
    assert.deepEqual(result.calls[1], ['authenticateUserByName', 'alice', 'oidcbr_token']);
    assert.equal(result.name, 'Alice');
    assert.deepEqual(result.passwordWrites, []);
    assert.equal(result.submitted, false);
});

test('a Jellyfin refusal of the account explains what to check', async () => {
    const result = await signIn('', {web: jellyfinWeb({refuseWith: 403})});

    assert.equal(result.submitted, false);
    assert.deepEqual(result.passwordWrites, []);
    assert.deepEqual(result.alerts.map(a => a.split(']')[0]), ['[tfa.login.oidc_refused']);
    assert.deepEqual(result.calls.at(-1), ['hideLoadingMsg']);
});

test('a rejected token after the ceremony is reported as a failed sign-in', async () => {
    const result = await signIn('', {web: jellyfinWeb({refuseWith: 401})});

    assert.equal(result.submitted, false);
    assert.deepEqual(result.passwordWrites, []);
    assert.deepEqual(result.alerts, ['Passkey sign-in failed: HTTP 401']);
});

// Without the globals the old path is the only one left: it still works, and
// says in the console why the token went through the form.
test('without the sign-in API, the token falls back to the login form', async () => {
    const result = await signIn('', {web: null});

    assert.deepEqual(result.alerts, []);
    assert.equal(result.name, 'alice');
    assert.equal(result.password, 'oidcbr_token');
    assert.deepEqual(result.passwordWrites, ['password:oidcbr_token']);
    assert.deepEqual(result.events, ['name:input', 'password:input']);
    assert.equal(result.submitted, true);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0], /submitting the login form/);
});

test('a login route for another server falls back to the login form', async () => {
    const web = jellyfinWeb();
    const result = await signIn('', {web, hash: '#/login?serverid=other-server'});

    assert.deepEqual(web.calls, []);
    assert.equal(result.password, 'oidcbr_token');
    assert.equal(result.submitted, true);
    assert.equal(result.warnings.length, 1);
});

test('a themed username field that only the fallback selector finds is filled in', async () => {
    const result = await signIn('', {themed: true, web: null});

    assert.deepEqual(result.alerts, []);
    assert.equal(result.name, 'alice');
    assert.equal(result.submitted, true);
});

test('with the fallback, a typed username keeps the existing flow and is not rewritten', async () => {
    const result = await signIn('Alice', {web: null});

    assert.deepEqual(result.alerts, []);
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

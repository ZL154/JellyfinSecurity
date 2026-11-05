import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const html = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/challenge.html', import.meta.url), 'utf8');
const start = html.indexOf('        function b64uToBytes(');
const end = html.indexOf('        // [v2.5.21]', start);
assert(start > 0 && end > start, 'the complete passkey handler must exist');
const source = html.slice(start, end);

async function answer({checked, changeDuringPrompt, token = 'test-device-token', ok = true, storedToken, storageBlocked = false}) {
    const elements = new Map();
    const handlers = new Map();
    const storage = new Map();
    if (storedToken) storage.set('twofactor_device_token', storedToken);
    const requests = [];
    const errors = [];
    let delivered;
    const element = id => {
        if (!elements.has(id)) elements.set(id, {checked: false, addEventListener: (event, handler) => handlers.set(id, handler)});
        return elements.get(id);
    };
    element('trustDevice').checked = checked;
    const context = {
        document: {getElementById: element},
        window: {tfaUrl: path => '/jf/' + path, location: {}},
        challengeToken: 'test-challenge', returnUrl: '/jf/web/',
        refreshPasskeyButton() {}, clearError() {}, showError: message => errors.push(message),
        _tr: (key, fallback) => fallback,
        atob: text => Buffer.from(text, 'base64').toString('binary'),
        btoa: text => Buffer.from(text, 'binary').toString('base64'),
        localStorage: {setItem: (key, value) => {
            if (storageBlocked) throw new Error('Storage is unavailable');
            storage.set(key, value);
        }},
        storeCredentials: async data => { delivered = data; },
        navigator: {credentials: {get: async () => {
            if (changeDuringPrompt !== undefined) element('trustDevice').checked = changeDuringPrompt;
            const bytes = new Uint8Array([1, 2, 3]).buffer;
            return {id: 'test-key', rawId: bytes, type: 'public-key', response: {
                authenticatorData: bytes, clientDataJSON: bytes, signature: bytes, userHandle: bytes,
            }};
        }}},
        fetch: async (url, options) => {
            requests.push({url, ...options, body: JSON.parse(options.body)});
            if (url.endsWith('/Begin')) return {ok: true, json: async () => ({nonce: 'test-nonce', options: {challenge: 'AQID', allowCredentials: [{id: 'AQID'}]}})};
            return {ok, headers: {get: name => name === 'X-TwoFactor-Device-Token' ? token : null},
                json: async () => ({AccessToken: 'test-session', User: {Id: 'test-user'}})};
        },
    };
    runInNewContext(source, context);
    await handlers.get('btnPasskey')();
    await Promise.resolve();
    return {requests, storage, errors, delivered};
}

for (const checked of [true, false]) {
    test(`passkey Finish sends the checkbox value ${checked} and stores the returned device token`, async () => {
        const result = await answer({checked});
        assert.equal(result.requests.length, 2);
        const finish = result.requests[1];
        assert.equal(finish.url, '/jf/TwoFactorAuth/Verify/Passkey/Finish');
        assert.equal(finish.method, 'POST');
        assert.equal(finish.body.challengeToken, 'test-challenge');
        assert.equal(finish.body.nonce, 'test-nonce');
        assert.equal(finish.body.trustDevice, checked);
        assert.equal(JSON.parse(finish.body.response).type, 'public-key');
        assert.equal(result.storage.get('twofactor_device_token'), 'test-device-token');
        assert.equal(result.delivered.AccessToken, 'test-session');
        assert.deepEqual(result.errors, []);
    });
}

test('the checkbox is read when Finish is submitted', async () => {
    const result = await answer({checked: false, changeDuringPrompt: true});
    assert.equal(result.requests[1].body.trustDevice, true);
});

test('an absent device token leaves stored trust alone', async () => {
    const result = await answer({checked: false, token: null, storedToken: 'existing-device-token'});
    assert.equal(result.storage.get('twofactor_device_token'), 'existing-device-token');
    assert.equal(result.delivered.AccessToken, 'test-session');
});

test('a failed assertion stores neither trust nor a session', async () => {
    const result = await answer({checked: true, ok: false});
    assert.equal(result.storage.size, 0);
    assert.equal(result.delivered, undefined);
    assert.equal(result.errors.length, 1);
});

test('blocked localStorage still lets the verified session complete', async () => {
    const result = await answer({checked: true, storageBlocked: true});
    assert.equal(result.storage.size, 0);
    assert.equal(result.delivered.AccessToken, 'test-session');
    assert.deepEqual(result.errors, []);
});

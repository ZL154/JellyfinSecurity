// Run with Node.js 18+: node --test tests/passkey-second-factor-page.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const pages = new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/', import.meta.url);
const read = name => readFileSync(new URL(name, pages), 'utf8');
const setup = read('setup.html');

// [#339] Run the switch on the Passkeys card exactly as setup.html defines
// it, together with the page's own request helper and step-up retry.
function pageFunction(name) {
    const found = setup.match(new RegExp(`\\n( *)(?:async )?function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\1\\}`));
    assert(found, `setup.html must define ${name}`);
    return found[0].trim();
}
let script;
const pageScript = () => script ??= [
    'api', 'mutateWithStepUp', 'passkeySecondFactorView', 'renderPasskeySecondFactor',
    'refreshPasskeySecondFactor', 'changePasskeySecondFactor',
].map(pageFunction).join('\n');

const PREFERENCE = '/jf/TwoFactorAuth/MyPasskeySecondFactorPreference';
const PROOF_REQUIRED = {
    message: 'A current authenticator or recovery code is required to modify two-factor settings.',
    stepUpRequired: true,
    twoFactorRequired: true,
};

// A MyStatus answer for an account with one passkey and no authenticator
// app, outside the enforcement scope, with the default left on.
const status = fields => ({
    UserId: 'test-user-id', Username: 'test-user', TotpEnabled: false, PasskeyCount: 1,
    PasskeyRequiresSecondFactor: true, PasswordSignInRequiresSecondFactor: true,
    PasswordSignInSecondFactorReason: 'passkey', SelfServiceStepUpMode: 'Forced',
    ...fields,
});
const optedOut = {
    PasskeyRequiresSecondFactor: false, PasswordSignInRequiresSecondFactor: false,
    PasswordSignInSecondFactorReason: 'none',
};

function fakeElement() {
    const attributes = new Map();
    const classes = new Set();
    return {
        style: {}, textContent: '', checked: false, disabled: false,
        classList: {add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c)},
        setAttribute: (name, value) => attributes.set(name, String(value)),
        getAttribute: name => attributes.has(name) ? attributes.get(name) : null,
        removeAttribute: name => attributes.delete(name),
    };
}

// responses answer the requests in order; proof is what the step-up prompt
// returns (null when the user cancels it).
function page({responses = [], proof = null} = {}) {
    const elements = new Map();
    const requests = [];
    const prompts = [];
    const context = {
        window: {},
        document: {
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, fakeElement());
                return elements.get(id);
            },
        },
        apiUrl: path => '/jf/' + path,
        getAuthHeaders: () => ({'Content-Type': 'application/json'}),
        _tr: (key, fallback) => fallback,
        tfaPromptForCode: async opts => {
            prompts.push(opts);
            return proof;
        },
        fetch: async (url, options) => {
            requests.push({url, method: options.method, body: options.body === undefined ? undefined : JSON.parse(options.body)});
            const next = responses.shift();
            assert(next, `unexpected request to ${url}`);
            return {ok: next.status >= 200 && next.status < 300, status: next.status, json: async () => next.body};
        },
    };
    runInNewContext(pageScript(), context);
    const el = id => context.document.getElementById(id);
    return {context, requests, prompts, el, toggle: el('passkeySecondFactorToggle'), error: el('passkeySecondFactorError')};
}
const view = s => ({...page().context.passkeySecondFactorView(s)});
const shown = element => element.style.display !== 'none';

test('the switch stays hidden without a passkey or without a status', () => {
    for (const s of [status({PasskeyCount: 0, ...optedOut}), null, {}]) {
        const p = page();
        p.context.renderPasskeySecondFactor(s);
        assert.equal(shown(p.el('passkeySecondFactor')), false);
        assert.equal(view(s).show, false);
    }
});

test('the switch shows the stored choice, and a missing field reads as on', () => {
    const missing = status();
    delete missing.PasskeyRequiresSecondFactor;
    const cases = [
        [status(), true],
        [status(optedOut), false],
        [missing, true],
        [{passkeyCount: 1, passkeyRequiresSecondFactor: false, passwordSignInRequiresSecondFactor: false, passwordSignInSecondFactorReason: 'none'}, false],
        [{passkeyCount: 2, passwordSignInRequiresSecondFactor: true, passwordSignInSecondFactorReason: 'passkey'}, true],
    ];
    for (const [s, checked] of cases) {
        const p = page();
        p.context.renderPasskeySecondFactor(s);
        assert.equal(shown(p.el('passkeySecondFactor')), true);
        assert.equal(p.toggle.checked, checked);
        assert.equal(p.toggle.disabled, false);
        assert.equal(shown(p.el('passkeySecondFactorReason')), false);
        assert.equal(shown(p.el('passkeySecondFactorStillAsked')), false);
    }
});

test('the enforcement scope and an authenticator app disable the switch and say why', () => {
    const reasons = {
        scope: /administrator requires a second factor for this account/,
        authenticator: /authenticator app already protects password sign-in/,
    };
    for (const [reason, text] of Object.entries(reasons)) {
        const p = page();
        p.context.renderPasskeySecondFactor(status({PasswordSignInSecondFactorReason: reason, TotpEnabled: reason === 'authenticator'}));
        assert.equal(p.toggle.checked, true);
        assert.equal(p.toggle.disabled, true);
        const note = p.el('passkeySecondFactorReason');
        assert.equal(shown(note), true);
        assert.match(note.textContent, text);
        assert.equal(note.getAttribute('data-i18n-key'), `tfa.setup.passkeys.second_factor_${reason}`);
        assert.equal(shown(p.el('passkeySecondFactorStillAsked')), false);
    }
});

test('a stored off that scope or the app overrides says password sign-in still asks', () => {
    for (const reason of ['scope', 'authenticator']) {
        const p = page();
        p.context.renderPasskeySecondFactor(status({
            PasskeyRequiresSecondFactor: false, PasswordSignInRequiresSecondFactor: true,
            PasswordSignInSecondFactorReason: reason,
        }));
        assert.equal(p.toggle.checked, false);
        assert.equal(p.toggle.disabled, true);
        assert.equal(shown(p.el('passkeySecondFactorReason')), true);
        assert.equal(shown(p.el('passkeySecondFactorStillAsked')), true);
    }
    assert.deepEqual(view(status({PasswordSignInSecondFactorReason: 'scope'})), {
        show: true, checked: true, disabled: true, reason: 'scope', stillAsked: false,
    });
});

test('the reason note goes away when nothing overrides the switch any more', () => {
    const p = page();
    p.context.renderPasskeySecondFactor(status({PasswordSignInSecondFactorReason: 'scope'}));
    p.context.renderPasskeySecondFactor(status());
    const note = p.el('passkeySecondFactorReason');
    assert.equal(shown(note), false);
    assert.equal(note.getAttribute('data-i18n-key'), null);
    assert.equal(p.toggle.disabled, false);
});

for (const proof of [{stepUpToken: 'test-step-up-token'}, {code: '123456'}]) {
    test(`turning the switch off asks for proof and retries with ${Object.keys(proof)[0]}`, async () => {
        const p = page({proof, responses: [{status: 403, body: PROOF_REQUIRED}, {status: 200, body: status(optedOut)}]});
        p.context.renderPasskeySecondFactor(status());
        p.toggle.checked = false;
        await p.context.changePasskeySecondFactor({target: p.toggle});
        assert.deepEqual(p.requests, [
            {url: PREFERENCE, method: 'POST', body: {enabled: false}},
            {url: PREFERENCE, method: 'POST', body: {enabled: false, ...proof}},
        ]);
        assert.equal(p.prompts.length, 1);
        assert.match(p.prompts[0].message, /stop asking for a second factor after password sign-in/);
        assert.equal(p.toggle.checked, false);
        assert.equal(p.toggle.disabled, false);
        assert.equal(p.error.classList.contains('show'), false);
    });
}

test('turning the switch on sends no proof and shows what the server stored', async () => {
    const p = page({responses: [{status: 200, body: status({PasswordSignInSecondFactorReason: 'scope'})}]});
    p.context.renderPasskeySecondFactor(status(optedOut));
    p.toggle.checked = true;
    await p.context.changePasskeySecondFactor({target: p.toggle});
    assert.deepEqual(p.requests, [{url: PREFERENCE, method: 'POST', body: {enabled: true}}]);
    assert.equal(p.prompts.length, 0);
    assert.equal(p.toggle.checked, true);
    assert.equal(p.toggle.disabled, true, 'the returned status is rendered, scope included');
    assert.equal(p.error.classList.contains('show'), false);
});

test('a refused proof puts the switch back and says the code did not verify', async () => {
    const p = page({proof: {code: '000000'}, responses: [{status: 403, body: PROOF_REQUIRED}, {status: 403, body: PROOF_REQUIRED}]});
    p.context.renderPasskeySecondFactor(status());
    p.toggle.checked = false;
    await p.context.changePasskeySecondFactor({target: p.toggle});
    assert.equal(p.requests.length, 2);
    assert.equal(p.toggle.checked, true);
    assert.equal(p.toggle.disabled, false);
    assert.equal(p.error.classList.contains('show'), true);
    assert.equal(p.error.textContent, 'That code did not verify. Try again.');
});

test('a cancelled prompt puts the switch back without an error', async () => {
    const p = page({proof: null, responses: [{status: 403, body: PROOF_REQUIRED}]});
    p.context.renderPasskeySecondFactor(status());
    p.toggle.checked = false;
    await p.context.changePasskeySecondFactor({target: p.toggle});
    assert.equal(p.requests.length, 1);
    assert.equal(p.toggle.checked, true);
    assert.equal(p.toggle.disabled, false);
    assert.equal(p.error.classList.contains('show'), false);
});

test('any other failure puts the switch back with the page\'s save error', async () => {
    const failures = [
        {status: 500, body: {}},
        {status: 400, body: {message: 'Register a passkey before changing this preference.'}},
    ];
    for (const failure of failures) {
        const p = page({responses: [failure]});
        p.context.renderPasskeySecondFactor(status(optedOut));
        p.toggle.checked = true;
        await p.context.changePasskeySecondFactor({target: p.toggle});
        assert.equal(p.toggle.checked, false);
        assert.equal(p.toggle.disabled, false);
        assert.equal(p.prompts.length, 0);
        assert.equal(p.error.classList.contains('show'), true);
        assert.equal(p.error.textContent, 'Could not save preference.');
    }
});

test('a passkey added or removed rereads the status and the count the prompt offers', async () => {
    const p = page({responses: [{status: 200, body: status({PasskeyCount: 2})}]});
    await p.context.refreshPasskeySecondFactor();
    assert.deepEqual(p.requests, [{url: '/jf/TwoFactorAuth/MyStatus', method: 'GET', body: undefined}]);
    assert.equal(p.context.window.__tfa_userPasskeyCount, 2);
    assert.equal(shown(p.el('passkeySecondFactor')), true);
    assert.equal(p.toggle.checked, true);
});

test('the page wires the switch into the Passkeys card, loadAll and the passkey list', () => {
    const card = setup.indexOf('id="cardPasskeys"');
    const box = setup.indexOf('id="passkeySecondFactor"');
    assert(card >= 0 && box > card && box < setup.indexOf('id="cardTotpRotate"'), 'the switch must sit in the Passkeys card');
    assert.match(setup, /id="passkeySecondFactor" style="display:none;/);
    assert.match(setup, /renderPasskeySecondFactor\(myStatus\);/);
    assert.match(setup, /getElementById\('passkeySecondFactorToggle'\)\.addEventListener\('change', changePasskeySecondFactor\);/);
    assert.equal(setup.match(/refreshPasskeySecondFactor\(\)\.catch\(/g)?.length, 2, 'after a passkey is added and after one is removed');
});

test('every new string has its English text in en.json and a translation in all eight bundles', () => {
    const english = {};
    const add = (key, text) => {
        assert(!(key in english) || english[key] === text, `${key} has two English texts`);
        english[key] = text;
    };
    for (const m of setup.matchAll(/data-i18n-key="(tfa\.setup\.passkeys\.second_factor_\w+)"[^>]*>([^<]*)</g)) add(m[1], m[2]);
    for (const m of setup.matchAll(/'(tfa\.setup\.passkeys\.second_factor_\w+)',\s*'((?:[^'\\]|\\.)*)'/g)) add(m[1], m[2].replace(/\\'/g, '\''));
    assert.deepEqual(Object.keys(english).sort(), [
        'tfa.setup.passkeys.second_factor_authenticator',
        'tfa.setup.passkeys.second_factor_help',
        'tfa.setup.passkeys.second_factor_label',
        'tfa.setup.passkeys.second_factor_scope',
        'tfa.setup.passkeys.second_factor_stepup_msg',
        'tfa.setup.passkeys.second_factor_still_asked',
    ]);
    const bundles = Object.fromEntries(['de', 'en', 'es', 'fr', 'it', 'ja', 'pt', 'zh']
        .map(lang => [lang, JSON.parse(read(`translations/${lang}.json`))]));
    for (const [key, text] of Object.entries(english)) {
        assert.equal(bundles.en[key], text, `en.json must hold the page's English text for ${key}`);
        for (const [lang, bundle] of Object.entries(bundles)) {
            if (lang === 'en') continue;
            assert.equal(typeof bundle[key], 'string', `${lang}.json must translate ${key}`);
            assert.notEqual(bundle[key].trim(), '', `${lang}.json has an empty ${key}`);
            assert.notEqual(bundle[key], text, `${lang}.json copies the English ${key}`);
        }
    }
});

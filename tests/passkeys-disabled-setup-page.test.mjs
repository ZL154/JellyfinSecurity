// Run with Node.js 18+: node --test tests/passkeys-disabled-setup-page.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const pages = new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/', import.meta.url);
const read = name => readFileSync(new URL(name, pages), 'utf8');
const setup = read('setup.html');

// [#345] Run the Setup page's functions exactly as setup.html defines them,
// with public-config saying whether the server allows passkeys.
function pageFunction(name) {
    const found = setup.match(new RegExp(`\\n( *)(?:async )?function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\1\\}`));
    assert(found, `setup.html must define ${name}`);
    return found[0].trim();
}
const script = names => names.map(pageFunction).join('\n');

// A MyStatus answer for an account with saved passkeys and no authenticator
// app, outside the enforcement scope.
const status = fields => ({
    UserId: 'test-user-id', Username: 'test-user', TotpEnabled: false, PasskeyCount: 2,
    PasskeyRequiresSecondFactor: true, PasswordSignInRequiresSecondFactor: false,
    PasswordSignInSecondFactorReason: 'none', SelfServiceStepUpMode: 'Forced',
    ...fields,
});

function fakeElement() {
    const attributes = new Map();
    const classes = new Set();
    return {
        style: {}, textContent: '', innerHTML: '', checked: false, disabled: false,
        classList: {add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c)},
        setAttribute: (name, value) => attributes.set(name, String(value)),
        getAttribute: name => attributes.has(name) ? attributes.get(name) : null,
        removeAttribute: name => attributes.delete(name),
        querySelectorAll: () => [],
    };
}

// publicConfig is what window._tfaPublicConfig holds once public-config has
// been read; responses answer the page's requests in order.
function page({publicConfig, responses = []} = {}) {
    const elements = new Map();
    const requests = [];
    const context = {
        window: {_tfaPublicConfig: publicConfig},
        document: {
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, fakeElement());
                return elements.get(id);
            },
            querySelector(selector) {
                if (!elements.has(selector)) elements.set(selector, fakeElement());
                return elements.get(selector);
            },
        },
        apiUrl: path => '/jf/' + path,
        getAuthHeaders: () => ({'Content-Type': 'application/json'}),
        proxyError: () => '',
        _tr: (key, fallback) => fallback,
        setTimeout: () => 0,
        console,
        fetch: async (url, options) => {
            requests.push({url, method: options.method});
            const next = responses.shift();
            assert(next, `unexpected request to ${url}`);
            return {ok: next.status >= 200 && next.status < 300, status: next.status, json: async () => next.body};
        },
    };
    runInNewContext(script([
        'api', 'escapeHtml', 'passkeysEnabled', 'renderPasskeyAvailability', 'passkeySecondFactorView',
        'renderPasskeySecondFactor', 'refreshPasskeySecondFactor', 'loadPasskeyDiag', 'loadPasskeys',
    ]), context);
    const el = id => context.document.getElementById(id);
    return {context, requests, el, altFactors: context.document.querySelector(ALT_FACTORS)};
}
const ALT_FACTORS = '[data-i18n-key="tfa.setup.enroll.alt_factors"]';
const shown = element => element.style.display !== 'none';
const noticeShown = p => p.el('passkeysOffNotice').classList.contains('show');
const OFF = {passkeysEnabled: false};

test('with passkeys off, saved passkeys keep the card with a notice and no way to add one', () => {
    const p = page({publicConfig: OFF});
    p.context.renderPasskeyAvailability(status());
    p.context.renderPasskeySecondFactor(status());
    assert.equal(shown(p.el('cardPasskeys')), true, 'the card stays for the saved passkeys');
    assert.equal(noticeShown(p), true);
    assert.equal(shown(p.el('passkeyRegister')), false, 'no label box and no Add button');
    assert.equal(shown(p.el('passkeySecondFactor')), false, 'no switch for a passkey that cannot be used');
});

test('with passkeys off, the saved passkeys are still listed, each with its Remove button', async () => {
    const rows = [
        {id: 'key-1', label: 'MacBook <Touch ID>', createdAt: '2026-10-01T10:00:00Z', lastUsedAt: null},
        {id: 'key-2', label: 'YubiKey', createdAt: '2026-10-02T10:00:00Z', lastUsedAt: '2026-11-01T10:00:00Z'},
    ];
    const p = page({publicConfig: OFF, responses: [{status: 403, body: {}}, {status: 200, body: rows}]});
    p.context.loadPasskeys();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(p.requests.map(r => r.url), ['/jf/TwoFactorAuth/Passkeys/Diagnose', '/jf/TwoFactorAuth/Passkeys']);
    const list = p.el('passkeyList').innerHTML;
    assert.equal(list.match(/class="btn-ghost btn-sm tfa-passkey-del" data-id="key-\d"/g)?.length, 2);
    assert.match(list, /MacBook &lt;Touch ID&gt;/);
    assert.match(list, /YubiKey/);
});

test('with passkeys off and none saved, the card goes away', () => {
    for (const s of [status({PasskeyCount: 0}), {passkeyCount: 0}, null]) {
        const p = page({publicConfig: OFF});
        p.context.renderPasskeyAvailability(s);
        assert.equal(shown(p.el('cardPasskeys')), false);
    }
});

test('removing the last saved passkey while passkeys are off takes the card away', async () => {
    const p = page({publicConfig: OFF, responses: [{status: 200, body: status({PasskeyCount: 0})}]});
    p.context.renderPasskeyAvailability(status({PasskeyCount: 1}));
    assert.equal(shown(p.el('cardPasskeys')), true);
    await p.context.refreshPasskeySecondFactor();
    assert.deepEqual(p.requests, [{url: '/jf/TwoFactorAuth/MyStatus', method: 'GET'}]);
    assert.equal(p.context.window.__tfa_userPasskeyCount, 0);
    assert.equal(shown(p.el('cardPasskeys')), false);
});

test('with passkeys on or the field missing, the card is left as the page drew it', () => {
    for (const publicConfig of [{passkeysEnabled: true}, {}, null]) {
        const p = page({publicConfig});
        // The SSO page rules may have hidden the card already; that stays.
        p.el('cardPasskeys').style.display = 'none';
        p.context.renderPasskeyAvailability(status({PasskeyCount: 0}));
        assert.equal(shown(p.el('cardPasskeys')), false);
        assert.equal(shown(p.el('passkeyRegister')), true);
        assert.equal(noticeShown(p), false);
        assert.equal(shown(p.altFactors), true);
        assert.equal(shown(p.el('enrollAltFactorsNoPasskey')), false);
        p.context.renderPasskeySecondFactor(status());
        assert.equal(shown(p.el('passkeySecondFactor')), true, 'the #343 switch shows as before');
    }
});

test('the switch view leaves the switch out only when the server has passkeys off', () => {
    const p = page();
    assert.deepEqual({...p.context.passkeySecondFactorView(status(), false)}, {show: false});
    assert.equal(p.context.passkeySecondFactorView(status(), true).show, true);
    assert.equal(p.context.passkeySecondFactorView(status()).show, true, 'no flag reads as on');
});

test('with passkeys off, the authenticator card stops suggesting a passkey', () => {
    const p = page({publicConfig: OFF});
    p.context.renderPasskeyAvailability(status());
    assert.equal(shown(p.altFactors), false);
    assert.equal(shown(p.el('enrollAltFactorsNoPasskey')), true);
});

// The step-up prompt as setup.html builds it. The card's markup is read
// back: the passkey button is there or not, and the text says what to do.
function prompt({publicConfig, passkeyCount = 1, totpOn = false, email = false, oidc = []}) {
    const created = [];
    const node = () => {
        const n = {
            style: {}, innerHTML: '', textContent: '', value: '',
            setAttribute() {}, appendChild() {}, remove() {}, focus() {}, addEventListener() {},
            querySelector(selector) {
                const act = /^\[data-act="(\w+)"\]$/.exec(selector);
                return act && n.innerHTML.includes(`data-act="${act[1]}"`) ? node() : null;
            },
            querySelectorAll: () => [],
        };
        created.push(n);
        return n;
    };
    const context = {
        window: {
            _tfaPublicConfig: publicConfig, __tfa_userPasskeyCount: passkeyCount,
            __tfa_userTotpOn: totpOn, __tfa_userHasEmail: email, __tfa_userOidcLinks: oidc,
        },
        document: {createElement: node, body: {appendChild() {}}, addEventListener() {}, removeEventListener() {}},
        setTimeout: () => 0,
        _tr: (key, fallback) => fallback,
    };
    runInNewContext(script(['escapeHtml', 'passkeysEnabled', 'stepUpPromptMessage', 'tfaPromptForCode']) + '\ntfaPromptForCode({});', context);
    const card = created.find(n => n.innerHTML.includes('data-act="code"'));
    assert(card, 'the prompt must render its card');
    return card.innerHTML;
}
const CODE_TEXT = 'Enter your current TOTP or recovery code to make this change.';
const OPTIONS_TEXT = 'Confirm it is you with one of the options below to make this change.';

test('with passkeys off, the step-up prompt offers no passkey and does not point to one', () => {
    const off = prompt({publicConfig: OFF});
    assert.doesNotMatch(off, /data-act="passkey"/);
    assert.match(off, new RegExp(CODE_TEXT.replace(/\./g, '\\.')), 'with nothing else to offer, the prompt asks for a code');
    const withEmail = prompt({publicConfig: OFF, email: true});
    assert.doesNotMatch(withEmail, /data-act="passkey"/);
    assert.match(withEmail, /data-act="email"/);
    assert.match(withEmail, new RegExp(OPTIONS_TEXT.replace(/\./g, '\\.')));
});

test('with passkeys on or the field missing, the step-up prompt still offers a saved passkey', () => {
    for (const publicConfig of [{passkeysEnabled: true}, {}, null]) {
        const on = prompt({publicConfig});
        assert.match(on, /data-act="passkey"/);
        assert.match(on, new RegExp(OPTIONS_TEXT.replace(/\./g, '\\.')));
    }
    assert.doesNotMatch(prompt({publicConfig: {passkeysEnabled: true}, passkeyCount: 0}), /data-act="passkey"/);
});

test('the page draws the passkey state in loadAll, after the SSO page rules', () => {
    const loadAll = pageFunction('loadAll');
    const sso = loadAll.indexOf('applySsoOnlyPage(ssoPage);');
    const availability = loadAll.indexOf('renderPasskeyAvailability(myStatus);');
    assert(sso > 0 && availability > sso, 'the SSO rules show the card first; passkeys off may then hide it');
    assert.match(loadAll, /var hasFactor = !!totpOn \|\| \(passkeysEnabled\(\) && passkeyCount > 0\);/);
    const card = setup.indexOf('id="cardPasskeys"');
    const end = setup.indexOf('id="cardTotpRotate"');
    for (const id of ['passkeysOffNotice', 'passkeyRegister']) {
        const at = setup.indexOf(`id="${id}"`);
        assert(at > card && at < end, `#${id} must sit in the Passkeys card`);
    }
    assert(setup.indexOf('id="btnAddPasskey"') > setup.indexOf('id="passkeyRegister"'), 'the Add button is part of the registration row');
    assert.match(setup, /<div class="alert warn" id="passkeysOffNotice" data-i18n-key="tfa\.setup\.passkeys\.off_notice">/);
    assert.equal(setup.split('data-i18n-key="tfa.setup.enroll.alt_factors"').length - 1, 2,
        'the pointer with the passkey keeps the key the page finds it by: once in the markup, once in the script');
    assert.match(setup, /id="enrollAltFactorsNoPasskey" style="display:none;/);
});

test('every new string has its English text in en.json and a translation in all eight bundles', () => {
    const keys = ['tfa.setup.passkeys.off_notice', 'tfa.setup.enroll.alt_factors_no_passkey'];
    const bundles = Object.fromEntries(['de', 'en', 'es', 'fr', 'it', 'ja', 'pt', 'zh']
        .map(lang => [lang, read(`translations/${lang}.json`)]));
    for (const key of keys) {
        const html = new RegExp(`data-i18n-key="${key.replace(/\./g, '\\.')}"[^>]*>([^<]*)<`).exec(setup);
        assert(html, `setup.html must carry ${key}`);
        assert.equal(JSON.parse(bundles.en)[key], html[1], `en.json must hold the page's English text for ${key}`);
        for (const [lang, text] of Object.entries(bundles)) {
            assert.equal(text.split(`"${key}":`).length - 1, 1, `${lang}.json must hold ${key} exactly once`);
            if (lang === 'en') continue;
            const translated = JSON.parse(text)[key];
            assert.equal(typeof translated, 'string', `${lang}.json must translate ${key}`);
            assert.notEqual(translated.trim(), '', `${lang}.json has an empty ${key}`);
            assert.notEqual(translated, html[1], `${lang}.json copies the English ${key}`);
        }
    }
});

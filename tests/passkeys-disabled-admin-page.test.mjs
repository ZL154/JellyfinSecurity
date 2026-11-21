// Run with Node.js 18+: node --test tests/passkeys-disabled-admin-page.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const pages = new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/', import.meta.url);
const read = name => readFileSync(new URL(name, pages), 'utf8');
const adminScript = read('admin-script.js');
const adminHtml = read('admin.html');
const LANGUAGES = ['de', 'en', 'es', 'fr', 'it', 'ja', 'pt', 'zh'];
const bundleText = Object.fromEntries(LANGUAGES.map(lang => [lang, read(`translations/${lang}.json`)]));
const bundles = Object.fromEntries(LANGUAGES.map(lang => [lang, JSON.parse(bundleText[lang])]));
const english = bundles.en;

const SERVER = 'https://jf.test';
const PLUGIN_ID = '94879a0c-da24-4eb1-aa06-f28b4b9333b1';
const CONFIG_URL = `${SERVER}/Plugins/${PLUGIN_ID}/Configuration`;
const HARDENING_URL = `${SERVER}/TwoFactorAuth/Admin/HardeningConfig`;
const PROOF_REQUIRED = {message: 'Step-up verification required.', stepUpRequired: true};
const REFUSED = 'tfa.admin.settings.passkeys_off_refused';

const settle = async () => { for (let i = 0; i < 50; i++) await new Promise(resolve => setImmediate(resolve)); };

// [#345] The whole admin script, loaded as the dashboard runs it, over a
// stand-in DOM and server. Every element the script looks up exists, keeps
// what the script writes, and logs innerHTML writes, so a test can tell text
// from markup. The server stores what a successful save sends; saveAnswers
// answer the configuration saves in order. language picks the bundle the
// page translates with (none: the script's English fallbacks).
function adminPage({config = {}, passkeyCount = 1, saveAnswers = [], language} = {}) {
    const elements = new Map();
    let settingsTab;
    const element = key => {
        if (elements.has(key)) return elements.get(key);
        const listeners = {};
        const classes = new Set();
        let html = '';
        const el = {
            key, style: {}, dataset: {}, value: '', checked: false, disabled: false, textContent: '', htmlWrites: [],
            get innerHTML() { return html; },
            set innerHTML(value) { html = String(value); el.htmlWrites.push(html); },
            classList: {add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c), toggle() {}},
            addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
            removeEventListener() {},
            querySelector: selector => element(selector),
            querySelectorAll: selector => selector === '.tfa-tab' ? [settingsTab] : [],
            setAttribute() {}, getAttribute: () => null, removeAttribute() {},
            appendChild() {}, remove() {}, focus() {}, closest: () => null,
            fire: type => Promise.all((listeners[type] || []).map(fn => fn.call(el, {target: el, preventDefault() {}}))),
        };
        elements.set(key, el);
        return el;
    };
    // The Settings tab, whose click loads the settings into the form.
    settingsTab = element('tab');
    settingsTab.dataset.tab = 'settings';

    let stored = structuredClone(config);
    const reads = {config: 0};
    const requests = [];
    const answer = (status, body) => ({
        ok: status >= 200 && status < 300, status,
        headers: {get: name => name.toLowerCase() === 'content-type' ? 'application/json; charset=utf-8' : null},
        json: async () => structuredClone(body),
        clone: () => answer(status, body),
    });
    const context = {
        console,
        setTimeout: () => 0,
        clearTimeout() {},
        document: {
            querySelector: selector => element(selector),
            querySelectorAll: () => [],
            getElementById: id => element('#' + id),
            addEventListener() {},
            createElement: tag => element('new:' + tag + ':' + elements.size),
            head: element('head'), body: element('body'),
        },
        ApiClient: {
            accessToken: () => 'test-token',
            serverAddress: () => SERVER,
            getUrl: path => `${SERVER}/${path}`,
            getPluginConfiguration: async id => {
                assert.equal(id, PLUGIN_ID);
                reads.config++;
                return structuredClone(stored);
            },
        },
        fetch: async (url, init = {}) => {
            const method = init.method || 'GET';
            const body = init.body === undefined ? undefined : JSON.parse(init.body);
            requests.push({url: String(url), method, body});
            if (url === CONFIG_URL && method === 'POST') {
                const next = saveAnswers.shift();
                assert(next, 'unexpected configuration save');
                if (next.status === 200) stored = body;
                return answer(next.status, next.body ?? {});
            }
            if (url === `${SERVER}/TwoFactorAuth/MyStatus`) return answer(200, {PasskeyCount: passkeyCount});
            if (url === `${SERVER}/TwoFactorAuth/StepUp/Verify` && method === 'POST') return answer(200, {});
            if (url === HARDENING_URL && method === 'POST') return answer(200, {});
            throw new Error(`unexpected request ${method} ${url}`);
        },
    };
    context.window = context;
    if (language) {
        context.tfaI18n = {tr: (key, fallback) => bundles[language][key] ?? fallback, proxyErrorMessage: () => ''};
    }
    runInNewContext(adminScript, context);
    const el = selector => element(selector);
    return {
        el, requests, reads,
        get stored() { return stored; },
        saves: () => requests.filter(r => r.url === CONFIG_URL),
        hardening: () => requests.filter(r => r.url === HARDENING_URL),
        async openSettings() { await settingsTab.fire('click'); await settle(); },
        async save() { await el('#btnSaveSettings').fire('click'); await settle(); },
    };
}

test('the switch loads checked unless the configuration says false', async () => {
    for (const [config, checked] of [[{}, true], [{PasskeysEnabled: true}, true], [{PasskeysEnabled: false}, false]]) {
        const p = adminPage({config});
        await p.openSettings();
        assert.equal(p.el('#cfgPasskeysEnabled').checked, checked, JSON.stringify(config));
    }
});

test('Save sends the switch as the box shows it', async () => {
    for (const checked of [true, false]) {
        const p = adminPage({config: {PasskeysEnabled: !checked}, saveAnswers: [{status: 200}]});
        p.el('#cfgPasskeysEnabled').checked = checked;
        await p.save();
        assert.equal(p.saves()[0].body.PasskeysEnabled, checked);
        assert.equal(p.el('#saveStatus').textContent, '✓ Saved');
    }
});

const DEPENDENTS = [
    {id: 'b3f1f3f0c2d94bd0a6a1e8a3f37a0d11', name: '<img src=x onerror=alert(1)>'},
    {id: '0c1b0f8e5d7a4e8c9a7f6b5d4c3b2a10', name: 'Zoe'},
];

test('a refused turn-off names the users as text and leaves the form as the admin left it', async () => {
    const p = adminPage({
        config: {PasskeysEnabled: true},
        saveAnswers: [{status: 409, body: {message: 'The server says no.', users: DEPENDENTS}}],
    });
    p.el('#cfgPasskeysEnabled').checked = false;
    await p.save();
    const box = p.el('#saveRefusal');
    assert.equal(box.style.display, '');
    assert.equal(box.textContent, english[REFUSED].split('{users}').join('<img src=x onerror=alert(1)>, Zoe'));
    assert.deepEqual(box.htmlWrites, [], 'the names never become markup');
    assert.equal(p.saves()[0].body.PasskeysEnabled, false);
    assert.equal(p.reads.config, 1, 'the configuration is not read back over the form');
    assert.equal(p.el('#cfgPasskeysEnabled').checked, false, 'the box stays as the admin set it');
    assert.equal(p.hardening().length, 0, 'nothing else is saved after a refusal');
    assert.equal(p.el('#saveStatus').textContent, '');
});

test('the refusal is built in the page language', async () => {
    const p = adminPage({config: {PasskeysEnabled: true}, saveAnswers: [{status: 409, body: {message: 'The server says no.', users: DEPENDENTS}}], language: 'pt'});
    p.el('#cfgPasskeysEnabled').checked = false;
    await p.save();
    assert.equal(p.el('#saveRefusal').textContent, bundles.pt[REFUSED].split('{users}').join('<img src=x onerror=alert(1)>, Zoe'));
});

test('a 409 without users shows the server message', async () => {
    const message = 'Passkeys cannot be disabled because these users rely on a passkey for their second factor: alice.';
    const p = adminPage({config: {PasskeysEnabled: true}, saveAnswers: [{status: 409, body: {message}}]});
    p.el('#cfgPasskeysEnabled').checked = false;
    await p.save();
    assert.equal(p.el('#saveRefusal').textContent, message);
    assert.equal(p.el('#saveRefusal').style.display, '');
    assert.equal(p.hardening().length, 0);
});

test('any other failure keeps the status line and leaves the refusal box hidden', async () => {
    const p = adminPage({config: {PasskeysEnabled: true}, saveAnswers: [{status: 500, body: {}}]});
    await p.save();
    assert.equal(p.el('#saveStatus').textContent, '✗ Save failed (HTTP 500)');
    assert.equal(p.el('#saveRefusal').style.display, 'none');
    assert.equal(p.hardening().length, 0);
    assert.equal(p.reads.config, 1);
});

test('the next Save takes an earlier refusal away', async () => {
    const p = adminPage({
        config: {PasskeysEnabled: true},
        saveAnswers: [{status: 409, body: {message: 'No.', users: DEPENDENTS}}, {status: 200}],
    });
    p.el('#cfgPasskeysEnabled').checked = false;
    await p.save();
    assert.equal(p.el('#saveRefusal').style.display, '');
    p.el('#cfgPasskeysEnabled').checked = true;
    await p.save();
    assert.equal(p.el('#saveRefusal').style.display, 'none');
    assert.equal(p.el('#saveRefusal').textContent, '');
    assert.equal(p.el('#saveStatus').textContent, '✓ Saved');
});

test('the step-up modal offers the passkey only for a saved passkey while passkeys are allowed', async () => {
    const cases = [
        [{PasskeysEnabled: true}, 1, true],
        [{}, 1, true],
        [{PasskeysEnabled: false}, 1, false],
        [{PasskeysEnabled: true}, 0, false],
    ];
    for (const [config, passkeyCount, offered] of cases) {
        const p = adminPage({config, passkeyCount, saveAnswers: [{status: 403, body: PROOF_REQUIRED}]});
        p.el('#cfgPasskeysEnabled').checked = config.PasskeysEnabled !== false;
        await p.save();
        assert.equal(p.el('#tfa-stepup-passkey').style.display, offered ? '' : 'none', JSON.stringify({config, passkeyCount}));
        await p.el('#tfa-stepup-cancel').fire('click');
        await settle();
        assert.equal(p.el('#saveStatus').textContent, '✗ Save failed (HTTP 403)', 'a cancelled prompt saves nothing');
    }
});

test('a save that succeeds makes the next prompt read the switch again', async () => {
    const p = adminPage({
        config: {PasskeysEnabled: true}, passkeyCount: 1,
        saveAnswers: [{status: 403, body: PROOF_REQUIRED}, {status: 200}, {status: 403, body: PROOF_REQUIRED}],
    });
    p.el('#cfgPasskeysEnabled').checked = false;
    await p.save();
    assert.equal(p.el('#tfa-stepup-passkey').style.display, '', 'passkeys were still allowed when the prompt opened');
    p.el('#tfa-stepup-code').value = '123456';
    await p.el('#tfa-stepup-submit').fire('click');
    await settle();
    assert.equal(p.stored.PasskeysEnabled, false);
    assert.equal(p.el('#saveStatus').textContent, '✓ Saved');
    await p.save();
    assert.equal(p.el('#tfa-stepup-passkey').style.display, 'none', 'the modal follows the saved switch without a reload');
});

test('the switch sits next to the email code option and the hide-button help points to it', () => {
    const at = id => adminHtml.indexOf(`id="${id}"`);
    assert(at('cfgEmailOtp') > 0 && at('cfgPasskeysEnabled') > at('cfgEmailOtp'));
    assert(at('cfgPasskeysEnabled') < at('cfgSendSignInCodeToApps'), 'right after the email code option');
    assert(at('saveRefusal') > at('saveStatus'), 'the refusal shows under Save Settings');
    assert.match(adminHtml, /<div id="saveRefusal" role="alert" style="display:none;/);
    for (const lang of LANGUAGES) {
        assert(bundles[lang]['tfa.admin.hardening.hide_builtin_passkey_help'].includes(bundles[lang]['tfa.admin.settings.opt_passkeys_enabled']),
            `${lang}: the hide-button help names the switch as the page labels it`);
    }
});

test('every new string has its English text in en.json and a translation in all eight bundles', () => {
    const fromHtml = key => new RegExp(`data-i18n-key="${key.replace(/\./g, '\\.')}"[^>]*>([^<]*)<`).exec(adminHtml)?.[1];
    const fromScript = key => new RegExp(`_tr\\('${key.replace(/\./g, '\\.')}', '((?:[^'\\\\]|\\\\.)*)'\\)`).exec(adminScript)?.[1].replace(/\\'/g, '\'');
    const keys = {
        'tfa.admin.settings.opt_passkeys_enabled': fromHtml,
        'tfa.admin.settings.passkeys_enabled_help': fromHtml,
        'tfa.admin.hardening.hide_builtin_passkey_help': fromHtml,
        [REFUSED]: fromScript,
    };
    for (const [key, source] of Object.entries(keys)) {
        const text = source(key);
        assert(text, `the page must carry ${key}`);
        assert.equal(english[key], text, `en.json must hold the page's English text for ${key}`);
        for (const lang of LANGUAGES) {
            assert.equal(bundleText[lang].split(`"${key}":`).length - 1, 1, `${lang}.json must hold ${key} exactly once`);
            if (lang === 'en') continue;
            assert.equal(typeof bundles[lang][key], 'string', `${lang}.json must translate ${key}`);
            assert.notEqual(bundles[lang][key].trim(), '', `${lang}.json has an empty ${key}`);
            assert.notEqual(bundles[lang][key], text, `${lang}.json copies the English ${key}`);
        }
    }
    for (const lang of LANGUAGES) {
        const refused = bundles[lang][REFUSED];
        assert.equal(refused.split('{users}').length - 1, 1, `${lang}: one {users} placeholder`);
        assert(refused.includes(bundles[lang]['tfa.admin.users.bulk_reset_2fa']), `${lang}: names the Users tab action as the page labels it`);
        assert(refused.includes(bundles[lang]['tfa.admin.tab_users']), `${lang}: names the Users tab as the page labels it`);
    }
});

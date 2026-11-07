// Run with Node.js 18+: node --test tests/login-button.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const inject = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/inject.js', import.meta.url), 'utf8');
const pageFunction = name => {
    const found = inject.match(new RegExp(`\\n( *)function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\1\\}`))?.[0];
    assert(found, `inject.js must define ${name}()`);
    return found;
};
const source = pageFunction('addLoginButton');
// [#345] The passkey button as inject.js inserts it, so a test sees whether
// the button is on the page, not only whether a stub was called.
const passkeyButtonSource = pageFunction('addPasskeyButton');

const ORIGIN = 'https://jellyfin.example.test';
const PASSKEY_BUTTON_ID = '__twofactor_passkey_btn';

// A minimal DOM that upgrades elements the way jellyfin-web's emby-button.js
// does: an inserted <a is="emby-linkbutton"> gains the emby-button class and a
// click listener that hands its href to appRouter.show unless it is "#".
function createPage({tv = false, username = '', cfg = {}, existingPasskeyButton = false} = {}) {
    const routed = [];
    const assigned = [];
    const children = [];
    function element(tag) {
        const attributes = new Map();
        const classes = new Set();
        const listeners = [];
        const el = {
            tagName: tag.toUpperCase(), id: '', innerHTML: '', parentNode: null, nextSibling: null, value: '', style: {},
            get className() { return [...classes].join(' '); },
            set className(value) { classes.clear(); String(value).split(/\s+/).filter(Boolean).forEach(c => classes.add(c)); },
            classList: {
                add: c => classes.add(c),
                contains: c => classes.has(c),
            },
            get href() { return attributes.get('href') ?? ''; },
            set href(value) { attributes.set('href', String(value)); },
            setAttribute: (name, value) => attributes.set(name, String(value)),
            getAttribute: name => attributes.get(name) ?? null,
            addEventListener: (type, fn) => listeners.push({type, fn}),
            click() {
                const event = {defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
                listeners.filter(l => l.type === 'click').forEach(l => l.fn.call(el, event));
                if (!event.defaultPrevented) assigned.push(el.href);
            },
            remove() {
                const at = children.indexOf(el);
                if (at >= 0) children.splice(at, 1);
                el.parentNode = null;
            },
        };
        return el;
    }
    function upgrade(el) {
        if (el.getAttribute('is') !== 'emby-linkbutton') return;
        el.classList.add('emby-button');
        if (tv) el.classList.add('show-focus');
        el.addEventListener('click', function (e) {
            const href = this.getAttribute('href') || '';
            e.preventDefault();
            if (href !== '#') routed.push(href);
        });
    }
    const signIn = element('button');
    signIn.className = 'raised button-submit block emby-button';
    const userInput = element('input');
    userInput.value = username;
    const form = element('div');
    children.push(signIn);
    form.appendChild = child => { children.push(child); child.parentNode = form; upgrade(child); };
    form.insertBefore = (child, before) => { children.splice(children.indexOf(before), 0, child); child.parentNode = form; upgrade(child); };
    signIn.parentNode = form;
    if (existingPasskeyButton) {
        // A passkey button already on the page from an earlier pass.
        const earlier = element('a');
        earlier.id = PASSKEY_BUTTON_ID;
        form.appendChild(earlier);
    }
    const htmlClasses = new Set(tv ? ['layout-tv'] : ['layout-desktop']);
    const document = {
        documentElement: {classList: {contains: c => htmlClasses.has(c)}},
        createElement: element,
        getElementById: id => children.find(c => c.id === id) ?? null,
        querySelector: selector => (/submit|\.raised/.test(selector) ? signIn : selector.includes('#txtManualName') ? userInput : null),
    };
    const context = {
        document,
        window: {location: {assign: url => assigned.push(url)}, isSecureContext: true, PublicKeyCredential: function () {}},
        BUTTON_ID: '__twofactor_login_btn',
        _tfaPublicCfg: {hideBuiltInTwoFactorButton: false, hideBuiltInPasskeyButton: true, ...cfg},
        isLoginPage: () => true,
        fetchTfaPublicConfig() {}, applyPasswordLoginGate() {}, addForgotPasswordLink() {},
        hideNativeForgotPassword() {}, hideForgotPasswordWhenNoPassword() {},
        addStyles() {}, repositionLinksBelowQuickConnect() {},
        T: (key, fallback) => fallback,
        withLang: url => url + (url.includes('?') ? '&' : '?') + 'lang=fr',
        serverUrl: path => ORIGIN + '/' + path,
        findUsername: () => userInput.value,
    };
    runInNewContext(`${source}\n${passkeyButtonSource}\naddLoginButton();`, context);
    const button = document.getElementById('__twofactor_login_btn');
    assert(button, 'addLoginButton must insert the 2FA button');
    return {button, routed, assigned, passkeyButton: document.getElementById(PASSKEY_BUTTON_ID)};
}

for (const username of ['', 'admin']) {
    const portal = ORIGIN + '/TwoFactorAuth/Login' + (username ? '?username=' + username + '&lang=fr' : '?lang=fr');

    test(`the 2FA button opens the portal without jellyfin-web's router (username "${username}")`, () => {
        const {button, routed, assigned} = createPage({username});
        button.click();
        assert.deepEqual(routed, [], 'the hash router must never see the portal URL');
        assert.deepEqual(assigned, [portal]);
    });
}

test('the 2FA button keeps the classes that render it like the sign-in button', () => {
    const {button} = createPage();
    assert.equal(button.getAttribute('is'), null);
    assert.equal(button.className, 'raised block emby-button');
});

test('the 2FA button keeps the TV focus style in the TV layout', () => {
    const {button} = createPage({tv: true});
    assert.equal(button.getAttribute('is'), null);
    assert.equal(button.className, 'raised block emby-button show-focus');
});

// [#345] public-config says whether the server allows passkeys. While it says
// they are off, the login page has no passkey button, whatever the separate
// "hide the passkey button" option says. A missing field (an older server, or
// public-config not read) keeps the button; the server refuses passkey
// sign-in while passkeys are off either way.
for (const [what, cfg] of [['true', {passkeysEnabled: true}], ['missing', {}]]) {
    test(`the passkey button is on the login page when passkeysEnabled is ${what}`, () => {
        const {passkeyButton} = createPage({cfg: {hideBuiltInPasskeyButton: false, ...cfg}});
        assert(passkeyButton, 'the passkey button must be inserted');
        assert.match(passkeyButton.innerHTML, /data-i18n-key="tfa\.login\.btn_passkey"/);
    });
}

test('the passkey button is left out, or taken away, while passkeys are off on the server', () => {
    for (const existingPasskeyButton of [false, true]) {
        const {button, passkeyButton} = createPage({
            cfg: {hideBuiltInPasskeyButton: false, passkeysEnabled: false}, existingPasskeyButton,
        });
        assert.equal(passkeyButton, null, existingPasskeyButton ? 'the earlier button must be removed' : 'no button may be inserted');
        assert(button, 'the 2FA button stays');
    }
});

test('hiding the passkey button still hides it while passkeys are on', () => {
    const {passkeyButton} = createPage({cfg: {hideBuiltInPasskeyButton: true, passkeysEnabled: true}});
    assert.equal(passkeyButton, null);
});

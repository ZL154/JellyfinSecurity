// Run with Node.js 18+: node --test tests/login-button.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const inject = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/inject.js', import.meta.url), 'utf8');
const source = inject.match(/\n( *)function addLoginButton\(\) \{[\s\S]*?\n\1\}/)?.[0];
assert(source, 'inject.js must define addLoginButton()');

const ORIGIN = 'https://jellyfin.example.test';

// A minimal DOM that upgrades elements the way jellyfin-web's emby-button.js
// does: an inserted <a is="emby-linkbutton"> gains the emby-button class and a
// click listener that hands its href to appRouter.show unless it is "#".
function createPage({tv = false, username = ''} = {}) {
    const routed = [];
    const assigned = [];
    function element(tag) {
        const attributes = new Map();
        const classes = new Set();
        const listeners = [];
        const el = {
            tagName: tag.toUpperCase(), id: '', innerHTML: '', parentNode: null, nextSibling: null, value: '',
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
            remove() {},
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
    const children = [signIn];
    form.appendChild = child => { children.push(child); child.parentNode = form; upgrade(child); };
    form.insertBefore = (child, before) => { children.splice(children.indexOf(before), 0, child); child.parentNode = form; upgrade(child); };
    signIn.parentNode = form;
    const htmlClasses = new Set(tv ? ['layout-tv'] : ['layout-desktop']);
    const document = {
        documentElement: {classList: {contains: c => htmlClasses.has(c)}},
        createElement: element,
        getElementById: id => children.find(c => c.id === id) ?? null,
        querySelector: selector => (/submit|\.raised/.test(selector) ? signIn : selector.includes('#txtManualName') ? userInput : null),
    };
    const context = {
        document,
        window: {location: {assign: url => assigned.push(url)}},
        BUTTON_ID: '__twofactor_login_btn',
        _tfaPublicCfg: {hideBuiltInTwoFactorButton: false, hideBuiltInPasskeyButton: true},
        isLoginPage: () => true,
        fetchTfaPublicConfig() {}, applyPasswordLoginGate() {}, addForgotPasswordLink() {},
        hideNativeForgotPassword() {}, hideForgotPasswordWhenNoPassword() {},
        addStyles() {}, addPasskeyButton() {}, repositionLinksBelowQuickConnect() {},
        T: (key, fallback) => fallback,
        withLang: url => url + (url.includes('?') ? '&' : '?') + 'lang=fr',
        serverUrl: path => ORIGIN + '/' + path,
        findUsername: () => userInput.value,
    };
    runInNewContext(`${source}\naddLoginButton();`, context);
    const button = document.getElementById('__twofactor_login_btn');
    assert(button, 'addLoginButton must insert the 2FA button');
    return {button, routed, assigned};
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

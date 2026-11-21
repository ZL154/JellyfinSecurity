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

// Run the injected bootstrap before DOMContentLoaded, when Jellyfin can already receive a 403.
function challengedBrowser({mount = '/jellyfin', apiReady = false, pluginPage = false,
    session = new Map(), servers = [], native = false, logout, client = {}, apiOrigin = ORIGIN,
    webRoute = '/web/index.html', response = () => Response.json({twoFactorRequired: true}, {status: 403})} = {}) {
    const navigations = [];
    const sessionStorage = {
        getItem: key => session.get(key) ?? null,
        setItem: (key, value) => session.set(key, value),
        removeItem: key => session.delete(key),
    };
    const context = {
        URL, Response, Request, Headers, navigator: {userAgent: 'Firefox'}, console: {log() {}},
        document: {readyState: 'loading', addEventListener() {}},
        location: {origin: ORIGIN, pathname: mount + (pluginPage ? '/TwoFactorAuth/Login' : webRoute),
            hash: '#/home', set href(url) { navigations.push(url); }},
        sessionStorage,
        localStorage: {getItem: key => key === 'jellyfin_credentials' ? JSON.stringify({Servers: servers}) : null},
        XMLHttpRequest: class {
            open() {} setRequestHeader() {}
            listeners = new Set();
            addEventListener(name, fn) { this.listeners.add(fn); }
            removeEventListener(name, fn) { this.listeners.delete(fn); }
            send() {
                Object.assign(this, {readyState: 4, status: this.fixtureStatus || 403, responseText: '{"twoFactorRequired":true}'});
                for (const listener of this.listeners) listener();
            }
        },
        ApiClient: client === null ? undefined : {logout, ...client},
        fetch: async (input, init) => response(input, init),
    };
    context.window = context;
    if (apiReady) context.ApiClient.getUrl = path => apiOrigin + mount + '/' + path;
    if (native) context.NativeShell = {};
    runInNewContext(inject, context);
    return {session, navigations,
        challenge: (init, url = mount + '/DisplayPreferences/usersettings') => context.fetch(url, init),
        xhrChallenge(headers, xhr = new context.XMLHttpRequest(), status = 403) {
            xhr.fixtureStatus = status;
            xhr.open('GET', mount + '/DisplayPreferences/usersettings');
            for (const [key, value] of Object.entries(headers)) xhr.setRequestHeader(key, value);
            xhr.send();
            return xhr;
        },
    };
}

for (const mount of ['', '/jellyfin', '/webmedia', '/TwoFactorAuthLab', '/TwoFactorAuth/site', '/web/site', '/web/TwoFactorAuth/site']) {
    for (const apiReady of [false, true]) {
        test(`challenged browser preserves mount ${mount || '/'} with ${apiReady ? 'initialized' : 'early'} client`, async () => {
            const page = challengedBrowser({mount, apiReady});
            await page.challenge();
            assert.deepEqual(page.navigations, [(apiReady ? ORIGIN : '') + mount + '/TwoFactorAuth/Login']);
            const portal = challengedBrowser({mount, apiReady, pluginPage: true});
            await portal.challenge();
            assert.deepEqual(portal.navigations, []);
        });
    }
}

for (const webRoute of ['/web', '/web/', '/WEB/index.HTML///']) {
    test(`a terminal ${webRoute} route preserves a mount containing both route names`, async () => {
        const mount = '/TwoFactorAuth/web/site';
        const page = challengedBrowser({mount, webRoute});
        await page.challenge();
        assert.deepEqual(page.navigations, [mount + '/TwoFactorAuth/Login']);
    });
}

const portalKey = '__tfa_portal_recovery';
const activeServer = {Id: 'active', UserId: 'alice', AccessToken: 'fixture-active-01234567', DateLastAccessed: 20};
const olderServer = {Id: 'older', UserId: 'bob', AccessToken: 'fixture-older-98765432', DateLastAccessed: 10};

const automaticPortal = '/jellyfin/TwoFactorAuth/Login#tfa-recovery';
const apiIdentity = server => ({
    serverId: () => server.Id, getCurrentUserId: () => server.UserId, accessToken: () => server.AccessToken,
});

for (const transport of ['fetch', 'XHR']) {
    test(`a server 403 over ${transport} marks the only saved session matching the client`, async () => {
        const page = challengedBrowser({servers: [activeServer], client: apiIdentity(activeServer)});
        const start = Date.now();
        if (transport === 'fetch') await Promise.all([page.challenge(), page.challenge()]);
        else page.xhrChallenge({});
        assert.deepEqual(page.navigations, [automaticPortal]);
        const raw = page.session.get(portalKey);
        const mark = JSON.parse(raw);
        assert.ok(mark.at >= start && mark.at <= Date.now() && Number.isInteger(mark.at));
        assert.deepEqual(mark, {at: mark.at, server: activeServer.Id, user: activeServer.UserId, tokenTail: '01234567'});
        assert.ok(!raw.includes(activeServer.AccessToken));
    });
}

for (const [reason, servers, client] of [
    ['two saved servers', [activeServer, olderServer], apiIdentity(activeServer)],
    ['another signed-out server', [activeServer, {...olderServer, AccessToken: '', UserId: ''}], apiIdentity(activeServer)],
    ['no servers', [], apiIdentity(activeServer)],
    ['missing client', [activeServer], null],
    ['incomplete client', [activeServer], {accessToken: () => activeServer.AccessToken}],
    ['server mismatch', [activeServer], apiIdentity({...activeServer, Id: 'other'})],
    ['user mismatch', [activeServer], apiIdentity({...activeServer, UserId: 'other'})],
    ['token mismatch', [activeServer], apiIdentity({...activeServer, AccessToken: 'other-token-' + activeServer.AccessToken.slice(-8)})],
    ['empty user', [{...activeServer, UserId: ''}], apiIdentity({...activeServer, UserId: ''})],
    ['exactly eight token characters', [{...activeServer, AccessToken: '12345678'}], apiIdentity({...activeServer, AccessToken: '12345678'})],
]) {
    test(`a server 403 opens the plain portal on ${reason}`, async () => {
        const page = challengedBrowser({servers, client, session: new Map([[portalKey, 'stale']])});
        await page.challenge({headers: {'X-Emby-Token': activeServer.AccessToken}});
        assert.equal(page.session.has(portalKey), false);
        assert.deepEqual(page.navigations, ['/jellyfin/TwoFactorAuth/Login']);
    });
}

test('a silently ignored marker write leaves the portal URL plain', async () => {
    const session = new Map();
    session.set = () => session;
    const page = challengedBrowser({servers: [activeServer], client: apiIdentity(activeServer), session});
    await page.challenge();
    assert.deepEqual(page.navigations, ['/jellyfin/TwoFactorAuth/Login']);
});

test('a separate-origin automatic navigation leaves no marker on the source tab', async () => {
    const page = challengedBrowser({servers: [activeServer], client: apiIdentity(activeServer), apiReady: true,
        apiOrigin: 'https://server.example.test', session: new Map([[portalKey, 'stale']])});
    await page.challenge();
    assert.equal(page.session.has(portalKey), false);
    assert.deepEqual(page.navigations, ['https://server.example.test/jellyfin/TwoFactorAuth/Login']);
});

test('a local pending block discards a stranded marker and keeps the new session out of recovery', async () => {
    const session = new Map([['__tfa_pending', String(Date.now())], [portalKey, 'old']]);
    const page = challengedBrowser({servers: [activeServer], client: apiIdentity(activeServer), session,
        response: () => assert.fail('pending request reached the network')});
    const reply = await page.challenge();
    assert.equal((await reply.json())._tfaShortCircuit, true);
    assert.equal(session.has(portalKey), false);
    assert.deepEqual(page.navigations, ['/jellyfin/TwoFactorAuth/Login']);
});

for (const transport of ['fetch', 'XHR']) {
    test(`a non-auth 401 over ${transport} only opens the plain portal`, async () => {
        const page = challengedBrowser({servers: [activeServer], client: apiIdentity(activeServer),
            response: () => Response.json({twoFactorRequired: true}, {status: 401})});
        if (transport === 'fetch') await page.challenge();
        else page.xhrChallenge({}, undefined, 401);
        assert.equal(page.session.has(portalKey), false);
        assert.deepEqual(page.navigations, ['/jellyfin/TwoFactorAuth/Login']);
    });
}

test('one-pass headers, Request headers and Request overrides reach native fetch intact', async () => {
    const received = [];
    const page = challengedBrowser({response: (input, init) => {
        const request = new Request(typeof input === 'string' ? new URL(input, ORIGIN) : input, init);
        received.push([...request.headers]);
        return Response.json({});
    }});
    const pairs = [['x-first', 'alpha'], ['x-second', 'beta']];
    const input = new Request(ORIGIN + '/items', {headers: {'x-original': 'present'}});
    await page.challenge({headers: pairs.values()});
    await page.challenge(undefined, input);
    await page.challenge({headers: pairs.values()}, input);
    assert.deepEqual(received, [pairs, [['x-original', 'present']], pairs]);
});

test('embedded logout still completes before opening the stock picker without a portal marker', async () => {
    let release;
    const page = challengedBrowser({servers: [activeServer], native: true, logout: () => new Promise(r => { release = r; })});
    await page.challenge();
    assert.deepEqual(page.navigations, []);
    release();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(page.navigations, ['/jellyfin/web/index.html#/login']);
    assert.equal(page.session.has(portalKey), false);
});

test('embedded client without logout opens the portal without marking a session', async () => {
    const page = challengedBrowser({servers: [activeServer], native: true});
    await page.challenge();
    assert.deepEqual(page.navigations, ['/jellyfin/TwoFactorAuth/Login']);
    assert.equal(page.session.has(portalKey), false);
});

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
        ApiClient: {logout, ...client},
        fetch: async () => response(),
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

for (const [reason, time] of [['older', 10], ['tied', 20]]) {
    for (const source of ['request', 'client', 'both']) {
        test(`the ${reason} session is selected by ${source} identity even when listed second`, async () => {
            const server = {...olderServer, DateLastAccessed: time};
            const page = challengedBrowser({servers: [activeServer, null, server],
                client: source === 'request' ? {} : apiIdentity(server)});
            const init = source === 'client' ? undefined : {headers: {Authorization: 'MediaBrowser Token="' + server.AccessToken + '"'}};
            const start = Date.now();
            await Promise.all([page.challenge(init), page.challenge(init)]);
            assert.deepEqual(page.navigations, [automaticPortal]);
            const raw = page.session.get(portalKey);
            const mark = JSON.parse(raw);
            assert.ok(Number.isInteger(mark.at) && mark.at >= start && mark.at <= Date.now());
            assert.deepEqual(mark, {at: mark.at, server: 'older', user: 'bob', tokenTail: '98765432'});
            assert.ok(!raw.includes(server.AccessToken));
        });
    }
}

for (const [reason, servers, client, token] of [
    ['empty store', [], {}, olderServer.AccessToken],
    ['missing identity', [olderServer, activeServer], {}, null],
    ['short token', [{...olderServer, AccessToken: 'short'}], {}, 'short'],
    ['exactly eight characters', [{...olderServer, AccessToken: '12345678'}], {}, '12345678'],
    ['no matching token', [activeServer], {}, olderServer.AccessToken],
    ['token reused by two entries', [olderServer, {...activeServer, AccessToken: olderServer.AccessToken}], {}, olderServer.AccessToken],
    ['request and client disagree', [olderServer, activeServer], apiIdentity(activeServer), olderServer.AccessToken],
    ['client user disagrees', [olderServer], apiIdentity({...olderServer, UserId: 'different'}), null],
]) {
    test(`browser drops a stale marker on ${reason}`, async () => {
        const page = challengedBrowser({servers, client, session: new Map([[portalKey, 'stale']])});
        await page.challenge(token ? {headers: {'X-Emby-Token': token}} : undefined);
        assert.equal(page.session.has(portalKey), false);
        assert.deepEqual(page.navigations, ['/jellyfin/TwoFactorAuth/Login']);
    });
}

test('a separate-origin automatic navigation leaves no marker on the source tab', async () => {
    const page = challengedBrowser({servers: [activeServer], client: apiIdentity(activeServer), apiReady: true,
        apiOrigin: 'https://server.example.test', session: new Map([[portalKey, 'stale']])});
    await page.challenge();
    assert.equal(page.session.has(portalKey), false);
    assert.deepEqual(page.navigations, ['https://server.example.test/jellyfin/TwoFactorAuth/Login']);
});

test('a delayed 403 uses the fetch headers dispatched before the caller modified them', async () => {
    let answer;
    const page = challengedBrowser({servers: [activeServer, olderServer], response: () => new Promise(r => { answer = r; })});
    const headers = new Headers({'X-Emby-Token': olderServer.AccessToken});
    const request = page.challenge({headers});
    headers.set('X-Emby-Token', activeServer.AccessToken);
    answer(Response.json({twoFactorRequired: true}, {status: 403}));
    await request;
    assert.equal(JSON.parse(page.session.get(portalKey)).server, olderServer.Id);
});

test('the pending gate uses the actual Request token and respects overriding init headers', async () => {
    for (const override of [false, true]) {
        const session = new Map([['__tfa_pending', String(Date.now())]]);
        const page = challengedBrowser({servers: [activeServer, olderServer], session});
        const input = new Request(ORIGIN + '/jellyfin/Users/Me', {headers: {Authorization: 'Bearer ' + olderServer.AccessToken}});
        const reply = await page.challenge(override ? {headers: {'X-Emby-Token': activeServer.AccessToken}} : undefined, input);
        assert.equal((await reply.json())._tfaShortCircuit, true);
        assert.equal(JSON.parse(session.get(portalKey)).server, override ? activeServer.Id : olderServer.Id);
    }
});

test('XHR challenge uses the token sent in its headers', () => {
    const page = challengedBrowser({servers: [activeServer, olderServer]});
    page.xhrChallenge({'X-Emby-Authorization': 'MediaBrowser Client="Web", Token="' + olderServer.AccessToken + '"'});
    assert.equal(JSON.parse(page.session.get(portalKey)).server, olderServer.Id);
});

test('a reused XHR identifies the challenged send even after an earlier successful request', () => {
    const page = challengedBrowser({servers: [activeServer, olderServer]});
    const xhr = page.xhrChallenge({'X-Emby-Token': activeServer.AccessToken}, undefined, 200);
    page.xhrChallenge({'X-Emby-Token': olderServer.AccessToken}, xhr);
    assert.equal(JSON.parse(page.session.get(portalKey)).server, olderServer.Id);
});

test('a request with a query token requires an exact saved match', async () => {
    const page = challengedBrowser({servers: [activeServer, olderServer]});
    await page.challenge(undefined, '/jellyfin/socket?api_key=' + olderServer.AccessToken);
    assert.equal(JSON.parse(page.session.get(portalKey)).server, olderServer.Id);
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

test('two saved tokens with the same marker tuple cannot be distinguished on the portal', async () => {
    const duplicateTail = {...olderServer, AccessToken: 'second-token-' + olderServer.AccessToken.slice(-8)};
    const page = challengedBrowser({servers: [olderServer, duplicateTail]});
    await page.challenge({headers: {'X-Emby-Token': olderServer.AccessToken}});
    assert.equal(page.session.has(portalKey), false);
});

test('multiple differing tokens in an authorization header leave the form available', async () => {
    const page = challengedBrowser({servers: [olderServer, activeServer]});
    await page.challenge({headers: {Authorization:
        'MediaBrowser Token="' + olderServer.AccessToken + '", Token="' + activeServer.AccessToken + '"'}});
    assert.equal(page.session.has(portalKey), false);
});

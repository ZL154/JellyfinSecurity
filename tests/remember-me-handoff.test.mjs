// Run with Node.js 18+: node --test tests/remember-me-handoff.test.mjs
//
// Jellyfin Web's "Remember Me" box, left unticked once, stores
// localStorage['enableAutoLogin'] = 'false', and every later page load drops
// the stored access token before connecting. The plugin's sign-in pages hand
// the session over by storing it and loading /web, so they mark the hand-off
// with the session they stored, and inject.js keeps that one session signed
// in for one load.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const pages = new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/', import.meta.url);
const read = name => readFileSync(new URL(name, pages), 'utf8');
const inject = read('inject.js');

// A function as the file defines it, from its first line to the closing brace
// at the same indentation.
function definition(source, name) {
    const found = source.match(new RegExp(`\\n( *)function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\1\\}`));
    assert(found, `${name} must be defined`);
    return found[0].trim();
}

const handoffKey = inject.match(/var TFA_HANDOFF_KEY = '([^']+)';/)?.[1];
const ttlMs = 10 * 60 * 1000;
const tokenTail = 8;
const now = 1_800_000_000_000;

class FakeStorage {
    constructor(entries = {}) { this.items = new Map(Object.entries(entries)); }
    getItem(key) { return this.items.has(key) ? this.items.get(key) : null; }
    setItem(key, value) { this.items.set(key, String(value)); }
    removeItem(key) { this.items.delete(key); }
}

function credentials(...servers) {
    return JSON.stringify({Servers: servers});
}
// The server entry a hand-off stores, as the pages write it.
const entry = (at = now, changes = {}) => ({
    Id: 'test-server', UserId: 'test-user-id', AccessToken: 'test-access-token-0001', DateLastAccessed: at, ...changes,
});
const handedOver = (at = now) => credentials(entry(at));

// The marker the real login.html leaves when it hands `stored` over at `at`,
// so these tests check what the pages write against what inject.js accepts.
function marker(at = now, stored = entry(at)) {
    const session = new FakeStorage();
    const clear = runInNewContext(`(${definition(read('login.html'), 'clearTfaClientState')})`,
        {sessionStorage: session, localStorage: new FakeStorage(), String, JSON, Date: {now: () => at}});
    clear(stored);
    return Object.fromEntries(session.items);
}

// Runs honorSessionHandoff on a fresh Storage prototype, the way inject.js
// runs it when the page loads. route.login says whether Jellyfin Web is on
// its login route when it reads.
function load(local, session, route = {login: false}) {
    const proto = Object.create(FakeStorage.prototype);
    Object.setPrototypeOf(local, proto);
    Object.setPrototypeOf(session, proto);
    // The helpers are checked on their own below, so a version without them still
    // runs here and fails on what it accepts.
    const helpers = ['isWholeNumber', 'isFilledString']
        .filter(name => new RegExp(`\\n *function ${name}\\(`).test(inject))
        .map(name => definition(inject, name)).join('\n');
    const honor = runInNewContext(`var TFA_HANDOFF_KEY = ${JSON.stringify(handoffKey)}, TFA_HANDOFF_TTL_MS = ${ttlMs}, TFA_HANDOFF_TOKEN_TAIL = ${tokenTail};\n`
        + `${helpers}\n(${definition(inject, 'honorSessionHandoff')})`);
    return honor(proto, local, session, () => route.login, now);
}

function storages(localEntries, sessionEntries) {
    return {local: new FakeStorage(localEntries), session: new FakeStorage(sessionEntries)};
}
const rememberOff = () => ({enableAutoLogin: 'false', jellyfin_credentials: handedOver()});
const rememberOffWith = (...servers) => ({enableAutoLogin: 'false', jellyfin_credentials: credentials(...servers)});

test('inject.js names the hand-off marker and its lifetime', () => {
    assert.equal(handoffKey, '__tfa_session_handoff');
    assert.match(inject, /var TFA_HANDOFF_TTL_MS = 10 \* 60 \* 1000;/);
    assert.match(inject, /var TFA_HANDOFF_TOKEN_TAIL = 8;/);
    definition(inject, 'isWholeNumber');
    definition(inject, 'isFilledString');
});

test('a handed-over load answers Jellyfin Web\'s Remember Me reads with true', () => {
    const {local, session} = storages(rememberOff(), marker());
    assert.equal(load(local, session), true);
    assert.equal(local.getItem('enableAutoLogin'), 'true');
    assert.equal(local.items.get('enableAutoLogin'), 'false', 'the stored setting must not change');
    assert.equal(session.getItem(handoffKey), null, 'the marker is spent by the load it was left for');
});

test('the next full load signs out again, as Remember Me off asks', () => {
    const {local, session} = storages(rememberOff(), marker());
    load(local, session);
    const next = storages(Object.fromEntries(local.items), Object.fromEntries(session.items));
    assert.equal(load(next.local, next.session), false);
    assert.equal(next.local.getItem('enableAutoLogin'), 'false');
});

test('once Jellyfin Web shows its login form, the box shows the stored choice again', () => {
    const route = {login: false};
    const {local, session} = storages(rememberOff(), marker());
    load(local, session, route);
    assert.equal(local.getItem('enableAutoLogin'), 'true', 'startup reads keep the session');
    route.login = true;
    assert.equal(local.getItem('enableAutoLogin'), 'false', 'the login form must read the user\'s own choice');
    route.login = false;
    assert.equal(local.getItem('enableAutoLogin'), 'false', 'and the exception does not come back on this page');
});

test('a marker older than its lifetime, or from the future, changes nothing', () => {
    for (const at of [now - ttlMs - 1, now + 1000]) {
        const {local, session} = storages({enableAutoLogin: 'false', jellyfin_credentials: handedOver(at)}, marker(at));
        assert.equal(load(local, session), false);
        assert.equal(local.getItem('enableAutoLogin'), 'false');
        assert.equal(session.getItem(handoffKey), null);
    }
});

// Jellyfin Web connects to the server entry it accessed last. Another tab of
// this origin can store a different session there while the hand-off is on
// its way to /web, even a second later; only the session the hand-off stored
// may be kept.
// Each case changes one part of what the hand-off stored, so each part of the
// marker is checked on its own.
const handedAt = now - 2000;
const laterSessions = {
    'another server entry, a second later': [entry(handedAt), entry(handedAt + 1000, {Id: 'other-server'})],
    'another server entry, a minute later': [entry(handedAt), entry(handedAt + 60_000, {Id: 'other-server'})],
    'another token for the same entry, a second later': [entry(handedAt + 1000, {AccessToken: 'test-access-token-0002'})],
    'another user on the same entry, a second later': [entry(handedAt + 1000, {UserId: 'other-user-id'})],
};
for (const [name, servers] of Object.entries(laterSessions)) {
    test(`a session stored after the hand-off is not kept: ${name}`, () => {
        const {local, session} = storages(rememberOffWith(...servers), marker(handedAt));
        assert.equal(load(local, session), false);
        assert.equal(local.getItem('enableAutoLogin'), 'false');
    });
}

test('the session the hand-off stored is kept even when Jellyfin Web touched it since', () => {
    const {local, session} = storages(rememberOffWith(entry(now)), marker(now - 3 * 60_000, entry(now - 3 * 60_000)));
    assert.equal(load(local, session), true);
    assert.equal(local.getItem('enableAutoLogin'), 'true');
});

test('a marker time that is not a whole number is refused', () => {
    const good = marker();
    const spoiled = changes => ({[handoffKey]: JSON.stringify({...JSON.parse(good[handoffKey]), ...changes})});
    const markers = {
        'time with trailing text': spoiled({at: `${now}garbage`}),
        'time as a string': spoiled({at: String(now)}),
        'fractional time': spoiled({at: now - 0.5}),
        'old plain-time marker': {[handoffKey]: String(now)},
        'not JSON': {[handoffKey]: `${now}garbage`},
    };
    for (const [name, value] of Object.entries(markers)) {
        const {local, session} = storages(rememberOff(), value);
        assert.equal(load(local, session), false, name);
        assert.equal(session.getItem(handoffKey), null, name);
    }
});

test('a DateLastAccessed that is not a whole number is refused', () => {
    for (const accessed of ['garbage', `${now}`, now + 0.5]) {
        const {local, session} = storages(rememberOffWith(entry(now, {DateLastAccessed: accessed})), marker());
        assert.equal(load(local, session), false, `DateLastAccessed ${String(accessed)}`);
    }
    // JSON has no Infinity, but JSON.parse reads 1e400 as one.
    const huge = rememberOffWith(entry(now, {DateLastAccessed: 0}));
    huge.jellyfin_credentials = huge.jellyfin_credentials.replace('"DateLastAccessed":0', '"DateLastAccessed":1e400');
    const infinite = storages(huge, marker());
    assert.equal(load(infinite.local, infinite.session), false, 'DateLastAccessed Infinity');
    const otherSpoiled = rememberOffWith(entry(now), entry(now, {Id: 'other-server', DateLastAccessed: 'garbage'}));
    const {local, session} = storages(otherSpoiled, marker());
    assert.equal(load(local, session), false, 'another entry with a spoiled time: the connected server is unknown');
});

// A marker and an entry that both lack a field must not match on undefined.
const missingOnBothSides = {
    'no server Id': {Id: undefined},
    'no UserId': {UserId: undefined},
};
for (const [name, change] of Object.entries(missingOnBothSides)) {
    test(`a hand-off whose marker and entry both have ${name} is refused`, () => {
        const stored = entry(now, change);
        const {local, session} = storages(rememberOffWith(stored), marker(now, stored));
        assert.equal(load(local, session), false);
        assert.equal(local.getItem('enableAutoLogin'), 'false');
    });
}

test('a hand-off whose session is gone, or has no token, changes nothing', () => {
    for (const stored of [credentials(), credentials(entry(now, {AccessToken: ''}))]) {
        const {local, session} = storages({enableAutoLogin: 'false', jellyfin_credentials: stored}, marker());
        assert.equal(load(local, session), false);
        assert.equal(local.getItem('enableAutoLogin'), 'false');
    }
    // A marker naming a session without a token, as a broken bridge response
    // would leave it, keeps nothing either.
    const empty = entry(now, {AccessToken: ''});
    const {local, session} = storages(rememberOffWith(empty),
        {[handoffKey]: JSON.stringify({at: now, server: empty.Id, user: empty.UserId, tokenTail: ''})});
    assert.equal(load(local, session), false);
});

test('a load nobody handed over keeps Jellyfin Web\'s own setting', () => {
    const {local, session} = storages(rememberOff(), {});
    assert.equal(load(local, session), false);
    assert.equal(local.getItem('enableAutoLogin'), 'false');
});

test('with Remember Me on, or never set, the marker changes nothing', () => {
    for (const setting of [{enableAutoLogin: 'true'}, {}]) {
        const {local, session} = storages({...setting, jellyfin_credentials: handedOver()}, marker());
        assert.equal(load(local, session), false);
        assert.equal(local.getItem('enableAutoLogin'), setting.enableAutoLogin ?? null);
        assert.equal(session.getItem(handoffKey), null);
    }
});

test('only the enableAutoLogin read of localStorage is answered', () => {
    const {local, session} = storages({...rememberOff(), other: 'kept'}, {...marker(), enableAutoLogin: 'session-value'});
    load(local, session);
    assert.equal(local.getItem('other'), 'kept');
    assert.equal(session.getItem('enableAutoLogin'), 'session-value');
});

test('inject.js applies it while loading, before the fetch and XHR hooks', () => {
    const call = inject.search(/honorSessionHandoff\(window\.Storage\.prototype, window\.localStorage, window\.sessionStorage,\s+isExplicitLoginRoute, Date\.now\(\)\);/);
    assert(call > 0, 'inject.js must call honorSessionHandoff with the page storages, the login route check and the clock');
    assert(call < inject.indexOf('var origFetch = window.fetch'), 'it must run before Jellyfin Web can read the setting');
});

// A marker the pages leave names the session they stored, and when: the
// server entry, the user and the last characters of the token. The token
// itself stays out of it.
function assertMarkedWith(session, stored) {
    const raw = session.getItem(handoffKey);
    assert.notEqual(raw, null, 'the hand-off must be marked');
    const mark = JSON.parse(raw);
    assert(Number.isSafeInteger(mark.at) && Math.abs(Date.now() - mark.at) < 5000, `marker must hold the hand-off time, got ${raw}`);
    assert.deepEqual({server: mark.server, user: mark.user, tokenTail: mark.tokenTail},
        {server: stored.Id, user: stored.UserId, tokenTail: stored.AccessToken.slice(-8)});
    assert(!raw.includes(stored.AccessToken), 'the marker must not hold a second copy of the token');
}

for (const page of ['login.html', 'challenge.html']) {
    test(`${page} marks the hand-off with the session it stored`, () => {
        const session = new FakeStorage({__tfa_pending: '1'});
        const local = new FakeStorage({__tfa_rp_logout: 'provider'});
        const clear = runInNewContext(`(${definition(read(page), 'clearTfaClientState')})`, {sessionStorage: session, localStorage: local, String, JSON, Date});
        clear(entry(Date.now()));
        assertMarkedWith(session, entry());
        assert.equal(session.getItem('__tfa_pending'), null);

        session.setItem(handoffKey, 'stale');
        clear(undefined);
        assert.equal(session.getItem(handoffKey), null, 'nothing stored: no marker, and an older one is dropped');
    });
}

// The in-app OIDC dialog spends its bridge token, stores the session and loads
// /web like the pages above.
const dialogStart = inject.indexOf('function completeWithBridgeToken(');
const dialogEnd = inject.indexOf('\n    function pollDeviceFlow(', dialogStart);
assert(dialogStart >= 0 && dialogEnd > dialogStart, 'completeWithBridgeToken boundaries must exist');

async function completeInApp(response) {
    const local = new FakeStorage();
    const session = new FakeStorage();
    const context = {
        TFA_CONNECTION_MODE_MANUAL: 2,
        TFA_HANDOFF_KEY: handoffKey,
        TFA_HANDOFF_TOKEN_TAIL: tokenTail,
        serverUrl: path => '/jf/' + path,
        jellyfinBasePath: () => '/jf',
        T: (key, fallback) => fallback,
        Tf: (key, fallback) => fallback,
        oidcModalStatus() {},
        clearTfaPending() {},
        closeOidcModal() {},
        setTimeout() {},
        localStorage: local,
        sessionStorage: session,
        crypto: {getRandomValues: bytes => bytes},
        window: {location: {origin: 'https://example.test', href: 'https://example.test/web/'}},
        fetch: async () => response,
    };
    runInNewContext(inject.slice(dialogStart, dialogEnd) + '\ncompleteWithBridgeToken("test-user", "test-bridge-token");', context);
    for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
    return {local, session};
}

test('in-app OIDC dialog: a sign-in that works marks the hand-off, a refused one does not', async () => {
    const signedIn = await completeInApp({
        ok: true,
        status: 200,
        json: async () => ({AccessToken: 'test-access-token-0001', ServerId: 'test-server', User: {Id: 'test-user-id', Name: 'test-user'}}),
    });
    assert.notEqual(signedIn.local.getItem('jellyfin_credentials'), null);
    assertMarkedWith(signedIn.session, entry());

    const refused = await completeInApp({ok: false, status: 401, text: async () => ''});
    assert.equal(refused.session.getItem(handoffKey), null);
});

// The two OIDC bridge pages the server renders (the browser callback and the
// app's device flow) do the same hand-off. Run their emitted script the way
// tests/oidc-bridge.test.mjs does, with a sign-in that works.
const controller = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Api/SecurityController.cs', import.meta.url), 'utf8');
const responseHandler = controller.match(/OidcAuthResponseHandler = """([\s\S]*?)""";/)?.[1] ?? '';

function bridgeScript(startMarker, endMarker) {
    const start = controller.indexOf(startMarker);
    const end = controller.indexOf(endMarker, start);
    assert(start >= 0 && end > start, 'OIDC bridge script boundaries must exist');
    return controller.slice(start, end).split('\n')
        .filter(line => line.trimStart().startsWith('+'))
        .map(line => {
            const fragment = line.trim().slice(1).trim();
            return fragment === 'OidcAuthResponseHandler' ? responseHandler : JSON.parse(fragment);
        }).join('\n');
}

const serverBridges = {
    callback: bridgeScript('+ "fetch(authPath,', '+ "})();"'),
    webview: bridgeScript('+ "fetch(su(\'Users/AuthenticateByName\'),', '\n            + "}"'),
};

for (const [name, script] of Object.entries(serverBridges)) {
    test(`server ${name} bridge marks the hand-off after a sign-in that works`, async () => {
        const local = new FakeStorage();
        const session = new FakeStorage();
        const element = () => ({textContent: '', style: {}, appendChild() {}});
        const context = {
            u: 'test-user', t: 'test-bridge-token', auth: 'test-authorization', bp: '', authPath: '/Users/AuthenticateByName',
            land: '/web/index.html', loginPath: '/TwoFactorAuth/Login', forcePw: false, rpLogoutId: null,
            su: p => '/' + p,
            window: {location: {origin: 'https://example.test', href: 'https://example.test/callback'}},
            localStorage: local,
            sessionStorage: session,
            document: {getElementById: element, querySelector: () => null, createElement: element},
            console: {error() {}},
            st() {},
            setTimeout() {},
            fetch: async () => ({
                ok: true,
                status: 200,
                json: async () => ({AccessToken: 'test-access-token-0001', ServerId: 'test-server', User: {Id: 'test-user-id', Name: 'test-user'}}),
            }),
        };
        runInNewContext(script, context);
        for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
        assert.notEqual(local.getItem('jellyfin_credentials'), null);
        assertMarkedWith(session, entry());
    });
}

const portalKey = '__tfa_portal_recovery';
const forwardKey = '__tfa_portal_forwarded';
const challenged = entry();
const mark = {at: now, server: challenged.Id, user: challenged.UserId, tokenTail: challenged.AccessToken.slice(-8)};
const saved = [
    entry(now - 1, {Id: 'other-server'}), null, challenged,
    entry(now - 2, {UserId: 'another-user'}), entry(now - 3, {AccessToken: 'another-session'}),
];
const stockLogin = '../web/index.html#/login';
const settlePortal = () => new Promise(resolve => setImmediate(resolve));

function portalPage({raw = JSON.stringify(mark), servers = saved, answer = () => Response.json({passwordLoginDisabled: true}),
    mount = '/jellyfin', urlMount = mount, session = new FakeStorage({__tfa_pending: 'armed'}), local = new FakeStorage({jellyfin_credentials: credentials(...servers)})} = {}) {
    if (raw !== null) session.setItem(portalKey, raw);
    const nodes = new Map();
    const requests = [];
    const navigations = [];
    const timers = new Map();
    const node = id => {
        if (!nodes.has(id)) nodes.set(id, {
            hidden: false, focus() {}, getAttribute: () => stockLogin,
            addEventListener(name, fn) { this[name] = fn; },
        });
        return nodes.get(id);
    };
    const ctx = {
        document: {readyState: 'loading', addEventListener() {}, getElementById: node, querySelector: node},
        window: {
            tfaUrl: path => urlMount + '/' + path,
            location: {search: '', href: 'https://example.test/jellyfin/TwoFactorAuth/Login'},
        },
        localStorage: local, sessionStorage: session, URL, URLSearchParams, Date: {now: () => now},
        async fetch(url, init) { requests.push(new Request(new URL(url, 'https://example.test'), init)); return answer(); },
        setTimeout(fn, ms) { timers.set(fn, ms); return fn; }, clearTimeout(id) { timers.delete(id); },
    };
    Object.defineProperty(ctx.window.location, 'href', {
        get: () => 'https://example.test' + mount + '/TwoFactorAuth/Login', set: url => navigations.push(url),
    });
    const script = read('login.html').match(/<script>([\s\S]*?)<\/script>/)[1];
    runInNewContext(script, ctx);
    return {card: node('.card'), requests, navigations, local, session, timers, link: node('standardLoginLink')};
}

test('portal consumes the marker before the GET and forwards only matching entries', async () => {
    const page = portalPage({servers: [...saved, challenged]});
    assert.equal(page.session.getItem(portalKey), null);
    assert.equal(page.card.hidden, true);
    await settlePortal();
    assert.equal(page.requests.length, 1);
    const req = page.requests[0];
    assert.deepEqual([req.url, req.method, req.credentials, [...req.headers]], [
        'https://example.test/jellyfin/TwoFactorAuth/public-config', 'GET', 'same-origin', [],
    ]);
    const cleared = {...challenged, AccessToken: '', UserId: ''};
    assert.deepEqual(JSON.parse(page.local.getItem('jellyfin_credentials')).Servers,
        [saved[0], null, cleared, saved[3], saved[4], cleared]);
    assert.equal(page.session.getItem('__tfa_pending'), null);
    assert.deepEqual(page.navigations, [stockLogin]);
    assert.ok(!page.session.getItem(forwardKey).includes(challenged.AccessToken));
});

for (const [reason, answer] of [
    ['false', () => Response.json({passwordLoginDisabled: false})], ['missing', () => Response.json({})],
    ['string', () => Response.json({passwordLoginDisabled: 'true'})], ['HTTP failure', () => Promise.resolve(new Response(null, {status: 503}))],
    ['network failure', () => Promise.reject(Error('offline'))], ['invalid JSON', () => Promise.resolve(new Response('oops'))],
]) {
    test(`portal restores the form on ${reason}`, async () => {
        const page = portalPage({answer: () => Promise.resolve(answer())});
        assert.equal(page.card.hidden, true);
        await settlePortal();
        assert.equal(page.card.hidden, false);
        assert.deepEqual(page.navigations, []);
        assert.equal(page.local.getItem('jellyfin_credentials'), credentials(...saved));
        assert.equal(page.session.getItem('__tfa_pending'), 'armed');
    });
}

test('the deadline includes body parsing and a late reply cannot change the choice', async () => {
    let answer;
    const page = portalPage({answer: async () => ({ok: true, json: () => new Promise(r => { answer = r; })})});
    await settlePortal();
    assert.equal(page.card.hidden, true);
    const [[expire, ms]] = page.timers;
    assert.equal(ms, 2500);
    expire();
    await settlePortal();
    assert.equal(page.card.hidden, false);
    answer({passwordLoginDisabled: true});
    await settlePortal();
    assert.deepEqual(page.navigations, []);
    assert.equal(page.local.getItem('jellyfin_credentials'), credentials(...saved));
});

for (const [reason, raw] of Object.entries({
    absent: null, invalid: '{', stale: JSON.stringify({...mark, at: now - 60001}),
    future: JSON.stringify({...mark, at: now + 1}), user: JSON.stringify({...mark, user: ''}),
    tail: JSON.stringify({...mark, tokenTail: challenged.AccessToken}), time: JSON.stringify({...mark, at: String(now)}),
})) {
    test(`portal leaves the form available without a recovery lookup for ${reason} marker`, () => {
        const page = portalPage({raw});
        assert.equal(page.card.hidden, false);
        assert.deepEqual(page.requests, []);
        assert.equal(page.session.getItem(portalKey), null);
        assert.deepEqual(page.navigations, []);
    });
}

test('a replacement during the GET forwards without changing the replacement or pending state', async () => {
    let release;
    const page = portalPage({answer: () => new Promise(r => { release = r; })});
    const replacement = credentials(entry(now, {AccessToken: 'replacement-different-tail'}));
    page.local.setItem('jellyfin_credentials', replacement);
    release(Response.json({passwordLoginDisabled: true}));
    await settlePortal();
    assert.deepEqual(page.navigations, [stockLogin]);
    assert.equal(page.local.getItem('jellyfin_credentials'), replacement);
    assert.equal(page.session.getItem('__tfa_pending'), 'armed');
});

for (const op of ['throw', 'ignore credentials', 'ignore pending removal', 'ignore loop guard', 'ignore marker removal']) {
    test(`portal keeps the form after storage operation: ${op}`, async () => {
        const {local, session} = storages({jellyfin_credentials: credentials(...saved)}, {__tfa_pending: 'armed'});
        if (op === 'throw') local.setItem = () => { throw Error('denied'); };
        if (op === 'ignore credentials') local.setItem = () => {};
        const remove = session.removeItem.bind(session);
        session.removeItem = key => {
            if (op === 'ignore pending removal' && key === '__tfa_pending') return;
            if (op === 'ignore marker removal' && key === portalKey) return;
            remove(key);
        };
        const set = session.setItem.bind(session);
        session.setItem = (key, value) => { if (op !== 'ignore loop guard' || key !== forwardKey) set(key, value); };
        const page = portalPage({local, session});
        await settlePortal();
        assert.equal(page.card.hidden, false);
        assert.deepEqual(page.navigations, []);
    });
}

test('repeated challenge for the same session shows the form; another session may forward', async () => {
    const page = portalPage();
    await settlePortal();
    assert.deepEqual(page.navigations, [stockLogin]);
    const repeat = portalPage({session: page.session});
    await settlePortal();
    assert.equal(repeat.card.hidden, false);
    assert.deepEqual(repeat.requests, []);
    assert.deepEqual(repeat.navigations, []);
    const other = portalPage({session: page.session, raw: JSON.stringify({...mark, server: 'other-server'})});
    await settlePortal();
    assert.deepEqual(other.navigations, [stockLogin]);
});

test('the manual standard login link still clears every saved session', () => {
    const page = portalPage({raw: null});
    page.link.click({preventDefault() {}});
    assert.deepEqual(JSON.parse(page.local.getItem('jellyfin_credentials')).Servers,
        saved.map(s => s && {...s, AccessToken: '', UserId: ''}));
    assert.equal(page.session.getItem('__tfa_pending'), null);
    assert.deepEqual(page.navigations, [stockLogin]);
});

test('an already cleared session forwards without touching storage', async () => {
    const {local, session} = storages({jellyfin_credentials: credentials(null, {...challenged, AccessToken: '', UserId: ''})},
        {__tfa_pending: 'new challenge'});
    local.setItem = () => assert.fail('no credential write');
    const page = portalPage({local, session});
    await settlePortal();
    assert.deepEqual(page.navigations, [stockLogin]);
    assert.equal(session.getItem('__tfa_pending'), 'new challenge');
});

test('a concurrent replacement seen at read-back forwards without overwriting it', async () => {
    const {local, session} = storages({jellyfin_credentials: credentials(challenged)}, {__tfa_pending: 'armed'});
    const replacement = credentials({...challenged, AccessToken: 'replacement-new-tail'});
    let writes = 0;
    local.setItem = (key, value) => {
        assert.equal(key, 'jellyfin_credentials');
        assert.equal(JSON.parse(value).Servers[0].AccessToken, '');
        writes++;
        local.items.set(key, replacement);
    };
    const page = portalPage({local, session});
    await settlePortal();
    assert.equal(writes, 1);
    assert.deepEqual(page.navigations, [stockLogin]);
    assert.equal(local.getItem('jellyfin_credentials'), replacement);
});

test('an expired forwarding guard allows the session to recover again', async () => {
    const session = new FakeStorage({[forwardKey]: JSON.stringify([{...mark, at: now - 60001}])});
    const page = portalPage({session});
    await settlePortal();
    assert.deepEqual(page.navigations, [stockLogin]);
});

test('portal keeps the form if the helper points to a different mount', async () => {
    const page = portalPage({mount: '/TwoFactorAuthLab', urlMount: ''});
    await settlePortal();
    assert.deepEqual(page.requests, []);
    assert.deepEqual(page.navigations, []);
    assert.equal(page.card.hidden, false);
    assert.equal(page.local.getItem('jellyfin_credentials'), credentials(...saved));
});

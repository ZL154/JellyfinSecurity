// Run with Node.js 18+: node --test tests/password-reset-page.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

// [#318] Runs the reset page's own script against a stub DOM, fetch and
// tfa-i18n, with French translations that arrive when the test says so.
const html = readFileSync(
    new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/password-reset.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

const french = {
    'tfa.pwreset.subtitle': 'Choisissez un nouveau mot de passe pour votre compte Jellyfin.',
    'tfa.pwreset.error_invalid_link': 'Ce lien de réinitialisation est invalide ou a expiré.',
    'tfa.pwreset.error_failed': 'Impossible de réinitialiser votre mot de passe.',
    'tfa.pwreset.error_mismatch': 'Les deux mots de passe ne correspondent pas.',
    'tfa.pwreset.success': 'Votre mot de passe a été réinitialisé.',
};

function page({complete = {status: 200}} = {}) {
    const el = () => ({style: {}, className: '', textContent: '', value: '', disabled: false, handlers: {},
        addEventListener(type, fn) { this.handlers[type] = fn; }});
    const ids = {form: el(), msg: el(), subtitle: el(), submit: el(), pw1: el(), pw2: el()};
    let translationsIn;
    let loaded = false;
    const ready = new Promise(resolve => { translationsIn = resolve; });
    const context = {
        window: {
            location: {search: '?token=abc123&lang=fr'},
            // Like tfa-i18n, tr gives the English fallback until the bundle is in.
            tfaI18n: {ready, tr: (key, fallback) => (loaded && key in french ? french[key] : fallback)},
        },
        document: {getElementById: id => ids[id]},
        fetch: url => Promise.resolve(url.includes('/Validate')
            ? {ok: true, status: 200, json: () => Promise.resolve({valid: true})}
            : {ok: complete.status < 300, status: complete.status,
               json: () => Promise.resolve({message: 'This reset link is invalid or has expired. Please request a new one.'})}),
        Promise,
    };
    runInNewContext(script, context);
    return {
        ids,
        // What tfa-i18n does once the bundle is in: keyed elements get their text.
        translate: () => { loaded = true; ids.subtitle.textContent = french['tfa.pwreset.subtitle']; translationsIn(); },
        submit: async (p1, p2) => {
            ids.pw1.value = p1; ids.pw2.value = p2;
            ids.submit.handlers.click();
            await new Promise(resolve => setTimeout(resolve, 0));
        },
        settle: () => new Promise(resolve => setTimeout(resolve, 0)),
    };
}

test('a link that expired while the form was open fails in the page language', async () => {
    const p = page({complete: {status: 400}});
    p.translate();
    await p.submit('nouveau-mdp', 'nouveau-mdp');
    await p.settle();
    assert.equal(p.ids.msg.textContent, french['tfa.pwreset.error_invalid_link']);
    assert.equal(p.ids.msg.className, 'msg err');
    assert.equal(p.ids.submit.disabled, false);
});

test('any other server failure shows the page own failure text', async () => {
    const p = page({complete: {status: 503}});
    p.translate();
    await p.submit('nouveau-mdp', 'nouveau-mdp');
    await p.settle();
    assert.equal(p.ids.msg.textContent, french['tfa.pwreset.error_failed']);
});

test('a message raised before the translations arrive is shown translated', async () => {
    const p = page();
    await p.submit('nouveau-mdp', 'autre-mdp');
    assert.equal(p.ids.msg.textContent, '');
    p.translate();
    await p.settle();
    assert.equal(p.ids.msg.textContent, french['tfa.pwreset.error_mismatch']);
});

test('success stays clean when the translations arrive after it', async () => {
    const p = page();
    await p.submit('nouveau-mdp', 'nouveau-mdp');
    p.translate();
    await p.settle();
    assert.equal(p.ids.msg.textContent, french['tfa.pwreset.success']);
    assert.equal(p.ids.msg.className, 'msg ok');
    assert.equal(p.ids.form.style.display, 'none');
    assert.equal(p.ids.subtitle.style.display, 'none');
});

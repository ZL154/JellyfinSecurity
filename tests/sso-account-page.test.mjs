// Run with Node.js 18+: node --test tests/sso-account-page.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const pages = new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/', import.meta.url);
const read = name => readFileSync(new URL(name, pages), 'utf8');
const setup = read('setup.html');

// [#247] Run the rule exactly as setup.html defines it.
const rule = setup.match(/\n( *)function ssoOnlyPage\(s\) \{[\s\S]*?\n\1\}/);
assert(rule, 'setup.html must define ssoOnlyPage(s)');
const ssoOnlyPage = runInNewContext(`(${rule[0].trim()})`);
const page = s => ({...ssoOnlyPage(s)});

const ssoUser = {
    hideSetupForSso: true, isAdmin: false, ssoLinkCount: 1,
    totpOn: false, passkeyCount: 0, passwordRecoveryEnabled: false,
};
const nothingHidden = {
    ssoStatus: false, hideEnroll: false, hidePasskeys: false,
    hideEmail: false, hideEmergency: false, hideSsoLinks: false,
};

test('a user who signs in through SSO sees none of the local 2FA setup', () => {
    assert.deepEqual(page(ssoUser), {
        ssoStatus: true, hideEnroll: true, hidePasskeys: true,
        hideEmail: true, hideEmergency: true, hideSsoLinks: true,
    });
});

test('nothing changes while the setting is off', () => {
    assert.deepEqual(page({...ssoUser, hideSetupForSso: false}), nothingHidden);
});

test('administrators keep the whole page', () => {
    assert.deepEqual(page({...ssoUser, isAdmin: true}), nothingHidden);
});

test('a user without a linked provider keeps the whole page', () => {
    assert.deepEqual(page({...ssoUser, ssoLinkCount: 0}), nothingHidden);
});

test('an authenticator the user already has keeps its status and the lockout card', () => {
    const p = page({...ssoUser, totpOn: true});
    assert.equal(p.ssoStatus, false);
    assert.equal(p.hideEmergency, false);
    assert.equal(p.hidePasskeys, true);
});

test('a passkey the user already has stays listed', () => {
    const p = page({...ssoUser, passkeyCount: 1});
    assert.equal(p.hidePasskeys, false);
    assert.equal(p.hideEmergency, false);
    assert.equal(p.ssoStatus, true);
});

test('the email card stays while it is the password recovery address', () => {
    assert.equal(page({...ssoUser, passwordRecoveryEnabled: true}).hideEmail, false);
});

test('the page feeds the rule from the server and applies it to the cards', () => {
    assert.match(setup, /hideSetupForSso: publicCfg\.hideTwoFactorSetupForSsoUsers === true/);
    assert.match(setup, /isAdmin: !!\(me\.Policy && me\.Policy\.IsAdministrator\)/);
    assert.match(setup, /ssoLinkCount: window\.__tfa_userOidcLinks\.length/);
    for (const id of ['cardPasskeys', 'cardEmail', 'cardEmergency', 'cardSsoLinks']) {
        assert.match(setup, new RegExp(`id="${id}"`));
        assert.match(setup, new RegExp(`${id}: p\\.hide`));
    }
});

test('the admin page loads and saves the setting', () => {
    assert.match(read('admin.html'), /id="cfgHideTwoFactorSetupForSsoUsers"/);
    const script = read('admin-script.js');
    assert.match(script, /hideSetupSsoEl\.checked = !!c\.HideTwoFactorSetupForSsoUsers/);
    assert.match(script, /c\.HideTwoFactorSetupForSsoUsers = hideSetupSsoSaveEl \? hideSetupSsoSaveEl\.checked : false/);
});

// [#327] The step-up prompt's text, run exactly as setup.html defines it.
const stepUpPromptMessage = () => {
    const m = setup.match(/\n( *)function stepUpPromptMessage\(s\) \{[\s\S]*?\n\1\}/);
    assert(m, 'setup.html must define stepUpPromptMessage(s)');
    return runInNewContext(`(${m[0].trim()})`);
};
const texts = {message: 'type your code', messageNoTotp: 'use an option below'};

test('an account without an authenticator app is not asked for its code', () => {
    assert.equal(stepUpPromptMessage()({...texts, totpOn: false, hasAlternative: true}), texts.messageNoTotp);
});

test('an account with an authenticator app is asked for its code', () => {
    assert.equal(stepUpPromptMessage()({...texts, totpOn: true, hasAlternative: true}), texts.message);
    assert.equal(stepUpPromptMessage()({...texts, totpOn: true, hasAlternative: false}), texts.message);
});

test('a prompt with no other option keeps the code field text', () => {
    assert.equal(stepUpPromptMessage()({...texts, totpOn: false, hasAlternative: false}), texts.message);
});

test('the prompt feeds the rule from the factors it renders', () => {
    assert.match(setup, /totpOn: window\.__tfa_userTotpOn === true,/);
    assert.match(setup, /hasAlternative: hasPasskey \|\| hasEmail \|\| hasOidc,/);
    assert.match(setup, /_tr\('tfa\.setup\.stepup\.msg_no_totp', /);
    assert.equal((setup.match(/messageNoTotp: opts\.messageNoTotp\n\s*\}\);/g) || []).length, 2,
        'both step-up retry helpers must pass messageNoTotp to the prompt');
    assert.ok(JSON.parse(read('translations/en.json'))['tfa.setup.stepup.msg_no_totp']);
});

// [#327] The step-up helpers and the factor read, run as setup.html defines
// them, against a fake API. No DOM is given to them: a read that touched the
// page's forms would throw here.
const pageFunction = name => {
    const m = setup.match(new RegExp(`\\n( *)(?:async )?function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\1\\}`));
    assert(m, `setup.html must define ${name}`);
    return m[0].trim();
};
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
    return {promise, resolve, reject};
};
const stepUpRequired = () => Object.assign(new Error('step-up'), {status: 403, body: {stepUpRequired: true}});

function stepUpHarness(handle) {
    const ctx = {
        window: {__tfa_userPasskeyCount: 0, __tfa_userTotpOn: false, _tfaPublicConfig: {}},
        calls: [], prompts: [], cards: [],
        api: (method, path, body) => { ctx.calls.push([method, path, body]); return handle(method, path, body, ctx); },
        tfaPromptForCode: opts => {
            ctx.prompts.push({opts, passkeyCount: ctx.window.__tfa_userPasskeyCount, hasEmail: ctx.window.__tfa_userHasEmail});
            return Promise.resolve(ctx.answer === undefined ? {stepUpToken: 'proof'} : ctx.answer);
        },
        renderAppPasswords: (canCreate, list) => ctx.cards.push([canCreate, list.length]),
    };
    const helpers = ['takeFactorRead', 'applyFactorFlags', 'canCreateAppPasswords', 'refreshFactors', 'mutateWithStepUp', 'mutateWithStepUpUrl'];
    const src = 'var _factorReadSeq = 0, _factorAppliedSeq = 0;\n'
        + helpers.map(pageFunction).join('\n')
        + `\n({${helpers.join(', ')}})`;
    return Object.assign(ctx, runInNewContext(src, ctx));
}
const status = (passkeys, extra) => ({passkeyCount: passkeys, totpEnabled: false, canCreateAppPasswords: passkeys > 0, ...extra});
const reads = (ms, path) => {
    if (path === 'TwoFactorAuth/MyStatus') return ms();
    if (path === 'TwoFactorAuth/Email') return Promise.resolve({email: ''});
    return Promise.resolve([]);
};

test('right after the first passkey, the prompt offers it and the proof goes with the retry', async () => {
    let tries = 0;
    const h = stepUpHarness((method, path) => {
        if (path === 'TwoFactorAuth/Setup/Totp') return ++tries === 1 ? Promise.reject(stepUpRequired()) : Promise.resolve({ok: true});
        return reads(() => Promise.resolve(status(1)), path);
    });
    assert.deepEqual({...(await h.mutateWithStepUp('POST', 'TwoFactorAuth/Setup/Totp', {}, {}))}, {ok: true});
    assert.equal(h.prompts.length, 1);
    assert.equal(h.prompts[0].passkeyCount, 1);
    assert.equal(h.calls.at(-1)[2].stepUpToken, 'proof');
    assert.deepEqual(h.cards, [[true, 0]]);
});

test('after the last passkey is removed, the prompt no longer offers it', async () => {
    const h = stepUpHarness((method, path) => {
        if (path.startsWith('TwoFactorAuth/Setup/Disable')) return h.calls.filter(c => c[1].startsWith('TwoFactorAuth/Setup/Disable')).length === 1 ? Promise.reject(stepUpRequired()) : Promise.resolve({});
        return reads(() => Promise.resolve(status(0, {totpEnabled: true})), path);
    });
    h.window.__tfa_userPasskeyCount = 1;
    h.answer = {code: '123456'};
    await h.mutateWithStepUpUrl('POST', 'TwoFactorAuth/Setup/Disable', {});
    assert.equal(h.prompts[0].passkeyCount, 0);
    assert.equal(h.calls.at(-1)[1], 'TwoFactorAuth/Setup/Disable?code=123456');
    assert.deepEqual(h.cards, [[false, 0]]);
});

test('an older factor read that answers last does not overwrite a newer one', async () => {
    const answers = [deferred(), deferred()];
    let n = 0;
    const h = stepUpHarness((method, path) => reads(() => answers[n++].promise, path));
    const older = h.refreshFactors();
    const newer = h.refreshFactors();
    answers[1].resolve(status(1));
    await newer;
    answers[0].resolve(status(0));
    await older;
    assert.equal(h.window.__tfa_userPasskeyCount, 1);
    assert.deepEqual(h.cards, [[true, 0]]);
});

test('a newer read that fails does not hold back an older one', async () => {
    const answers = [deferred(), deferred()];
    let n = 0;
    const h = stepUpHarness((method, path) => reads(() => answers[n++].promise, path));
    const older = h.refreshFactors();
    const newer = h.refreshFactors();
    answers[1].reject(new Error('offline'));
    await assert.rejects(newer);
    answers[0].resolve(status(1));
    await older;
    assert.equal(h.window.__tfa_userPasskeyCount, 1);
});

test('when the factor read fails, the prompt still opens with what the page knew', async () => {
    const h = stepUpHarness((method, path) => {
        if (path === 'TwoFactorAuth/Setup/Totp') return Promise.reject(stepUpRequired());
        return reads(() => Promise.reject(new Error('offline')), path);
    });
    h.window.__tfa_userPasskeyCount = 1;
    h.answer = null;
    await assert.rejects(h.mutateWithStepUp('POST', 'TwoFactorAuth/Setup/Totp', {}, {}), e => e.cancelled === true);
    assert.equal(h.prompts[0].passkeyCount, 1);
    assert.deepEqual(h.cards, []);
});

test('the step-up text options reach the prompt from both helpers', async () => {
    const h = stepUpHarness((method, path) => path.startsWith('TwoFactorAuth/AppPasswords') && method === 'POST'
        ? Promise.reject(stepUpRequired()) : reads(() => Promise.resolve(status(1)), path));
    h.answer = null;
    const opts = {message: 'code text', messageNoTotp: 'options text'};
    await assert.rejects(h.mutateWithStepUp('POST', 'TwoFactorAuth/AppPasswords', {}, opts));
    await assert.rejects(h.mutateWithStepUpUrl('POST', 'TwoFactorAuth/AppPasswords', opts));
    for (const p of h.prompts) {
        assert.equal(p.opts.message, 'code text');
        assert.equal(p.opts.messageNoTotp, 'options text');
    }
});

// Adding or removing a passkey rereads the factors and the passkey list, not
// the whole page, so an email or an allowlist typed but not saved survives.
const handlerAfter = (start) => {
    const from = setup.indexOf(start);
    assert(from >= 0, `setup.html must contain ${start}`);
    return setup.slice(from, setup.indexOf('} catch (e) {', from));
};
for (const [what, start] of [['adding', "'TwoFactorAuth/Passkeys/RegisterFinish'"], ['removing', "await mutateWithStepUpUrl('DELETE', url,"]]) {
    test(`${what} a passkey rereads the factors without redrawing the forms`, () => {
        const h = handlerAfter(start);
        assert.match(h, /\bloadPasskeys\(\);/);
        assert.match(h, /\brefreshFactors\(\)\.catch\(/);
        assert.doesNotMatch(h, /\bloadAll\(\);/);
    });
}

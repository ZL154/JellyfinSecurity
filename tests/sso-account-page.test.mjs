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

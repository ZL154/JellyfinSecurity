// Run with Node.js 18+: node --test tests/discovery-url-compare.test.mjs
// The settings page warns before a discovery URL change with the same rule
// the server uses to retire account links (OidcService.SameDiscoveryUrl).
// Both run the shared cases in discovery-url-cases.json.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const script = readFileSync(new URL('../src/Jellyfin.Plugin.TwoFactorAuth/Pages/admin-script.js', import.meta.url), 'utf8');
const fn = script.match(/\n( *)function canonicalDiscoveryUrl\(raw\) \{[\s\S]*?\n\1\}/);
assert(fn, 'admin-script.js must define canonicalDiscoveryUrl(raw)');
const canonical = runInNewContext(`(${fn[0].trim()})`);
const cases = JSON.parse(readFileSync(new URL('./discovery-url-cases.json', import.meta.url), 'utf8'));

test('URLs the server treats as the same do not warn', () => {
    for (const [a, b] of cases.same) assert.equal(canonical(a), canonical(b), `${a} vs ${b}`);
});

test('URLs the server treats as different warn', () => {
    for (const [a, b] of cases.different) assert.notEqual(canonical(a), canonical(b), `${a} vs ${b}`);
});

test('the canonical form matches the server', () => {
    for (const [input, expected] of cases.canonical) assert.equal(canonical(input), expected, input);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import {caps, getCaps, getSlots} from './config.mjs';
import {assertCard, assertPreserved, authorityParameters, registry} from './manage.mjs';
import {transformSource} from './prepare.mjs';

const baseline = `ISD: A000000003000000 (OP_READY)
     Privs: SecurityDomain
APP: F06D6F6E6F69640201 (SELECTABLE)
     From: F06D6F6E6F696402
PKG: F06D6F6E6F696402 (LOADED)
     Version: 0.0
     Applet: F06D6F6E6F69640201
`;

test('registry comparison ignores listing order and preserves package details', () => {
  const reordered = `PKG: F06D6F6E6F696402 (LOADED)
     Applet: F06D6F6E6F69640201
     Version: 0.0
APP: F06D6F6E6F69640201 (SELECTABLE)
     From: F06D6F6E6F696402
ISD: A000000003000000 (OP_READY)
     Privs: SecurityDomain
`;

  assert.deepEqual(registry(baseline), registry(reordered));
});

test('unowned additions and removals fail the preservation guard', () => {
  const ledger = {baselineRegistry: registry(baseline), confirmed: []};

  assertPreserved(baseline, ledger);
  assert.throws(() => assertPreserved(baseline + 'APP: F000000000 (SELECTABLE)\n', ledger));
  assert.throws(() => assertPreserved(baseline.replace('Version: 0.0', 'Version: 0.1'), ledger));
  assert.throws(() => assertPreserved('ISD: A000000003000000 (OP_READY)\n', ledger));
});

test('only exact journaled benchmark AIDs are accepted', () => {
  const installed = baseline + 'PKG: F06D6F6E6F6964C0 (LOADED)\n';
  const ledger = {baselineRegistry: registry(baseline), confirmed: ['F06D6F6E6F6964C0']};

  assertPreserved(installed, ledger);
  assert.throws(() => assertPreserved(baseline, ledger));
  assert.throws(() => assertPreserved(installed, {...ledger, confirmed: []}));
  assert.throws(() =>
    assertPreserved(installed + 'APP: F06D6F6E6F6964C001 (SELECTABLE)\n', ledger),
  );
});

test('every suite deletes clients before their imported packages', () => {
  for (const suite of ['core', 'fido', 'otp', 'full']) {
    const selected = getCaps(suite);
    const order = getSlots(selected);

    for (const cap of selected) {
      if (cap.applet) {
        assert.ok(order.indexOf(`${cap.aid}01`) < order.indexOf(cap.aid));
      }

      for (const name of cap.dependencies) {
        const dependency = caps.find(cap => cap.name === name);

        assert.ok(order.indexOf(cap.aid) < order.indexOf(dependency.aid));
      }
    }
  }
});

test('card guard requires the exact supplied physical serial', () => {
  assertCard('CPLC: ICSerialNumber=12345678', '12345678');
  assert.throws(() => assertCard('CPLC: ICSerialNumber=12345678', '12345679'));
  assert.throws(() => assertCard('No card present', '12345678'));
});

test('Authority install parameters require URL and public key together', () => {
  const key = '04' + '11'.repeat(64);
  const url = 'https://authority.example.test';
  const encoded = Buffer.from(authorityParameters(key, url), 'hex');

  assert.equal(authorityParameters(), null);
  assert.equal(encoded[0], 2);
  assert.equal(encoded.subarray(1, 66).toString('hex'), key);
  assert.equal(encoded.subarray(66).toString(), url);
  assert.throws(() => authorityParameters(key));
  assert.throws(() => authorityParameters(undefined, url));
  assert.throws(() => authorityParameters(key, 'file:///authority'));
  assert.throws(() => authorityParameters(key, 'https://example.test/' + 'x'.repeat(178)));
});

test('source transform isolates package names and complete embedded AIDs only', () => {
  const source = `package monoid;
import monoididentity.IdentityShareable;
monoid.authenticate(token, offset);
byte[] aid = { (byte) 0xf0, 'm', 'o', 'n', 'o', 'i', 'd', 0x00, 0x01 };
byte[] value = { 'd', 0x00, 0x01 };
`;
  const transformed = transformSource(source);

  assert.match(transformed, /^package monoidbench;/);
  assert.match(transformed, /import identitybench.IdentityShareable;/);
  assert.match(transformed, /monoid\.authenticate\(token, offset\)/);
  assert.match(transformed, /0x64, \(byte\) 0xc0, 0x01/);
  assert.match(transformed, /byte\[\] value = \{ 'd', 0x00, 0x01 \}/);
  assert.throws(() => transformSource(source.replace('0x00, 0x01', '0x7f, 0x01')));
});

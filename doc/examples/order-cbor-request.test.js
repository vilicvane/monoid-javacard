import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

import {orderCborRequest} from './order-cbor-request.js';

const fieldOrders = JSON.parse(
  readFileSync(new URL('../../cbor-field-order.json', import.meta.url), 'utf8'),
);

test('all configured commands use their recommended root order', () => {
  for (const [command, orders] of Object.entries(fieldOrders)) {
    const keys = orders.$;
    const request = Object.fromEntries([...keys].reverse().map(key => [key, null]));
    const ordered = orderCborRequest(Number(command), request, fieldOrders);

    assert.deepEqual(Object.keys(ordered), keys, command);
    assert.deepEqual(ordered, request);
  }
});

test('reorders nested maps without mutating inputs or copying bytes and arrays', () => {
  const index = new Uint8Array(8);
  const digest = Buffer.alloc(32);
  const path = [0x8000002c, 0x80000000, 0x80000000, 0, 0];
  const extra = {z: 1, a: 2};
  const derivation = Object.freeze({path, type: 'bip32'});
  const request = Object.freeze({
    extra,
    digest,
    cipher: 'ecdsa',
    derivation,
    type: 'seed',
    index,
    another: false,
  });
  const ordered = orderCborRequest(0x41, request, fieldOrders);

  assert.deepEqual(Object.keys(ordered), [
    'index',
    'type',
    'derivation',
    'cipher',
    'digest',
    'extra',
    'another',
  ]);
  assert.deepEqual(Object.keys(ordered.derivation), ['type', 'path']);
  assert.deepEqual(Object.keys(derivation), ['path', 'type']);
  assert.deepEqual(ordered, request);
  assert.notEqual(ordered, request);
  assert.notEqual(ordered.derivation, derivation);
  assert.equal(ordered.index, index);
  assert.equal(ordered.digest, digest);
  assert.equal(ordered.derivation.path, path);
  assert.equal(ordered.extra, extra);
});

test('keeps scalar, array and byte values at configured map paths unchanged', () => {
  for (const value of [true, false, null, undefined, [], new Uint8Array(0), Buffer.alloc(0)]) {
    const ordered = orderCborRequest(0x41, {taproot: value}, fieldOrders);

    assert.deepEqual(Object.keys(ordered), ['taproot']);
    assert.equal(ordered.taproot, value);
  }
});

test('orders object taproot and retains unknown fields', () => {
  const merkleRoot = new Uint8Array(32);
  const ordered = orderCborRequest(
    0x40,
    {taproot: {extra: false, merkleRoot, another: null}},
    fieldOrders,
  );

  assert.deepEqual(Object.keys(ordered.taproot), ['merkleRoot', 'extra', 'another']);
  assert.equal(ordered.taproot.merkleRoot, merkleRoot);
  assert.equal(ordered.taproot.extra, false);
  assert.equal(ordered.taproot.another, null);
});

test('preserves unconfigured requests and does not add absent fields', () => {
  const request = {z: 1, a: 2};

  assert.equal(orderCborRequest(0xc0, request, fieldOrders), request);
  assert.deepEqual(orderCborRequest(0x41, {}, fieldOrders), {});
  assert.deepEqual(orderCborRequest(0x20, request, fieldOrders), request);
});

test('orders granted key descriptors while preserving other arrays and byte values', () => {
  const index = new Uint8Array(10);
  const path = new Uint8Array(4);
  const domain = new Uint8Array(3);
  const types = [[0x1001, true]];
  const key = Object.freeze({
    derivation: Object.freeze({path, type: 'bip32'}),
    type: 'seed',
    index,
  });
  const keys = Object.freeze([key]);
  const request = Object.freeze({seed: {domain, index}, keys, types, aid: new Uint8Array(8)});
  const ordered = orderCborRequest(0x51, request, fieldOrders);

  assert.deepEqual(Object.keys(ordered), ['aid', 'types', 'keys', 'seed']);
  assert.deepEqual(Object.keys(ordered.keys[0]), ['index', 'type', 'derivation']);
  assert.deepEqual(Object.keys(ordered.keys[0].derivation), ['type', 'path']);
  assert.deepEqual(Object.keys(ordered.seed), ['index', 'domain']);
  assert.deepEqual(ordered, request);
  assert.equal(ordered.types, types);
  assert.equal(ordered.keys[0].index, index);
  assert.equal(ordered.keys[0].derivation.path, path);
  assert.equal(ordered.seed.domain, domain);
  assert.deepEqual(Object.keys(key), ['derivation', 'type', 'index']);
});

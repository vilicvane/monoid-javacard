import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {encode, decode} from './cbor.mjs';
import {getCaps, repositoryRoot} from './config.mjs';
import {check} from './prepare.mjs';
import {context} from './runtime.mjs';
import {rpc} from './transport.mjs';

test('Monoid CBOR preserves request order and binary values', () => {
  const request = {
    index: Buffer.from('f1010102030405060708', 'hex'),
    type: -3839,
    alias: '测试',
    data: Buffer.alloc(600, 0xa5),
    secret: true,
    keys: [{type: 'hmac', index: Buffer.alloc(10)}],
  };
  const encoded = encode(request);

  assert.equal(encoded.subarray(0, 7).toString('hex'), 'a665696e646578');
  assert.deepEqual(decode(encoded), request);

  for (const value of [0, 23, 24, 255, 256, 65535, 65536, -1, -3839, false, null]) {
    assert.deepEqual(decode(encode(value)), value);
  }
});

test('Monoid CBOR accepts streamed nested maps and arrays', () => {
  const bytes = Buffer.from(
    'bf656974656d739fbf65696e64657842f1016474797065390efe66736563726574f5ffff66637572736f72f6ff',
    'hex',
  );

  assert.deepEqual(decode(bytes), {
    items: [{index: Buffer.from('f101', 'hex'), type: -3839, secret: true}],
    cursor: null,
  });

  assert.throws(() => decode(bytes.subarray(0, -1)), /Truncated CBOR/);
  assert.throws(() => decode(Buffer.concat([bytes, Buffer.from([0])])), /Trailing CBOR/);
  assert.throws(() => decode(Buffer.from('a2616101616102', 'hex')), /Duplicate map key/);
});

test('Monoid transport orders fields and completes both request and response chains', async () => {
  const index = Buffer.from('0f100102030405060708', 'hex');
  const data = Buffer.alloc(600, 0x5a);
  const expected = {index, data: Buffer.alloc(700, 0xa5)};
  const responseBytes = encode(expected);
  const requests = [];
  const responseRequests = [];
  let responseOffset = 0;

  function response() {
    const data = responseBytes.subarray(responseOffset, responseOffset + 211);

    responseOffset += data.length;

    const remaining = responseBytes.length - responseOffset;

    return {data, sw: remaining ? 0x6100 | (Math.min(remaining, 256) & 255) : 0x9000};
  }

  const bridge = {
    async raw(label, hex) {
      const frame = Buffer.from(hex, 'hex');

      if (frame[1] === 0xc0) {
        responseRequests.push(frame);

        assert.equal(frame[0], 0);
        assert.equal(frame.length, 5);
        assert.equal(frame[4], Math.min(responseBytes.length - responseOffset, 256) & 255);

        return response();
      }

      requests.push(frame);

      assert.equal(frame[1], 0x34);
      assert.equal(frame.length, frame[4] + 6);
      assert.equal(frame.at(-1), 0);

      return frame[0] === 0xa0 ? response() : {data: Buffer.alloc(0), sw: 0x9000};
    },
  };

  const actual = await rpc(bridge, {'0x34': {$: ['index', 'alias', 'data']}}, 'create', 0x34, {
    data,
    alias: 'fixture',
    index,
  });

  assert.deepEqual(actual, expected);
  assert.deepEqual(
    requests.map(frame => frame[0]),
    [0x90, 0xb0, 0xa0],
  );
  assert.deepEqual(
    Buffer.concat(requests.map(frame => frame.subarray(5, -1))),
    encode({index, alias: 'fixture', data}),
  );
  assert.equal(responseRequests.length, 3);
});

test('Monoid transport rejects a failed intermediate APDU without sending more', async () => {
  let calls = 0;

  await assert.rejects(
    rpc(
      {
        async raw() {
          calls++;

          return {data: Buffer.alloc(0), sw: 0x6982};
        },
      },
      {},
      'create',
      0x34,
      {data: Buffer.alloc(600)},
    ),
  );

  assert.equal(calls, 1);
});

test('context memoizes SELECT and does not cache a failed selection', async () => {
  const selections = [];
  let fail = false;
  const ctx = context(
    {
      events: [],
      async select(label, aid) {
        selections.push([label, aid]);

        if (fail) throw Error('selection failed');
      },
    },
    {aids: {monoid: 'A00001', fido: 'A00002'}},
  );

  await ctx.select('fido');
  await ctx.select('fido');
  await ctx.select('fido', {force: true});

  assert.equal(selections.length, 2);

  fail = true;

  await assert.rejects(ctx.select('monoid'), /selection failed/);
  assert.equal(ctx.selected, 'fido');

  fail = false;

  await ctx.select('monoid');
  assert.equal(ctx.selected, 'monoid');
  assert.equal(selections.length, 4);
});

test('nested measurements count physical APDUs once in the complete flow', async () => {
  const event = elapsedMs => ({elapsedMs, commandBytes: 8, responseBytes: 12});
  const bridge = {events: [event(99)]};
  const ctx = context(bridge, {});

  const result = await ctx.measure(
    'flow',
    async () => {
      bridge.events.push(event(2));

      const innerResult = await ctx.measure('stage', async () => {
        bridge.events.push(event(3));

        return 'verified';
      });

      bridge.events.push(event(5));

      return innerResult;
    },
    {phase: 'first'},
  );

  assert.equal(result, 'verified');

  const stage = ctx.samples.find(sample => sample.name === 'stage');
  const flow = ctx.samples.find(sample => sample.name === 'flow');

  assert.equal(stage.elapsedMs, 3);
  assert.equal(stage.apduCount, 1);
  assert.equal(flow.elapsedMs, 10);
  assert.equal(flow.apduCount, 3);
  assert.equal(flow.requestBytes, 24);
  assert.equal(flow.responseBytes, 36);
  assert.equal(flow.eventStart, 1);
  assert.equal(flow.eventEnd, 4);
  assert.equal(flow.phase, 'first');
  assert(flow.hostElapsedMs >= stage.hostElapsedMs);
});

test('cleanup can ignore changed host code while still verifying frozen inputs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'monoid-benchmark-check-'));
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const source = Buffer.from('frozen source');
  const hostPath = 'scripts/benchmark/config.mjs';
  const hostBytes = await readFile(join(repositoryRoot, hostPath));
  const manifest = {
    schemaVersion: 1,
    repositoryRoot,
    suite: 'core',
    caps: getCaps('core'),
    files: [{path: 'source.java', sha256: hash(source)}],
    hostFiles: [{path: hostPath, sha256: hash(hostBytes)}],
  };

  try {
    await writeFile(join(directory, 'source.java'), source);
    await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest));

    await check(directory);

    manifest.hostFiles[0].sha256 = '0'.repeat(64);
    await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest));

    await assert.rejects(check(directory), /config\.mjs/);
    await check(directory, {host: false});

    await writeFile(join(directory, 'source.java'), 'changed source');

    await assert.rejects(check(directory, {host: false}), /source\.java/);
  } finally {
    await rm(directory, {recursive: true});
  }
});

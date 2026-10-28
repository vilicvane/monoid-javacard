import assert from 'node:assert/strict';

import {
  digest,
  k1Private,
  message,
  p256Private,
  rfcSeed,
  vectors,
  verifyEC,
  verifyEd,
} from './vectors.mjs';

const DATA_TYPE = 0x0f10;
const METADATA = Buffer.from('monoid benchmark v1');

async function repeat(ctx, name, action) {
  for (let iteration = 0; iteration < ctx.count; iteration++) {
    await ctx.measure(name, () => action(iteration), {phase: 'warm'});
  }
}

function indexFor(group, sequence) {
  const index = Buffer.alloc(10);

  index.writeUInt16BE(DATA_TYPE);
  index.write('BENCH', 2, 'ascii');
  index[7] = group;
  index.writeUInt16BE(sequence, 8);

  return index;
}

function checkIndices(response, indices) {
  assert.deepEqual(
    response.items.map(item => Buffer.from(item.index).toString('hex')).sort(),
    indices.map(index => index.toString('hex')).sort(),
  );
}

async function benchmarkStorage(ctx) {
  for (const size of [64, 600, 1536]) {
    const data = message(size);
    const replacement = Buffer.from(data.map(byte => byte ^ 0xa5));
    const indices = [];

    await repeat(ctx, `core.create.${size}`, async iteration => {
      const index = indexFor(1, size + iteration);
      const response = await ctx.rpc('create-data', 0x34, {
        index,
        metadata: METADATA,
        alias: 'Benchmark data',
        data,
      });

      assert.deepEqual(Buffer.from(response.index), index);
      indices.push(index);
    });

    await repeat(ctx, `core.get.${size}`, async iteration => {
      const response = await ctx.rpc('get-data', 0x32, {index: indices[iteration]});

      assert.deepEqual(Buffer.from(response.data), data);
    });

    await repeat(ctx, `core.set.${size}`, async iteration => {
      await ctx.rpc('set-data', 0x33, {index: indices[iteration], data: replacement});
    });

    for (const index of indices) {
      const response = await ctx.rpc('verify-set-data', 0x32, {index});

      assert.deepEqual(Buffer.from(response.data), replacement);
    }

    await repeat(ctx, `core.remove.${size}`, async iteration => {
      await ctx.rpc('remove-data', 0x35, {index: indices[iteration]});
    });

    checkIndices(await ctx.rpc('verify-removed-data', 0x30, {type: DATA_TYPE}), []);
  }

  const indices = [];

  for (let iteration = 0; iteration < 16; iteration++) {
    const index = indexFor(2, iteration);

    await ctx.rpc('create-list-fixture', 0x34, {
      index,
      metadata: Buffer.concat([METADATA, Buffer.from([iteration % 2])]),
      alias: `Benchmark list ${String(iteration).padStart(2, '0')}`,
      data: message(64),
    });
    indices.push(index);

    if (iteration === 0 || iteration === 15) {
      await repeat(ctx, `core.list.${indices.length}`, async () => {
        const response = await ctx.rpc('list-fixtures', 0x30, {type: DATA_TYPE});

        checkIndices(response, indices);
      });
    }
  }

  await repeat(ctx, 'core.list.metadata-prefix.8', async () => {
    const response = await ctx.rpc('list-metadata-prefix', 0x30, {
      type: DATA_TYPE,
      metadataPrefix: Buffer.concat([METADATA, Buffer.from([0])]),
    });

    checkIndices(
      response,
      indices.filter((_, iteration) => iteration % 2 === 0),
    );
  });

  for (const index of indices) {
    await ctx.rpc('remove-list-fixture', 0x35, {index});
  }
}

async function benchmarkCrypto(ctx) {
  const indices = {seed: ctx.seedIndex};

  for (const [name, type, data] of [
    ['ed', 'ed25519', rfcSeed],
    ['k1', 'secp256k1', k1Private],
    ['p256', 'secp256r1', p256Private],
  ]) {
    const response = await ctx.rpc('create-crypto-fixture', 0x34, {
      type,
      data,
      secret: true,
      alias: `Benchmark ${name}`,
    });

    indices[name] = Buffer.from(response.index);
    assert.equal(indices[name].length, 10);
  }

  const fixtures = vectors(indices);

  for (const vector of [...fixtures.ec, ...fixtures.ed]) {
    const view = async () => {
      const response = await ctx.rpc('view-key', 0x40, vector.request);

      assert.deepEqual(Buffer.from(response.publicKey), vector.publicKey);

      if (vector.chainCode) {
        assert.deepEqual(Buffer.from(response.chainCode), vector.chainCode);
      } else {
        assert.equal(response.chainCode, undefined);
      }
    };

    await ctx.measure(`core.view-key.${vector.name}`, view, {phase: 'first'});
    await repeat(ctx, `core.view-key.${vector.name}`, view);

    if (vector.cipher) {
      const sign = async () => {
        const response = await ctx.rpc('sign-digest', 0x41, {
          ...vector.request,
          cipher: vector.cipher,
          digest,
        });

        verifyEC(vector, Buffer.from(response.signature));
      };

      await ctx.measure(`core.sign.${vector.name}`, sign, {
        phase: 'first-after-view',
      });
      await repeat(ctx, `core.sign.${vector.name}`, sign);
    } else {
      for (const size of [64, 600, 1232]) {
        const input = message(size);
        const sign = async () => {
          const response = await ctx.rpc('sign-message', 0x41, {
            ...vector.request,
            cipher: 'ed25519',
            message: input,
          });

          verifyEd(vector, input, Buffer.from(response.signature));
        };

        if (size === 64) {
          await ctx.measure(`core.sign.${vector.name}.${size}`, sign, {
            phase: 'first-after-view',
          });
        }

        await repeat(ctx, `core.sign.${vector.name}.${size}`, sign);
      }
    }
  }

  for (const name of ['ed', 'k1', 'p256']) {
    await ctx.rpc('remove-crypto-fixture', 0x35, {index: indices[name]});
  }
}

export async function runCore(ctx) {
  ctx.notes.push(
    'Core first ViewKey means the first invocation of that named case, not a power cycle. Shared curves and repeated key descriptors may already be cached; each derived path is new when first viewed. Sign starts after ViewKey has populated derivation/public-key caches.',
    'Core data fixtures use 64, 600 and 1536 bytes; Ed25519 signs 64, 600 and 1232 raw bytes. Request and response chaining are included by the runner.',
    'Core mutates only publicly known test fixtures in its isolated Monoid instance; every signature and readback is independently checked.',
  );

  await ctx.select('monoid');

  await repeat(ctx, 'core.hello', async () => {
    const response = await ctx.rpc('hello', 0x20);

    assert.equal(response.id.length, 4);
    assert.equal(response.publicKey.length, 65);
    assert.equal(response.bundle, false);
    assert.equal(Boolean(response.authority), ctx.authority);
  });

  await repeat(ctx, 'core.authenticate.access', () => ctx.authenticate(false));
  await repeat(ctx, 'core.authenticate.secret', () => ctx.authenticate(true));

  await benchmarkStorage(ctx);
  await benchmarkCrypto(ctx);
}

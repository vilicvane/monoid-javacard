import assert from 'node:assert/strict';
import {createECDH, createHash, createHmac, createPrivateKey, sign, verify} from 'node:crypto';

const accountType = 0xf201 - 0x10000;
const timeDomain = Buffer.from('Monoid Authority Time');
const seconds = 1234567890n;

// Public test-vector scalar 1; this key belongs only to isolated benchmark instances.
const authorityScalar = Buffer.alloc(32);
authorityScalar[31] = 1;

const authorityECDH = createECDH('prime256v1');
authorityECDH.setPrivateKey(authorityScalar);

export const authorityPublicKey = authorityECDH.getPublicKey();

const authorityPrivateKey = createPrivateKey({
  format: 'jwk',
  key: {
    kty: 'EC',
    crv: 'P-256',
    d: authorityScalar.toString('base64url'),
    x: authorityPublicKey.subarray(1, 33).toString('base64url'),
    y: authorityPublicKey.subarray(33).toString('base64url'),
  },
});

const specifications = [
  {algorithm: 1, name: 'sha1', secret: Buffer.from('12345678901234567890')},
  {algorithm: 2, name: 'sha256', secret: Buffer.from('12345678901234567890123456789012')},
  {
    algorithm: 3,
    name: 'sha512',
    secret: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234'),
  },
];

function timeBytes(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));

  return bytes;
}

export function hotp(secret, counter, algorithm = 'sha1', digits = 8) {
  const digest = createHmac(algorithm, secret).update(timeBytes(counter)).digest();
  const offset = digest[digest.length - 1] & 15;
  const truncated = digest.readUInt32BE(offset) & 0x7fffffff;

  return String(truncated % 10 ** digits).padStart(digits, '0');
}

export function signTime(challenge, unixSeconds) {
  assert.equal(challenge.length, 32);

  const data = Buffer.concat([Buffer.from([1]), timeBytes(unixSeconds), Buffer.from(challenge)]);
  const signature = sign('sha256', Buffer.concat([timeDomain, data]), {
    key: authorityPrivateKey,
    dsaEncoding: 'ieee-p1363',
  });

  assert.equal(signature.length, 64);

  return {data, signature};
}

export function selfTest() {
  // RFC 4226 Appendix D and RFC 6238 Appendix B; no firmware implementation is used.
  const hotpExpected = [
    '755224',
    '287082',
    '359152',
    '969429',
    '338314',
    '254676',
    '287922',
    '162583',
    '399871',
    '520489',
  ];

  hotpExpected.forEach((value, counter) => {
    assert.equal(hotp(specifications[0].secret, counter, 'sha1', 6), value);
  });

  const vectors = [
    [59n, ['94287082', '46119246', '90693936']],
    [1111111109n, ['07081804', '68084774', '25091201']],
    [1111111111n, ['14050471', '67062674', '99943326']],
    [1234567890n, ['89005924', '91819424', '93441116']],
    [2000000000n, ['69279037', '90698825', '38618901']],
    [20000000000n, ['65353130', '77737706', '47863826']],
  ];

  for (const [time, expected] of vectors) {
    specifications.forEach((account, index) => {
      assert.equal(hotp(account.secret, time / 30n, account.name, 8), expected[index]);
    });
  }

  const challenge = Buffer.alloc(32, 0xa5);
  const proof = signTime(challenge, seconds);

  assert.equal(proof.data.length, 41);
  assert.equal(proof.data.readBigUInt64BE(1), seconds);
  assert.deepEqual(proof.data.subarray(9), challenge);
  assert.ok(
    verify(
      'sha256',
      Buffer.concat([timeDomain, proof.data]),
      {
        key: authorityPrivateKey,
        dsaEncoding: 'ieee-p1363',
      },
      proof.signature,
    ),
  );

  proof.data[8] ^= 1;
  assert.equal(
    verify(
      'sha256',
      Buffer.concat([timeDomain, proof.data]),
      {
        key: authorityPrivateKey,
        dsaEncoding: 'ieee-p1363',
      },
      proof.signature,
    ),
    false,
  );

  return {hotpVectors: 10, totpVectors: 18, signedTimeChecks: 2};
}

function verifyCodes(response, accounts, unixSeconds) {
  assert.equal(Buffer.from(response.time).readBigUInt64BE(), unixSeconds);
  assert.equal(response.items.length, accounts.length);

  for (const [index, item] of response.items.entries()) {
    const account = accounts[index];

    assert.deepEqual(Buffer.from(item.index), account.index);
    assert.equal(item.period, account.period);
    assert.deepEqual(
      item.codes,
      Array.from({length: 3}, (_, window) =>
        hotp(
          account.secret,
          unixSeconds / BigInt(account.period) + BigInt(window),
          account.name,
          account.digits,
        ),
      ),
    );
  }
}

export async function runOTP(ctx) {
  const oracle = selfTest();
  const otpAid = Buffer.from(ctx.aids.otp, 'hex');
  const accounts = [];
  const keys = [];

  await ctx.select('monoid');
  await ctx.authenticate();

  for (const specification of specifications) {
    const {algorithm, name, secret} = specification;
    const index = Buffer.concat([
      Buffer.from([0xf2, 0x01]),
      createHash('sha256').update(secret).digest().subarray(0, 8),
    ]);
    const metadata = Buffer.from([1, algorithm, 8, 0, 30]);
    let data = secret;

    if (!ctx.capabilities.otpAccountSecret) {
      const key = await ctx.rpc(`otp-fixture-${name}-key`, 0x34, {
        type: 'hmac',
        data: secret,
        secret: true,
      });

      data = Buffer.from(key.index);
      keys.push({index: data, type: 'hmac'});
    }

    const account = await ctx.rpc(`otp-fixture-${name}-account`, 0x34, {
      index,
      data,
      metadata,
      alias: `Benchmark ${name}`,
      secret: ctx.capabilities.otpAccountSecret,
    });

    assert.deepEqual(Buffer.from(account.index), index);
    accounts.push({...specification, index, digits: 8, period: 30});
  }

  await ctx.rpc('otp-fixture-grant', 0x51, {
    aid: otpAid,
    types: [[accountType, false]],
    ...(keys.length ? {keys} : {}),
  });

  const hello = await ctx.rpc('otp-hello', 0x20, {}, 'otp');
  assert.equal(hello.batchSize, 3);

  ctx.notes.push(
    `OTP account storage: ${ctx.capabilities.otpAccountSecret ? 'mapped F201 secret' : 'public F201 referencing a separately granted HMAC key'}.`,
  );
  ctx.notes.push(
    `OTP time: ${ctx.authority ? 'offline P-256 signed proof; no network or time service latency' : 'APP-supplied unsigned Unix time'}.`,
  );
  ctx.notes.push(
    'OTP flow starts on Monoid, uses known account indices, and includes SELECT plus preparation, one-use Access authorization and Calculate. Stage timings exclude SELECT; first is not a power-cycle measurement.',
  );

  let verifiedCodes = 0;

  async function flow(name, selected) {
    // Start every sample from the same applet. This SELECT is outside the measured flow.
    await ctx.select('monoid');

    const response = await ctx.measure(`${name}.flow`, async () => {
      await ctx.select('otp');
      let proof;

      if (ctx.authority) {
        const challenge = await ctx.measure(`${name}.challenge`, () =>
          ctx.rpc(`${name}-challenge`, 0x21, {}, 'otp'),
        );

        proof = signTime(Buffer.from(challenge.challenge), seconds);
      }

      await ctx.measure(`${name}.prepare`, () =>
        ctx.rpc(
          `${name}-prepare`,
          0x22,
          {
            ...(proof ?? {time: timeBytes(seconds)}),
            indices: selected.map(account => account.index),
          },
          'otp',
        ),
      );

      await ctx.select('monoid');
      await ctx.measure(`${name}.authenticate`, () => ctx.authenticate(false, {aid: otpAid}));

      await ctx.select('otp');
      return ctx.measure(`${name}.calculate`, () => ctx.rpc(`${name}-calculate`, 0x23, {}, 'otp'));
    });

    verifyCodes(response, selected, seconds);
    verifiedCodes += selected.length * 3;
  }

  for (const account of accounts) {
    await flow(`otp.${account.name}.single.first`, [account]);

    for (let sample = 0; sample < ctx.count; sample++) {
      await flow(`otp.${account.name}.single.repeat`, [account]);
    }
  }

  await flow('otp.mixed.batch3.first', accounts);

  for (let sample = 0; sample < ctx.count; sample++) {
    await flow('otp.mixed.batch3.repeat', accounts);
  }

  return {oracle, accounts: accounts.length, verifiedCodes};
}

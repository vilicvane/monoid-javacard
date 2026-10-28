import assert from 'node:assert/strict';
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  verify,
} from 'node:crypto';
import {HDNodeWallet} from 'ethers';
import {secp256k1, schnorr} from '@noble/curves/secp256k1';
import {p256} from '@noble/curves/p256';

export const bytes = hex => Buffer.from(hex.replace(/^0x/, ''), 'hex');
export const hash = value => createHash('sha256').update(value).digest();
const scalar = value => BigInt('0x' + Buffer.from(value).toString('hex'));
const scalarBytes = value => bytes(value.toString(16).padStart(64, '0'));
const hmac = (key, value) => createHmac('sha512', key).update(value).digest();
export const rfcSeed = bytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
export const seed = Buffer.from(Array.from({length: 64}, (_, i) => i));
export const edPath = bytes('8000002c800001f58000000080000000');
export const btcPath = bytes('8000002c80000000800000000000000000000000');
export const context = Buffer.from('Monoid benchmark v1');
export const digest = hash(context);
export const k1Private = scalarBytes(3n);
export const p256Private = bytes(
  'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
);

export function edKey(seedBytes) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([bytes('302e020100300506032b657004220420'), seedBytes]),
    format: 'der',
    type: 'pkcs8',
  });
  const key = createPublicKey(privateKey);
  return {key, publicKey: key.export({format: 'der', type: 'spki'}).subarray(-32)};
}

export function slip10(seedBytes, path) {
  let node = hmac('ed25519 seed', seedBytes);

  for (let offset = 0; offset < path.length; offset += 4) {
    assert(path[offset] & 0x80);
    node = hmac(
      node.subarray(32),
      Buffer.concat([Buffer.from([0]), node.subarray(0, 32), path.subarray(offset, offset + 4)]),
    );
  }

  return {
    ...edKey(node.subarray(0, 32)),
    chainCode: node.subarray(32),
    privateKey: node.subarray(0, 32),
  };
}

export function monoid001(seedBytes, input) {
  for (let attempt = 0; attempt < 256; attempt++) {
    const info = Buffer.concat([
      Buffer.from('Monoid-001'),
      Buffer.from([0]),
      input,
      Buffer.from([attempt]),
    ]);
    const privateKey = Buffer.from(
      hkdfSync('sha512', seedBytes, Buffer.from('Monoid-001'), info, 32),
    );

    if (scalar(privateKey) > 0n && scalar(privateKey) < p256.CURVE.n) {
      return {privateKey, publicKey: Buffer.from(p256.getPublicKey(privateKey, true))};
    }
  }

  throw new Error('Fixture rejection sampling exhausted');
}

function bip32(seedBytes, path) {
  const steps = [];

  for (let offset = 0; offset < path.length; offset += 4) {
    const value = path.readUInt32BE(offset);
    steps.push(`${value & 0x7fffffff}${value & 0x80000000 ? "'" : ''}`);
  }

  const node = HDNodeWallet.fromSeed(seedBytes).derivePath('m/' + steps.join('/'));

  return {publicKey: bytes(node.publicKey), chainCode: bytes(node.chainCode)};
}

export function taprootPublic(publicKey) {
  const x = publicKey.subarray(1),
    tag = hash(Buffer.from('TapTweak'));
  const tweak = scalar(hash(Buffer.concat([tag, tag, x])));

  assert(tweak < secp256k1.CURVE.n);
  const point = secp256k1.ProjectivePoint.fromHex(Buffer.concat([Buffer.from([2]), x]));

  return Buffer.from(
    (tweak === 0n ? point : point.add(secp256k1.ProjectivePoint.BASE.multiply(tweak))).toRawBytes(
      true,
    ),
  ).subarray(1);
}

export const message = length =>
  Buffer.from(Array.from({length}, (_, index) => (index * 17 + length) & 255));

export function vectors(indices) {
  const direct = (name, type) => ({index: indices[name], type});
  const k1Public = Buffer.from(secp256k1.getPublicKey(k1Private, true));

  return {
    ed: [
      {name: 'direct-ed25519', request: direct('ed', 'ed25519'), ...edKey(rfcSeed)},
      {
        name: 'slip10-ed25519',
        request: {
          ...direct('seed', 'seed'),
          derivation: {type: 'slip10', curve: 'ed25519', path: edPath},
        },
        ...slip10(seed, edPath),
      },
    ],
    ec: [
      {
        name: 'direct-p256',
        request: direct('p256', 'secp256r1'),
        publicKey: Buffer.from(p256.getPublicKey(p256Private, true)),
        algorithm: p256,
        cipher: 'ecdsa',
      },
      {
        name: 'monoid001-p256',
        request: {...direct('seed', 'seed'), derivation: {type: 'monoid-001', context}},
        ...monoid001(seed, context),
        algorithm: p256,
        cipher: 'ecdsa',
      },
      {
        name: 'direct-k1',
        request: direct('k1', 'secp256k1'),
        publicKey: k1Public,
        algorithm: secp256k1,
        cipher: 'ecdsa',
      },
      {
        name: 'bip32-k1',
        request: {...direct('seed', 'seed'), derivation: {type: 'bip32', path: btcPath}},
        ...bip32(seed, btcPath),
        algorithm: secp256k1,
        cipher: 'ecdsa',
      },
      {
        name: 'bip340',
        request: direct('k1', 'secp256k1'),
        publicKey: k1Public,
        verifyPublic: k1Public.subarray(1),
        algorithm: schnorr,
        cipher: 'bip340',
      },
      {
        name: 'taproot-k1',
        request: {...direct('k1', 'secp256k1'), taproot: true},
        publicKey: taprootPublic(k1Public),
        algorithm: schnorr,
        cipher: 'bip340',
      },
    ],
  };
}

export function verifyEd(vector, input, signature) {
  assert.equal(signature.length, 64);
  assert(
    verify(null, input, vector.key, signature),
    vector.name + ': independent Ed25519 verification',
  );
}

export function verifyEC(vector, signature) {
  assert.equal(signature.length, 64);
  const publicKey = vector.verifyPublic ?? vector.publicKey;

  assert(
    vector.cipher === 'bip340'
      ? vector.algorithm.verify(signature, digest, publicKey)
      : vector.algorithm.verify(signature, digest, publicKey, {prehash: false, lowS: true}),
    vector.name + ': independent digest verification',
  );
}

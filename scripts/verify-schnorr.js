// @ts-check

import {schnorr} from '@noble/curves/secp256k1';

const [signature, digest, publicKey] = process.argv
  .slice(2)
  .map(value => Buffer.from(value, 'hex'));

process.exit(schnorr.verify(signature, digest, publicKey) ? 0 : 1);

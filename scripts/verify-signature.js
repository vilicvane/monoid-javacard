// @ts-check

import {computeAddress, recoverAddress, Signature} from 'ethers';

const [signatureHex, digestHex, publicKeyHex] = process.argv.slice(2);

const signature = Signature.from(`0x${signatureHex}`);

const address = computeAddress(`0x${publicKeyHex}`);

for (const v of [27, 28]) {
  signature.v = v;

  if (recoverAddress(`0x${digestHex}`, signature) === address) {
    process.exit(0);
  }
}

process.exit(1);

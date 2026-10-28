import assert from 'node:assert/strict';

import {orderCborRequest} from '../../doc/examples/order-cbor-request.js';
import {encode, decode} from './cbor.mjs';

export async function rpc(bridge, orders, label, instruction, request) {
  const payload = encode(orderCborRequest(instruction, request, orders));
  let response;

  for (let offset = 0; offset < payload.length; offset += 255) {
    const part = payload.subarray(offset, offset + 255);
    const last = offset + part.length === payload.length;
    const cla = offset === 0 ? (last ? 0 : 0x90) : last ? 0xa0 : 0xb0;

    response = await bridge.raw(
      label,
      Buffer.concat([
        Buffer.from([cla, instruction, 0, 0, part.length]),
        part,
        Buffer.from([0]),
      ]).toString('hex'),
    );

    if (!last) {
      assert.equal(response.sw, 0x9000, label);
      assert.equal(response.data.length, 0, label);
    }
  }

  const parts = [response.data];

  for (let count = 0; (response.sw & 0xff00) === 0x6100; count++) {
    assert(count < 256, 'Unterminated response chain');

    response = await bridge.raw(
      `${label}-response`,
      Buffer.from([0, 0xc0, 0, 0, response.sw & 255]).toString('hex'),
    );
    parts.push(response.data);
  }

  assert.equal(response.sw, 0x9000, label);

  const value = decode(Buffer.concat(parts));

  assert(!value.error, `${label}: ${JSON.stringify(value)}`);

  return value;
}

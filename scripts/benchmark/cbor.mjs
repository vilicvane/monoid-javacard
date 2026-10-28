import assert from 'node:assert/strict';

function head(major, value) {
  if (value < 24) return Buffer.from([(major << 5) | value]);

  const count = value <= 255 ? 1 : value <= 65535 ? 2 : 4;
  const bytes = Buffer.alloc(count + 1);

  bytes[0] = (major << 5) | {1: 24, 2: 25, 4: 26}[count];
  bytes.writeUIntBE(value, 1, count);

  return bytes;
}

/** Preserve insertion order: Monoid's recommended field order is not CTAP canonical order. */
export function encode(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);

    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);

  const entries = Object.entries(value);

  return Buffer.concat([
    head(5, entries.length),
    ...entries.flatMap(([key, child]) => [encode(key), encode(child)]),
  ]);
}

export function decode(bytes) {
  const input = Buffer.from(bytes);
  let offset = 0;

  function read() {
    assert(offset < input.length, 'Truncated CBOR');

    const first = input[offset++];
    const major = first >>> 5;
    const info = first & 31;

    if (major === 7) {
      assert([20, 21, 22].includes(info), 'Unsupported CBOR simple value');

      return info === 22 ? null : info === 21;
    }

    let length = info;

    if (info >= 24 && info !== 31) {
      const count = {24: 1, 25: 2, 26: 4}[info];

      assert(count && offset + count <= input.length, 'Invalid CBOR length');
      length = input.readUIntBE(offset, count);
      offset += count;
    }

    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2 || major === 3) {
      assert(info !== 31 && offset + length <= input.length, 'Invalid CBOR string');
      const value = input.subarray(offset, (offset += length));

      return major === 2
        ? Buffer.from(value)
        : new TextDecoder('utf-8', {fatal: true}).decode(value);
    }

    assert(major === 4 || major === 5, 'Unsupported CBOR type');
    const entries = [];

    for (let index = 0; info === 31 ? input[offset] !== 0xff : index < length; index++) {
      const value = read();

      entries.push(major === 5 ? [value, read()] : value);
    }
    if (info === 31) offset++;

    if (major === 4) return entries;

    assert(
      entries.every(([key]) => typeof key === 'string'),
      'Monoid response requires text map keys',
    );
    assert.equal(new Set(entries.map(([key]) => key)).size, entries.length, 'Duplicate map key');

    return Object.fromEntries(entries);
  }

  const result = read();

  assert.equal(offset, input.length, 'Trailing CBOR');

  return result;
}

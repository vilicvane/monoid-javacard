import assert from 'node:assert/strict';
import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  verify,
} from 'node:crypto';

// Independent host implementation; never imports authenticator crypto or CBOR code.
export const map = entries => new Map(entries);
export const sha256 = bytes => createHash('sha256').update(bytes).digest();

export const pinAuth = (token, bytes) =>
  createHmac('sha256', token).update(bytes).digest().subarray(0, 16);

export const hex = bytes => Buffer.from(bytes).toString('hex');

function head(major, length) {
  assert(Number.isSafeInteger(length) && length >= 0 && length <= 0xffffffff);

  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 255) return Buffer.from([(major << 5) | 24, length]);

  const bytes = Buffer.alloc(length <= 65535 ? 3 : 5);

  bytes[0] = (major << 5) | (bytes.length === 3 ? 25 : 26);

  if (bytes.length === 3) {
    bytes.writeUInt16BE(length, 1);
  } else {
    bytes.writeUInt32BE(length, 1);
  }

  return bytes;
}

export function encode(value) {
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (value === null) return Buffer.from([0xf6]);

  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');

    return Buffer.concat([head(3, bytes.length), bytes]);
  }

  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);

  const entries = value instanceof Map ? [...value] : Object.entries(value);
  const encoded = entries.map(([key, child]) => [encode(key), encode(child)]);

  // CTAP2 canonical sorting is major-type first, then length/lexicographic;
  // encoded lexicographic order is equivalent for the scalar keys CTAP uses.
  encoded.sort((a, b) => Buffer.compare(a[0], b[0]));

  for (let i = 1; i < encoded.length; i++) {
    assert(!encoded[i][0].equals(encoded[i - 1][0]), 'Duplicate CBOR key');
  }

  return Buffer.concat([head(5, encoded.length), ...encoded.flat()]);
}

export function decodeAt(bytes, offset = 0) {
  const input = Buffer.from(bytes);

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

    if (info >= 24) {
      const count = {24: 1, 25: 2, 26: 4}[info];

      assert(count && offset + count <= input.length, 'Invalid CBOR length');
      length = input.readUIntBE(offset, count);
      offset += count;
      assert(length >= (count === 1 ? 24 : count === 2 ? 256 : 65536), 'Nonminimal CBOR integer');
    }

    if (major === 0) return length;
    if (major === 1) return -1 - length;

    if (major === 2 || major === 3) {
      assert(offset + length <= input.length, 'Truncated CBOR bytes');

      const value = input.subarray(offset, offset + length);

      offset += length;

      return major === 2
        ? Buffer.from(value)
        : new TextDecoder('utf-8', {fatal: true}).decode(value);
    }

    if (major === 4) return Array.from({length}, read);

    assert.equal(major, 5, 'Unsupported CBOR type');

    const result = new Map();
    let previous;

    for (let i = 0; i < length; i++) {
      const start = offset;
      const key = read();
      const encoded = input.subarray(start, offset);

      assert(
        !previous || Buffer.compare(previous, encoded) < 0,
        'Noncanonical or duplicate CBOR key',
      );

      previous = encoded;
      result.set(key, read());
    }

    return result;
  }

  return {value: read(), offset};
}

export function decode(bytes) {
  const result = decodeAt(bytes);

  assert.equal(result.offset, bytes.length, 'Trailing CBOR');

  return result.value;
}

export class CtapNfc {
  constructor(bridge, {chunkSize = 240, getResponseCLA = 0x80} = {}) {
    this.bridge = bridge;
    this.chunkSize = chunkSize;
    this.getResponseCLA = getResponseCLA;
  }

  async command(
    command,
    request,
    {label = `ctap-${command.toString(16)}`, extended = false, p1 = 0, rawPayload} = {},
  ) {
    const payload =
      rawPayload ??
      Buffer.concat([
        Buffer.from([command]),
        request === undefined ? Buffer.alloc(0) : encode(request),
      ]);
    let response;
    let elapsedMs = 0;
    let requestFragments = 0;
    let responseFragments = 1;

    if (extended) {
      assert(payload.length <= 65535);

      const header = Buffer.alloc(7);

      header.set([0x80, 0x10, p1, 0, 0]);
      header.writeUInt16BE(payload.length, 5);

      response = await this.bridge.raw(
        label,
        hex(Buffer.concat([header, payload, Buffer.from([0, 0])])),
      );
      elapsedMs += response.elapsedMs;
      requestFragments++;
    } else {
      for (let offset = 0; offset < payload.length; offset += this.chunkSize) {
        const chunk = payload.subarray(offset, offset + this.chunkSize);
        const last = offset + chunk.length === payload.length;
        const frame = Buffer.concat([
          Buffer.from([last ? 0x80 : 0x90, 0x10, p1, 0, chunk.length]),
          chunk,
          last ? Buffer.from([0]) : Buffer.alloc(0),
        ]);
        response = await this.bridge.raw(`${label}-${requestFragments}`, hex(frame));
        elapsedMs += response.elapsedMs;
        requestFragments++;

        if (!last) {
          assert.equal(response.sw, 0x9000, `${label} intermediate APDU`);
          assert.equal(response.data.length, 0, `${label} intermediate response must be empty`);
        }
      }
    }

    const parts = [response.data];

    while ((response.sw & 0xff00) === 0x6100) {
      assert(responseFragments++ < 256, 'Response chain does not terminate');

      response = await this.bridge.raw(
        `${label}-response`,
        hex(Buffer.from([this.getResponseCLA, 0xc0, 0, 0, response.sw & 255])),
      );
      elapsedMs += response.elapsedMs;
      parts.push(response.data);
    }

    assert.equal(response.sw, 0x9000, `${label} unexpected ISO status`);

    const data = Buffer.concat(parts);

    assert(data.length > 0, 'Missing CTAP status');

    return {
      label,
      status: data[0],
      value: data.length > 1 ? decode(data.subarray(1)) : undefined,
      raw: data,
      elapsedMs,
      requestFragments,
      responseFragments,
    };
  }

  async ok(command, request, options) {
    const response = await this.command(command, request, options);

    assert.equal(
      response.status,
      0,
      `${response.label} CTAP status ${response.status.toString(16)}`,
    );

    return response.value;
  }

  async expect(status, command, request, options) {
    const response = await this.command(command, request, options);

    assert.equal(response.status, status, `${response.label} expected CTAP ${status.toString(16)}`);

    return response;
  }
}

export function aesCBC(key, bytes, decrypt = false) {
  const cipher = (decrypt ? createDecipheriv : createCipheriv)(
    'aes-256-cbc',
    key,
    Buffer.alloc(16),
  );

  cipher.setAutoPadding(false);

  return Buffer.concat([cipher.update(bytes), cipher.final()]);
}

export function coseFromPoint(point, algorithm = -25) {
  assert.equal(point.length, 65);
  assert.equal(point[0], 4);

  return map([
    [1, 2],
    [3, algorithm],
    [-1, 1],
    [-2, point.subarray(1, 33)],
    [-3, point.subarray(33, 65)],
  ]);
}

export function pointFromCose(cose, algorithm) {
  assert.equal(cose.get(1), 2);
  assert.equal(cose.get(-1), 1);

  if (algorithm !== undefined) assert.equal(cose.get(3), algorithm);

  assert.equal(cose.get(-2).length, 32);
  assert.equal(cose.get(-3).length, 32);

  return Buffer.concat([Buffer.from([4]), cose.get(-2), cose.get(-3)]);
}

export class PinProtocol1 {
  constructor(ctap) {
    this.ctap = ctap;
  }

  async retries() {
    return (
      await this.ctap.ok(
        0x06,
        map([
          [1, 1],
          [2, 1],
        ]),
      )
    ).get(3);
  }

  async agree() {
    const peer = (
      await this.ctap.ok(
        0x06,
        map([
          [1, 1],
          [2, 2],
        ]),
      )
    ).get(1);
    const key = createECDH('prime256v1');

    key.generateKeys();
    this.keyAgreement = coseFromPoint(key.getPublicKey());
    this.sharedSecret = sha256(key.computeSecret(pointFromCose(peer, -25)));
  }

  padPIN(pin) {
    const bytes = Buffer.from(pin, 'utf8');

    assert(bytes.length >= 4 && bytes.length < 64);

    const padded = Buffer.alloc(64);

    bytes.copy(padded);

    return padded;
  }

  async set(pin) {
    await this.agree();

    const encrypted = aesCBC(this.sharedSecret, this.padPIN(pin));

    return this.ctap.ok(
      0x06,
      map([
        [1, 1],
        [2, 3],
        [3, this.keyAgreement],
        [4, pinAuth(this.sharedSecret, encrypted)],
        [5, encrypted],
      ]),
      {label: 'pin-set'},
    );
  }

  async change(current, next) {
    await this.agree();

    const encrypted = aesCBC(this.sharedSecret, this.padPIN(next));
    const oldHash = aesCBC(this.sharedSecret, sha256(Buffer.from(current)).subarray(0, 16));

    return this.ctap.ok(
      0x06,
      map([
        [1, 1],
        [2, 4],
        [3, this.keyAgreement],
        [4, pinAuth(this.sharedSecret, Buffer.concat([encrypted, oldHash]))],
        [5, encrypted],
        [6, oldHash],
      ]),
      {label: 'pin-change'},
    );
  }

  async getToken(pin, expectedStatus = 0) {
    await this.agree();

    const encrypted = aesCBC(this.sharedSecret, sha256(Buffer.from(pin)).subarray(0, 16));
    const result = await this.ctap.expect(
      expectedStatus,
      0x06,
      map([
        [1, 1],
        [2, 5],
        [3, this.keyAgreement],
        [6, encrypted],
      ]),
      {label: expectedStatus ? 'pin-wrong' : 'pin-token'},
    );

    if (expectedStatus) return result;

    this.token = aesCBC(this.sharedSecret, result.value.get(2), true);
    assert.equal(this.token.length, 32);

    return this.token;
  }

  authenticate(clientDataHash) {
    assert(this.token);

    return pinAuth(this.token, clientDataHash);
  }
}

export function parseAuthData(input) {
  const data = Buffer.from(input);

  assert(data.length >= 37);

  const result = {
    data,
    rpIdHash: data.subarray(0, 32),
    flags: data[32],
    counter: data.readUInt32BE(33),
  };
  let offset = 37;

  if (result.flags & 0x40) {
    assert(data.length >= 55);

    result.aaguid = data.subarray(37, 53);

    const length = data.readUInt16BE(53);

    offset = 55 + length;
    assert(offset < data.length);
    result.credentialId = data.subarray(55, offset);

    const cose = decodeAt(data, offset);

    result.cose = cose.value;
    offset = cose.offset;
  }

  if (result.flags & 0x80) {
    const extensions = decodeAt(data, offset);

    result.extensions = extensions.value;
    offset = extensions.offset;
  }

  assert.equal(offset, data.length, 'Unexpected authenticator data tail');

  return result;
}

export function publicKeyFromCose(cose) {
  const point = pointFromCose(cose, -7);

  return createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: point.subarray(1, 33).toString('base64url'),
      y: point.subarray(33).toString('base64url'),
    },
    format: 'jwk',
  });
}

export function verifyAuthData(data, rpId, {uv = false, up = true, attested = false} = {}) {
  const auth = parseAuthData(data);

  assert.deepEqual(auth.rpIdHash, sha256(Buffer.from(rpId)), 'RP binding');
  assert.equal(Boolean(auth.flags & 1), up, 'UP flag');
  assert.equal(Boolean(auth.flags & 4), uv, 'UV flag');
  assert.equal(Boolean(auth.flags & 0x40), attested, 'AT flag');
  assert.equal(auth.flags & 0x3a, 0, 'Reserved/unsupported flags');
  assert.equal(auth.counter, 0, 'Approved no-counter policy');

  return auth;
}

export function verifyMakeCredential(response, rpId, clientDataHash, flags) {
  assert.equal(response.get(1), 'packed');

  const auth = verifyAuthData(response.get(2), rpId, {...flags, attested: true});
  const statement = response.get(3);

  assert.equal(statement.get('alg'), -7);
  assert(!statement.has('x5c'), 'Expected self attestation');
  assert.equal(auth.credentialId.length, 32);

  const key = publicKeyFromCose(auth.cose);
  const signature = statement.get('sig');

  assert(
    verify('sha256', Buffer.concat([auth.data, clientDataHash]), key, signature),
    'Invalid make-credential DER ECDSA signature',
  );

  return {...auth, key};
}

export function verifyAssertion(response, rpId, clientDataHash, credential, flags) {
  if (response.has(1)) {
    assert.equal(response.get(1).get('type'), 'public-key');
    assert.deepEqual(response.get(1).get('id'), credential.credentialId);
  }

  const auth = verifyAuthData(response.get(2), rpId, flags);

  assert(
    verify('sha256', Buffer.concat([auth.data, clientDataHash]), credential.key, response.get(3)),
    'Invalid assertion DER ECDSA signature',
  );

  if (!flags?.uv && response.has(4)) {
    for (const key of response.get(4).keys()) {
      assert.equal(key, 'id', 'User identifying information without UV');
    }
  }

  return auth;
}

export const newClientDataHash = () => sha256(randomBytes(32));
export const descriptor = credential => ({type: 'public-key', id: credential.credentialId});

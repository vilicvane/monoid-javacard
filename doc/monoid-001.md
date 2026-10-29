# Monoid-001: Context-based key derivation

API identifier: `monoid-001`.

Monoid-001 derives a secp256r1 scalar or Ed25519 private-key seed from a
64-byte seed and opaque context bytes. It uses
[RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869#section-2)
with SHA-512. The secp256r1 branch follows the P-256 rejection-sampling pattern in
[RFC 9180 section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180#section-7.1.3).
Its labels, hash and context binding define a separate scheme; it does not
implement HPKE's `DeriveKeyPair` or SLIP-0010.

## Inputs and encoding

- `seed`: 64 bytes of secret seed material.
- `context`: an arbitrary byte string, including the empty string.
- `curve`: `secp256r1` (default) or `ed25519`.
- `label`: the ten ASCII bytes `Monoid-001`, without a terminator.
- `n`: the secp256r1 subgroup order,
  `ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`.

`||` denotes byte concatenation. `I2OSP(counter, 1)` encodes an unsigned
integer as exactly one byte. `OS2IP` interprets a byte string as an unsigned
big-endian integer. No text conversion, normalization or hashing is applied
to `context` before the operations below.

## Master generation

```text
master = HKDF-Extract-SHA512(salt = label, IKM = seed)
       = HMAC-SHA512(key = label, data = seed)
```

The internal master is this complete 64-byte PRK. It is not a private scalar
followed by a chain code.

## Context derivation

### secp256r1

```text
for counter = 0 through 255:
    info = label || 0x00 || context || I2OSP(counter, 1)
    candidate = HKDF-Expand-SHA512(PRK = master, info = info, L = 32)
    d = OS2IP(candidate)
    if 1 <= d < n:
        return candidate
fail
```

Because SHA-512 produces 64 bytes and `L = 32`, each candidate is the first
32 bytes of:

```text
HMAC-SHA512(key = master, data = label || 0x00 || context || counter || 0x01)
```

The retry counter starts at `0x00`; the final `0x01` is HKDF's first-block
counter. They are separate bytes. The first valid candidate is used without
modular reduction or an added constant. If all 256 candidates fail, derivation
fails without returning a key or wrapping the retry counter.

### Ed25519

```text
info = label || 0x01 || context || 0x00
privateKeySeed = HKDF-Expand-SHA512(PRK = master, info = info, L = 32)
```

Equivalently, take the first 32 bytes of:

```text
HMAC-SHA512(key = master, data = label || 0x01 || context || 0x00 || 0x01)
```

The byte immediately after `label` separates the two curves: `0x00` for
secp256r1, `0x01` for Ed25519. The byte after `context` is fixed at `0x00`
for Ed25519; the final `0x01` remains HKDF's first-block counter.

All 32-byte outputs are valid Ed25519 private-key seeds. There is no rejection
sampling or modular reduction. Key expansion and clamping occur when this seed
is used by [RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5).
The result is a seed, not an expanded scalar or an extended private key.

## API mapping

```ts
type KeyMonoid001 = {
  index: byte[];
  type: 'seed';
  derivation: {
    type: 'monoid-001';
    /** Omitted selects secp256r1. */
    curve?: 'secp256r1' | 'ed25519';
    context: byte[];
  };
};
```

| Curve       | View key (`0x40`)                  | Sign (`0x41`) input                           | Signature                           |
| ----------- | ---------------------------------- | --------------------------------------------- | ----------------------------------- |
| `secp256r1` | 33-byte compressed public key `dG` | `cipher: 'ecdsa'`, 32-byte `digest`           | 64 bytes: `r` followed by low-S `s` |
| `ed25519`   | 32-byte public key                 | `cipher: 'ed25519'`, original `message` bytes | 64-byte pure Ed25519                |

Neither branch returns `chainCode` or accepts `path` or `taproot` (including
`false`). Independent private-key items do not accept this derivation.
Applet grant key descriptors use the same `curve` selection. The existing
`Monoid.getMonoid001PublicKey` and `signMonoid001ECDSADigest` Shareable methods
continue to use secp256r1.

The same seed, curve and context produce the same key. The index, metadata,
alias, signing digest or message, and card identity
are not derivation inputs. Empty context still derives a key; it does not
select a master scalar.

Applications define stable context encodings and distinguish their purposes.
A Passkey application can bind its purpose, RP ID and Credential ID in that
encoding. Credential discovery, RP authorization and credential metadata
remain application responsibilities. This specification does not define a
Passkey credential format.

## Test vectors

All values are hexadecimal. These public fixtures are not production secrets.
All vectors use:

```text
seed =
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

master =
6056a2488cc46e6902d97942968be1d80cba5f7e80a4e963e14035701e214441b8
bdf93dcdcfeedd9ed12faeeb4de5865caf57a5e9b9418474719dcc4efd0b51
```

### secp256r1, empty context

```text
context = (empty)
counter = 00
privateKey = 9858d02b1d88118d84a69262fdf7526417803c9b44c66455493840f658be9f9c
publicKey = 025ba8761994ac159a921f4ea3d46ef333849eda9441c540b9997cc438a018d458
```

### secp256r1, binary context

```text
context = 00010200ff
counter = 00
privateKey = 87377011608e75faab88369db70913f0e885b2e84bb3b04fafe3f4d0586a9e3e
publicKey = 027b09b64420ee4a22f3b8cd3bbe22c08b77c35003b105d8f050bb39b5bd947de9
```

### Ed25519, empty context

```text
context = (empty)
privateKeySeed = 3ca45f0809035fdfc7820573d8c3d0829939945aef1361517f0f44f4ecdeabc8
publicKey = 3bac0815174a5af3eed1636eef4ff0b7f3fa225f952c40a64d84012449fb8273
```

### Ed25519, binary context

```text
context = 00010200ff
privateKeySeed = 83e8916442da94f6b66e13836b0f065c60825eaf87955d876044e01fe1be9b39
publicKey = 62e52cd8effc619db4a8daa340b5aa8f56d506e38710d2d5ee7b1ed1cf43ce89
```

The Ed25519 vectors were generated independently using Node.js
`crypto.hkdfSync('sha512', seed, label, info, 32)` and Ed25519 key generation.
The secp256r1 vectors and outputs remain unchanged.

Monoid-001 fixes these input meanings and derived outputs. Incompatible
derivation rules require a different specification identifier; implementation
optimizations and document clarifications do not change it.

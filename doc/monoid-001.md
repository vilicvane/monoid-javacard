# Monoid-001: Context-based P-256 key derivation

API identifier: `monoid-001`.

Monoid-001 derives a secp256r1 private key from a seed and
opaque context bytes. It uses [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869#section-2)
with SHA-512 and follows the P-256 rejection-sampling pattern in
[RFC 9180 section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180#section-7.1.3).
Its labels, hash and context binding define a separate scheme; it does not
implement HPKE's `DeriveKeyPair` or SLIP-0010.

## Inputs and encoding

- `seed`: 64 bytes of secret seed material.
- `context`: an arbitrary byte string, including the empty string.
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

## API mapping

```ts
type KeyMonoid001 = {
  index: byte[];
  type: 'seed';
  derivation: {
    type: 'monoid-001';
    context: byte[];
  };
};
```

View key (`0x40`) returns the 33-byte compressed public key `dG`, without
`chainCode`. Sign (`0x41`) accepts `cipher: 'ecdsa'` and a 32-byte `digest`,
returning the existing 64-byte low-S `r || s` signature. Neither command
accepts `taproot` for this scheme, including `false`. The derivation has no
`curve` or `path` override. Independent private-key items do not accept it.

The same seed and the same context produce
the same key. The index, lookup key, alias, signing digest and card identity
are not derivation inputs. Empty context still derives a key; it does not
select a master scalar.

Applications define stable context encodings and distinguish their purposes.
A Passkey application can bind its purpose, RP ID and Credential ID in that
encoding. Credential discovery, RP authorization and credential metadata
remain application responsibilities. This specification does not define a
Passkey credential format.

## Test vectors

All values are hexadecimal. These public fixtures are not production secrets.
Both vectors use:

```text
seed =
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

master =
6056a2488cc46e6902d97942968be1d80cba5f7e80a4e963e14035701e214441b8
bdf93dcdcfeedd9ed12faeeb4de5865caf57a5e9b9418474719dcc4efd0b51
```

### Empty context

```text
context = (empty)
counter = 00
privateKey = 9858d02b1d88118d84a69262fdf7526417803c9b44c66455493840f658be9f9c
publicKey = 025ba8761994ac159a921f4ea3d46ef333849eda9441c540b9997cc438a018d458
```

### Binary context

```text
context = 00010200ff
counter = 00
privateKey = 87377011608e75faab88369db70913f0e885b2e84bb3b04fafe3f4d0586a9e3e
publicKey = 027b09b64420ee4a22f3b8cd3bbe22c08b77c35003b105d8f050bb39b5bd947de9
```

Monoid-001 fixes these input meanings and derived outputs. Incompatible
derivation rules require a different specification identifier; implementation
optimizations and document clarifications do not change it.

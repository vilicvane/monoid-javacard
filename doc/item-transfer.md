# Encrypted item transfer

Export and Import transfer one authenticated Safe item. The commands and their
authorization requirements are defined in [README](../README.md#iso-7816-commands).
The `data` field carries the binary envelope below; `index`, `key` and `alias`
remain public and are authenticated with it. Keep the Export request's original
index with its response for Import.

## Envelope

For an item containing `n` data bytes:

| Offset  | Length  | Value                                |
| ------- | ------- | ------------------------------------ |
| 0       | 1       | Version: `01`                        |
| 1       | 113     | Identity-encrypted communication key |
| 114     | 12      | Payload AES-GCM nonce                |
| 126     | `n + 2` | Payload ciphertext                   |
| `128+n` | 16      | Payload AES-GCM authentication tag   |

The total length is `n + 144` bytes. Payload length is inferred from the CBOR byte
string's length; there is no additional length field. Unknown versions and
envelopes shorter than 144 bytes are rejected.

The communication-key envelope follows [Safe Identity](safe-identity.md):
RFC 9180 Auth with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM. Its 113
bytes are `enc[65] || ciphertext[32] || tag[16]`. The long-term sender and recipient
public keys are uncompressed 65-byte SEC 1 points. The sender public key is supplied
separately to Import; `enc` is the ephemeral public key, not the sender identity.

## Metadata context

All lengths and short values below use unsigned big-endian encoding. `||` denotes
byte concatenation, and quoted labels are ASCII without a terminator.

```text
nullable(null)  = FF FF
nullable(value) = u16(length(value)) || value

context = SHA-256(
  "Monoid Item" || 01 || index || nullable(key) || nullable(alias)
)
```

`index` is exactly 10 bytes: two type bytes followed by the eight-byte identifier.
`key` is the exact byte string. `alias` is its exact UTF-8 encoding, without Unicode
normalization. An omitted optional field uses `null`; an empty byte string or alias
uses length `0000`. These encodings are distinct. Length `FFFF` is reserved for
null; lengths count bytes rather than characters.

The 32-byte context is the HPKE `info` for protecting the communication key and is
also included in payload-key derivation. Changing the index, either optional
field, or whether a field is omitted invalidates the artifact.

## Payload encryption

Each Export generates a fresh random 32-byte communication key and a fresh random
12-byte payload nonce. Identity makes a fresh HPKE encapsulation for that key.

Derive the 16-byte payload key with RFC 5869 HKDF-SHA256:

```text
PRK = HKDF-Extract(salt = empty, IKM = communicationKey)
K   = HKDF-Expand(PRK, info = "Monoid Item Key" || context, L = 16)
```

An empty salt is equivalent to 32 zero bytes. For this one-block expansion:

```text
K = HMAC-SHA256(PRK, "Monoid Item Key" || context || 01)[0:16]
```

The plaintext is:

```text
u16(secret) || itemData

secret = 5A FE  when true
secret = A5 01  when false
```

Encrypt it with AES-128-GCM, the envelope's 12-byte nonce, empty AAD and a full
16-byte tag. The metadata context authenticates public fields through HPKE and
key derivation; the payload tag authenticates the secret flag and item data.

Import authenticates the communication key, decrypts into a Safe-owned buffer,
and verifies the complete payload tag before returning plaintext to Safe.
The buffer uses transient memory when available, otherwise temporary persistent storage.
Successful tag verification is repeated three times. Safe accepts only the two
defined secret encodings before committing an item. Invalid artifacts cannot
publish a plaintext result or modify an existing item.

## Trust and retries

Export's recipient public key and Import's expected sender public key must come
from the application's trust decision. The envelope does not establish that an
unverified public key belongs to the intended physical card. The four-byte Safe
display ID is not a cryptographic identity fingerprint.

An artifact is encrypted for one recipient Identity, which may be the sender
itself. Retaining that Identity permits importing after Safe replacement. A
different recipient requires a new Export.

Retrying an existing artifact does not re-encrypt it. Re-exporting generates a new
key, nonce and envelope. Import succeeds without mutation when the existing item
has identical index, key, alias, secret and data; different contents conflict.
Items commit independently. The format does not authenticate a complete batch or
detect omitted items, and does not provide rollback or replay protection.

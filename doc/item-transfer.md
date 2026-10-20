# Encrypted item transfer

Export and Import transfer one authenticated Safe item. The commands and their
authorization requirements are defined in [README](../README.md#iso-7816-commands).
The `data` field carries the binary envelope below; `index`, `key` and `alias`
remain public and are authenticated with it. Keep the Export request's original
index with its response for Import.

## Asymmetric envelope (`01`)

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
version `01` envelopes shorter than 144 bytes are rejected.

The communication-key envelope follows [Monoid Identity](identity.md):
RFC 9180 Auth with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM. Its 113
bytes are `enc[65] || ciphertext[32] || tag[16]`. The long-term sender and recipient
public keys are uncompressed 65-byte SEC 1 points. The sender public key is supplied
separately to Import; `enc` is the ephemeral public key, not the sender identity.

This format is exported only when the card has no Bundle. The recipient public
key is required. An enrolled card can still import version `01` artifacts addressed
to its Identity.

## Bundle envelope (`02`)

For an item containing `n` data bytes:

| Offset | Length  | Value                              |
| ------ | ------- | ---------------------------------- |
| 0      | 1       | Version: `02`                      |
| 1      | 32      | Bundle hash: `SHA-256(bundleKey)`  |
| 33     | 32      | HKDF salt                          |
| 65     | 12      | Payload AES-GCM nonce              |
| 77     | `n + 2` | Payload ciphertext                 |
| `79+n` | 16      | Payload AES-GCM authentication tag |

The total length is `n + 95` bytes. Identity generates a fresh salt and nonce for
each Export. Import requires a local Bundle with the same hash and validates the
payload using its stored Bundle key. Unknown versions and version `02` envelopes
shorter than 95 bytes are rejected.

Enrolled cards always export this format, even when `recipientPublicKey` is
supplied. Import does not need `senderPublicKey`: the artifact authenticates the
Bundle, not an individual member. See [Bundle](bundle.md) for enrollment and reinitialization.

## Metadata context

All lengths and short values below use unsigned big-endian encoding. `||` denotes
byte concatenation, and quoted labels are ASCII without a terminator.

```text
nullable(null)  = FF FF
nullable(value) = u16(length(value)) || value

context = SHA-256(
  "Monoid Item" || version || u8(length(callerAID)) || callerAID
  || index || nullable(key) || nullable(alias)
)
```

`index` is exactly 10 bytes: two type bytes followed by the eight-byte identifier.
`key` is the exact byte string. `alias` is its exact UTF-8 encoding, without Unicode
normalization. An omitted optional field uses `null`; an empty byte string or alias
uses length `0000`. These encodings are distinct. Length `FFFF` is reserved for
null; lengths count bytes rather than characters.

`callerAID` is the full calling applet AID obtained by Identity from the Java Card
runtime. It is not supplied by the host or carried as a selectable envelope field.
The receiving applet must have the same AID as the sender. Monoid uses its fixed
instance AID; other applets can use the same algorithms in their own domains.

`version` is the envelope's single version byte (`01` or `02`). The 32-byte context
is included in payload-key derivation and, for version `01`, is the HPKE `info`
protecting the communication key. Changing the caller AID, index, either optional field, or
whether a field is omitted invalidates the artifact.

## Payload encryption

For version `01`, each Export generates a fresh random 32-byte communication key
and a fresh random 12-byte payload nonce. Identity makes a fresh HPKE encapsulation
for that key.

Derive the 16-byte payload key with RFC 5869 HKDF-SHA256:

```text
PRK = HKDF-Extract(salt = empty, IKM = communicationKey)
K   = HKDF-Expand(PRK, info = "Monoid Item Key" || context, L = 16)
```

An empty salt is equivalent to 32 zero bytes. For this one-block expansion:

```text
K = HMAC-SHA256(PRK, "Monoid Item Key" || context || 01)[0:16]
```

Version `02` first derives a caller-specific key from the persistent Bundle root,
then uses the envelope's 32-byte random salt:

```text
callerKey = HMAC-SHA256(
  bundleKey, "Monoid Bundle Caller Key" || u8(length(callerAID)) || callerAID
)
PRK = HKDF-Extract(salt = envelope.salt, IKM = callerKey)
K   = HKDF-Expand(PRK, info = "Monoid Bundle Item Key" || context, L = 16)
```

The plaintext is:

```text
u16(secret) || itemData

secret = 5A FE  when true
secret = A5 01  when false
```

Encrypt it with AES-128-GCM, the envelope's 12-byte nonce, empty AAD and a full
16-byte tag. The metadata context authenticates public fields through key
derivation and, for version `01`, HPKE. The payload tag authenticates the secret
flag and item data.

Identity performs the complete encryption and decryption. Import decrypts into
a private buffer and verifies the complete payload tag before making plaintext
available to Monoid for storage. Item data crosses the applet boundary in bounded
ranges; Export and Import do not require a complete global array for the artifact.
Successful tag verification is repeated three times. Safe accepts only the two
defined secret encodings before committing an item. Invalid artifacts cannot
publish a plaintext result or modify an existing item.

## Trust and retries

For asymmetric transfer, Export's recipient public key and Import's expected
sender public key must come from the application's trust decision. For Bundle
transfer, that decision applies when establishing the fixed membership. Neither
envelope establishes that an unverified public key belongs to the intended
physical card. The four-byte display ID is not a cryptographic identity fingerprint.

An asymmetric artifact targets one Identity, which may be the sender itself;
a different recipient requires a new Export. A Bundle artifact can be imported
by the same applet AID on any member holding the shared key. Retaining Identity and its Bundle state
permits importing the corresponding artifacts after Monoid replacement.

`0xFF Reset` clears local items, both PINs, authorization and the Bundle together,
preserving the Identity. New PINs must be initialized before importing artifacts.
It does not revoke copies on other cards or exported artifacts. Old asymmetric
artifacts remain addressed to the retained Identity; old Bundle artifacts require
rejoining their original Bundle before they can be imported.

Retrying an existing artifact does not re-encrypt it. Re-exporting generates a new
communication key or Bundle salt, nonce and envelope. Import succeeds without
mutation when the existing item
has identical index, key, alias, secret and data; different contents conflict.
Items commit independently. The format does not authenticate a complete batch or
detect omitted items, and does not provide rollback or replay protection.

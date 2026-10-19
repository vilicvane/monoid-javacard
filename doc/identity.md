# Monoid Identity

Monoid Identity retains a P-256 key pair and a four-byte random ID generated on
installation. Its private key has no export or replacement interface. Identity
also owns the optional Bundle key and fixed membership, and performs complete
item encryption and decryption. Monoid owns both PINs, Safe item storage and
command authorization.

Install Identity before Monoid. Monoid updates preserve its matching Identity.
Deleting Identity removes its private key and local Bundle state.

## Interface

```java
public interface IdentityShareable extends Shareable {
  byte[] getId();

  byte[] getPublicKey();

  /** SHA-256 of the Bundle key, or null when not enrolled. */
  byte[] getBundle();

  /** Generates/replaces; returns concatenated enrollment packets in input order, excluding self. */
  CommunicationDataShareable createBundle(byte[] publicKeys);

  /** Returns the hash of the actually stored Bundle after import or an identical retry. */
  byte[] importBundle(byte[] senderPublicKey, byte[] data);

  void resetBundle();

  CommunicationDataShareable encryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  );

  /** Returns secret (two bytes) || data after authenticating the complete envelope. */
  CommunicationDataShareable decryptData(
    byte[] index,
    byte[] key,
    byte[] alias,
    byte[] senderPublicKey,
    CommunicationDataShareable data
  );
}

public interface CommunicationDataShareable extends Shareable {
  short getLength();

  void read(short dataOffset, byte[] buffer, short offset, short length);
}
```

- ID: four random bytes, generated once at Identity installation.
- Public keys: 65-byte SEC 1 uncompressed P-256 points (`04 || X || Y`).
- Bundle keys and asymmetric item communication keys: 32 bytes, kept inside Identity.
- Metadata: ten-byte index, optional byte-string key and optional UTF-8 alias.
  Null and empty fields remain distinct.
- Byte-array arguments and direct results: global arrays for card-local calls.
  Data sources use repeatable range reads through a bounded global buffer.
- Completed data results are readable only by their original calling applet.
- Admission: Monoid's version-independent AID prefix, checked on acquisition and invocation.
- Direct APDUs: SELECT only. Monoid owns [item transfer](item-transfer.md) and
  [Bundle management](bundle.md) commands; Hello exposes `id`, `publicKey` and
  `bundle` directly.

Identity derives authenticated contexts internally from the operation and
metadata. Callers cannot supply arbitrary HPKE contexts or retrieve decrypted
communication or Bundle keys. Enrollment and ordinary item transfer use separate
cryptographic domains. With a Bundle installed, item encryption always uses it;
`recipientPublicKey` is ignored. Decryption dispatches by envelope version and
still accepts asymmetric items addressed to the local Identity.

## HPKE profile

The fixed [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) profile is:

| Parameter            | Value                               |
| -------------------- | ----------------------------------- |
| Mode                 | Auth (`0x02`)                       |
| KEM                  | DHKEM(P-256, HKDF-SHA256), `0x0010` |
| KDF                  | HKDF-SHA256, `0x0001`               |
| AEAD                 | AES-128-GCM, `0x0001`               |
| HPKE info            | Operation-specific context hash     |
| AEAD additional data | Empty                               |
| Message sequence     | Zero; fresh encapsulation per call  |

```text
encrypted key (113 bytes)
┌────────────────────┬──────────────────────┬────────────────┐
│ enc: ephemeral key │ encrypted key        │ GCM tag        │
│ 65 bytes           │ 32 bytes             │ 16 bytes       │
└────────────────────┴──────────────────────┴────────────────┘
```

Encryption authenticates the local Identity and targets `recipientPublicKey`.
Decryption uses the local private key and authenticates `senderPublicKey` and the
operation's context before using the key inside Identity. Self-encryption uses the
local public key for both roles. The domains and complete envelopes are specified
in [item transfer](item-transfer.md) and [Bundle](bundle.md).

`createBundle` receives concatenated 65-byte public keys. Its result contains
equal-length enrollment packets in input order with self omitted. Identity
encrypts all packets before atomically publishing the new key and membership.
Monoid reads the result by range and associates each packet with its recipient
in the Create Bundle response.

The caller must obtain the expected peer public key through its trust mechanism;
the envelope does not establish that trust. AID admission isolates applets but
does not authenticate installed code. Item transfer has no single-use restriction;
Bundle import is idempotent only for an identical key and membership. Bundle creation
always generates a new key and replaces the local Bundle.

## Safe ID

Hello returns the ID stored in Identity. Card reset, Bundle replacement/clearing, Monoid
replacement and PIN changes preserve it; reinstalling Identity generates a new ID.
The four-byte random value
is a display identifier, not a peer authentication fingerprint or a guarantee of
uniqueness. It is independent of the public key.

## Card requirements

P-256 key generation, ECDH `ALG_EC_SVDP_DH_PLAIN_XY`, SHA-256 and AES
`ALG_AES_BLOCK_128_ECB_NOPAD` are required. GCM combines native AES with software
CTR and GHASH, using a 12-byte nonce and 16-byte tag.
Digest, cipher and key agreement instances must support shared access.
Transient cryptographic buffers and keys use reset-scoped storage for nested SIO
calls; temporary private arrays use persistent storage.
The native ECDH implementation must reject off-curve points; canonical encoding
and coordinate ranges are checked before it is called.

Simulator and host tests cover key scheduling, independent decryption and malformed
inputs. They do not establish physical-card support, firewall behavior or timing
for a newly added operation; those require separate card verification.

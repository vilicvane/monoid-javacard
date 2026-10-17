# Safe Identity

Safe Identity retains a P-256 key pair and a four-byte random ID generated on
installation. Its private key has no export or replacement interface. Safe owns
PINs, permissions and item data; Identity owns no Safe objects or sessions.

Install Identity before Safe, then Monoid. Ordinary Safe updates preserve Identity.
Deleting Identity loses access to communication keys encrypted to that identity.
The allocation and earlier-AID migration boundary are in [Architecture](architecture.md).

## Interface

```java
public interface SafeIdentityShareable extends Shareable {
  byte[] getId();

  byte[] getPublicKey();

  byte[] encryptCommunicationKey(byte[] recipientPublicKey, byte[] context, byte[] key);

  byte[] decryptCommunicationKey(byte[] senderPublicKey, byte[] context, byte[] encryptedKey);
}
```

- ID: four random bytes, generated once at Identity installation.
- Public keys: 65-byte SEC 1 uncompressed P-256 points (`04 || X || Y`).
- Communication keys: 32 bytes.
- Context: byte string; empty is valid. Decryption requires the same bytes.
- Arguments and results: global arrays for card-local cross-context calls.
- Admission: Safe's version-independent AID prefix, checked on acquisition and invocation.
- Direct APDUs: SELECT only. [Item transfer](item-transfer.md) belongs to Safe/Monoid;
  Hello with `safe: true` exposes the Identity public key as `safe.publicKey`.

## Encryption format

The fixed [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) profile is:

| Parameter            | Value                               |
| -------------------- | ----------------------------------- |
| Mode                 | Auth (`0x02`)                       |
| KEM                  | DHKEM(P-256, HKDF-SHA256), `0x0010` |
| KDF                  | HKDF-SHA256, `0x0001`               |
| AEAD                 | AES-128-GCM, `0x0001`               |
| HPKE info            | `context`                           |
| AEAD additional data | Empty                               |
| Message sequence     | Zero; fresh encapsulation per call  |

```text
encryptedKey (113 bytes)
┌────────────────────┬──────────────────────┬────────────────┐
│ enc: ephemeral key │ encrypted key        │ GCM tag        │
│ 65 bytes           │ 32 bytes             │ 16 bytes       │
└────────────────────┴──────────────────────┴────────────────┘
```

Encryption authenticates the local Identity and targets `recipientPublicKey`.
Decryption uses the local private key and authenticates `senderPublicKey` and
`context` before releasing the communication key. Self-encryption uses the local
public key for both roles. Cryptographic errors return no key.

The caller must obtain the expected peer public key through its trust mechanism;
the envelope does not establish that trust. AID admission isolates applets but
does not authenticate installed code. Replay policy belongs to the communication
protocol; this interface has no transfer state or single-use restriction.

## Safe ID

Safe returns the ID stored in Identity. Reset, Safe replacement and PIN changes
preserve it; reinstalling Identity generates a new ID. The four-byte random value
is a display identifier, not a peer authentication fingerprint or a guarantee of
uniqueness. It is independent of the public key.

## Card requirements

P-256 key generation, ECDH `ALG_EC_SVDP_DH_PLAIN_XY`, SHA-256 and AES
`ALG_AES_BLOCK_128_ECB_NOPAD` are required. GCM combines native AES with software
CTR and GHASH, using a 12-byte nonce and 16-byte tag.
Digest, cipher and key agreement instances must support shared access;
working buffers and transient keys use reset-scoped storage for nested SIO calls.
The native ECDH implementation must reject off-curve points; canonical encoding
and coordinate ranges are checked before it is called.

Simulator tests cover RFC-derived key scheduling, independent host decryption,
tampering, malformed points and Identity/Safe lifecycle. Physical-card support,
firewall behavior and deletion remain separate acceptance checks.

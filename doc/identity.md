# Monoid Identity

Monoid Identity retains a P-256 key pair and a four-byte random ID generated on
installation or `0xFF Reset`. Its private key has no export interface. Identity
also owns Secret PIN, its retry and caller authorization state, the optional Bundle
key and fixed membership. It performs complete item encryption and decryption
for applets in separate caller domains. Monoid owns Access PIN, Safe item storage
and command authorization.

Install Identity before Monoid. Monoid updates preserve its matching Identity.
Deleting Identity removes its private key, binding secret, Secret PIN and local
Bundle state.

## Interface

```java
public interface IdentityShareable extends Shareable {
  /** Stable private binding token for the runtime caller's complete AID. */
  byte[] getToken();

  byte[] getId();

  byte[] getPublicKey();

  /** SHA-256 of the Bundle key, or null when not enrolled. */
  byte[] getBundle();

  boolean isSecretPINSet();

  short getSecretPINTriesRemaining();

  /** Verifies a global PIN buffer and authorizes only the runtime caller. */
  boolean checkSecretPIN(byte[] pin);

  /** Monoid only: initializes Secret PIN, or changes it after Secret authentication. */
  void updateSecretPIN(byte[] pin);

  /** Returns the encoded authorization result for the runtime caller. */
  short getSecretPINValidationResult();

  void clearSecretAuth();

  /** Requires Secret authentication and no Bundle; packets exclude self, in input order. */
  CommunicationDataShareable createBundle(byte[] publicKeys);

  /** Requires Secret authentication; identical enrollment is idempotent. */
  byte[] joinBundle(byte[] senderPublicKey, byte[] data);

  /** Monoid only: prepares a new identity outside a transaction and returns its caller token. */
  byte[] prepareReset();

  /** Monoid only: publishes the prepared identity within Monoid's reset transaction. */
  void reset();

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

- ID: four random bytes, regenerated at Identity installation or `0xFF Reset`.
- Public keys: 65-byte SEC 1 uncompressed P-256 points (`04 || X || Y`).
- Binding tokens: 32 bytes, distinct for each caller AID and current Identity secret.
- Bundle keys and asymmetric item communication keys: 32 bytes, kept inside Identity.
- Metadata: ten-byte index, optional byte-string key and optional UTF-8 alias.
  Null and empty fields remain distinct.
- Byte-array arguments and direct results: global arrays for card-local calls.
  Data sources use repeatable range reads through a bounded global buffer.
- Completed data results are readable only by their original calling applet.
- Admission: any registered applet can acquire the interface, read public information
  and get its own token. Encryption/decryption requires Secret PIN verification by
  Identity for that caller. Creating/joining a Bundle and changing Secret PIN also
  require the exact Monoid instance AID. Preparing/publishing a reset requires that
  AID but deliberately does not require PIN authentication.
- Direct APDUs: SELECT only. Monoid owns [item transfer](item-transfer.md) and
  [Bundle management](bundle.md) commands; Hello exposes `id`, `publicKey` and
  `bundle` directly.

Identity derives authenticated contexts internally from the operation, full runtime
caller AID and metadata. Callers cannot choose another AID, supply arbitrary HPKE contexts or retrieve decrypted
communication or Bundle keys. Enrollment and ordinary item transfer use separate
cryptographic domains. With a Bundle installed, item encryption always uses it;
`recipientPublicKey` is ignored. Decryption dispatches by envelope version. With a
Bundle present, it rejects artifacts sent by the local Identity in either format,
including self-addressed asymmetric items created before enrollment.

Matching applet AIDs on different cards can exchange data; different AIDs cannot
decrypt each other's envelopes, even within the same Bundle. Bundle item transfers
derive a key for the runtime caller and actual sending Identity from the shared
root before deriving each payload key. The sender must be another fixed member
when decrypting.
The root key and its public hash remain common to all members. See
[item transfer](item-transfer.md) for the exact derivation.

## Secret PIN

Identity owns the persistent Secret PIN, five-attempt counter and validation state.
A successful verification authorizes the actual runtime caller AID; a caller cannot
supply a success flag or borrow another caller's authorization. Access PIN does
not authorize Identity cryptography. Registered callers may verify Secret PIN for
their own communication domain; only Monoid may initialize or change it.
Identity authorization is reset-scoped and bound to that caller, so it survives
ordinary SELECT switches without authorizing other callers. A new Secret PIN
check, PIN update, explicit authorization clearing or card power reset invalidates
the previous validation. Monoid APDU authorization has its separate deselect scope.

Encryption, decryption, Create Bundle and Join Bundle require current Secret
authorization inside Identity. Changing an existing PIN requires the same
validation and clears authorization. Monoid reinstallation preserves Secret PIN
and retries. Unauthenticated `0xFF Reset` may clear it only while replacing the
Identity keys and binding secret and deleting local protected data and Bundle.

## Identity binding

Identity generates an independent random 32-byte secret at installation or `0xFF Reset`:

```text
token = HMAC-SHA256(identitySecret,
  "Monoid Identity Token" || callerAID || callerAID || callerAID)
```

`callerAID` is the complete AID supplied by the Java Card runtime at the SIO call,
not an argument. Each of the three occurrences is read afresh from the runtime
and immediately added to HMAC. The secret is never returned; tokens are not available through
APDUs. Bundle changes do not affect them. Repeated calls return independent copies
of the same token for that caller and Identity.

Identity keeps up to 32 tokens in a persistent FIFO cache keyed by complete AID.
Hits verify the runtime caller and return a copy without recomputing HMAC or
writing the cache. A card power reset preserves entries; `0xFF Reset` replaces the
secret and cache. Eviction only causes the same token to be computed again while
the secret is unchanged. Entries retain private bytes, not references to callers.
Requests inside an existing transaction can use cached tokens but do not publish
new entries.

Before its first command, Monoid stores a private persistent copy of its token.
This happens before any PIN or item can be created. Later Identity operations
retrieve a fresh global token and compare it directly, without creating another
persistent copy or sending the saved token back to Identity. A mismatch is
rejected and never causes automatic rebinding. The authorized lifecycle operation
`0xFF Reset` explicitly replaces Monoid's binding in the same transaction as its
data/PIN removal and Identity replacement. Other applets' old binding tokens
become invalid; they are not automatically rebound. Monoid retains no Identity object reference.

Deleting Monoid deletes its data, Access PIN and binding; Identity retains its
Secret PIN and retries. A new instance can bind to the retained Identity, but must
authenticate that Secret PIN to recover permitted previously exported items. This assumes trusted
initial applets and the Java Card firewall; it does not authenticate installed code
or prevent the [same-AID recovery workflow](bundle.md#recovery-and-data-migration).

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
operation's context before using the key inside Identity. Without a Bundle,
self-encryption uses the local public key for both roles. With a Bundle, exports
use the Bundle format and imports reject the local Identity as sender. The domains
and complete envelopes are specified
in [item transfer](item-transfer.md) and [Bundle](bundle.md).

`createBundle` receives concatenated 65-byte public keys. Its result contains
equal-length enrollment packets in input order with self omitted. Identity
encrypts all packets before atomically publishing the new key and membership.
Monoid reads the result by range and associates each packet with its recipient
in the Create Bundle response.

The caller must obtain the expected peer public key through its trust mechanism;
the envelope does not establish that trust. Caller AIDs isolate transfer domains but
does not authenticate installed code. Item transfer has no single-use restriction;
Joining a Bundle is idempotent only for an identical key and membership. Bundle
creation requires no existing Bundle. Neither method replaces an installed Bundle.
`prepareReset` requires no active transaction and no communication operation in
progress. It generates a candidate key pair, random ID, binding secret, unset
Secret PIN and empty token cache without changing the current identity, and returns the candidate
Monoid token in a global array. `reset` requires an active Monoid transaction and
publishes that candidate while clearing the Bundle and references to the old
communication key state. In the same transaction, Monoid replaces its binding,
clears items/derivation cache and replaces Access PIN with unset state; Identity
publishes the new unset Secret PIN in that transaction.
A failed transaction retains the previous published identity and Monoid state;
the candidate is discarded after the publication attempt or a card power reset.
Successful Reset clears Monoid authorization. These methods implement `0xFF Reset`;
they are not separate host commands.
See [reinitialization](bundle.md#reinitialization) for Reset and the GP lifecycle.

## Safe ID

Hello returns the ID stored in Identity. A card power reset, Bundle creation/joining,
Monoid replacement and PIN changes preserve it. `0xFF Reset` or reinstalling Identity
generates a new ID, key pair and binding secret.
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

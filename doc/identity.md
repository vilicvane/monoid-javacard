# Monoid Identity

Monoid Identity retains a P-256 key pair generated on installation or `0xFF Reset`
and a four-byte Card ID preserved by Reset. Its private key has no export interface. Identity
also owns Secret PIN, its retry and caller authorization state, the optional Bundle
key, extension policy and enrollment snapshot. It performs complete item encryption and decryption
for applets in separate caller domains. Monoid owns Access PIN, Safe item storage
and command authorization.

Install Identity before Monoid. Monoid updates preserve its matching Identity.
Deleting Identity removes its private key, binding secret, Secret PIN and local
Bundle state.

## Installation parameters

Identity accepts the following application data in the GP installation parameters:

```text
flags:              1 byte
id:                 4 bytes, present when flags & 0x01
authorityPublicKey: 65 bytes, present when flags & 0x02
authorityUrl:       remaining bytes, nonempty UTF-8, present when flags & 0x02
```

Fields appear in that order. Empty application data or `flags = 0` generates a random
Card ID and leaves Authority unset. Other flag bits are invalid. The Authority key
is an uncompressed P-256 public key (`04 || X || Y`), independent of the card's key pair.
The service URL and public key must be supplied together. The URL occupies the rest
of the application data, without another length prefix; a key-only configuration is invalid.
Card ID, Authority URL and Authority key are stored persistently and preserved by
`0xFF Reset` and Monoid replacement.
Identity reinstallation can restore a supplied Card ID, but generates a fresh card key pair
and binding secret. No runtime setter is exposed.

The user selects the Authority service URL, and the installer obtains its public
key before installing both. This initial choice establishes trust. The APP uses
the URL returned by Monoid Hello to reach the service; Identity does not access the
network and verifies [Authority-issued Bundle enrollment and signed time](authority.md)
with the installed key. A different key returned by the service cannot replace it
at runtime. Authority cannot replace an existing Bundle or change its policy.

`scripts/build-install.ps1 -Mode Install` accepts optional `-CardId` (8 hex digits)
and the paired `-AuthorityPublicKey` (130 hex digits beginning with `04`) and
`-AuthorityUrl` arguments. These apply only to Identity installation;
`ReinstallMonoid` preserves the existing Identity configuration. The script receives
the public key explicitly; fetching it from the chosen service belongs to the APP.
With the standard nine-byte instance AID and empty control information, application
data is limited to 243 bytes: up to 177 UTF-8 bytes for the URL, or 173 when supplying
a Card ID. The limit counts bytes, not characters.

```powershell
.\scripts\build-install.ps1 -AuthorityUrl 'https://authority.example' -AuthorityPublicKey $authorityPublicKey
```

## Interface

```java
public interface IdentityShareable extends Shareable {
  /** Stable private binding token for the runtime caller's complete AID. */
  byte[] getToken();

  byte[] getId();

  byte[] getPublicKey();

  /** Authority service URL as global UTF-8 bytes, or null when not configured. */
  byte[] getAuthority();

  /** SHA-256 of the Bundle key, or null when not enrolled. */
  byte[] getBundle();

  /** Verifies signed time using the installed key and the caller's one-use challenge. */
  void verifyAuthorityTime(byte[] data, byte[] signature, byte[] challenge);

  boolean isSecretPINSet();

  short getSecretPINTriesRemaining();

  /** Verifies a global PIN buffer and authorizes only the runtime caller. */
  boolean checkSecretPIN(byte[] pin);

  /** Monoid only: initializes Secret PIN, or changes it after Secret authentication. */
  void updateSecretPIN(byte[] pin);

  /** Returns the encoded authorization result for the runtime caller. */
  short getSecretPINValidationResult();

  void clearSecretAuth();

  /** Requires Secret authentication and no Bundle; recipients exclude self, without duplicates. */
  CommunicationDataShareable createBundle(byte[] publicKeys);

  /** Requires Secret authentication; the same Bundle key and policy are idempotent. */
  byte[] joinBundle(byte[] senderPublicKey, byte[] data);

  /** Monoid only, with Secret authentication and allowPeerExtension: initiates extension. */
  CommunicationDataShareable extendBundle(byte[] publicKey);

  /** Monoid only, with Secret authentication and allowPeerExtension: approves another member's request. */
  CommunicationDataShareable approveBundleExtension(byte[] request);

  /** Monoid only: prepares a new identity outside a transaction and returns its caller token. */
  byte[] prepareReset();

  /** Monoid only: publishes the prepared identity within Monoid's reset transaction. */
  void reset();

  CommunicationDataShareable encryptData(
    byte[] index,
    byte[] metadata,
    byte[] alias,
    short secret,
    byte[] recipientPublicKey,
    CommunicationDataShareable data
  );

  /** Returns secret (two bytes) || data after authenticating the complete envelope. */
  CommunicationDataShareable decryptData(
    byte[] index,
    byte[] metadata,
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

- ID: four bytes, supplied at Identity installation or randomly generated, and preserved by `0xFF Reset`.
- Public keys: 65-byte SEC 1 uncompressed P-256 points (`04 || X || Y`).
- Binding tokens: 32 bytes, distinct for each caller AID and current Identity secret.
- Bundle keys and asymmetric item communication keys: 32 bytes, kept inside Identity.
- Item fields: ten-byte index, optional byte-string metadata and optional UTF-8 alias.
  Null and empty fields remain distinct.
- Byte-array arguments and direct results: global arrays for card-local calls.
  Data sources use repeatable range reads through a bounded global buffer.
- Completed data results are readable only by their original calling applet.
- Admission: any registered applet can acquire the interface, read public information
  and get its own token. Encryption/decryption requires Secret PIN verification by
  Identity for that caller. Creating, joining or extending a Bundle and changing Secret PIN also
  require the exact Monoid instance AID. Preparing/publishing a reset requires that
  AID but deliberately does not require PIN authentication.
- Direct APDUs: SELECT only. Monoid owns [item transfer](item-transfer.md) and
  [Bundle management](bundle.md) commands; Hello exposes `id`, `publicKey`,
  `authority` (URL or false) and `bundle` directly.

Identity derives authenticated contexts internally from the operation, full runtime
caller AID and metadata. Callers cannot choose another AID, supply arbitrary HPKE contexts or retrieve decrypted
communication or Bundle keys. Enrollment, extension requests and ordinary item transfer use separate
cryptographic domains. With a Bundle installed, item encryption always uses it;
`recipientPublicKey` is ignored. Decryption dispatches by envelope version. With a
Bundle present, it rejects artifacts sent by the local Identity in either format,
including self-addressed asymmetric items created before enrollment.

Matching applet AIDs on different cards can exchange data; different AIDs cannot
decrypt each other's envelopes, even within the same Bundle. Bundle item transfers
derive a key for the runtime caller and actual sending Identity from the shared
root before deriving each payload key. Decryption requires a valid tag under the
same Bundle root and a sender other than the local Identity. It does not consult
the stored enrollment snapshot.
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

Encryption, decryption, Create Bundle, Join Bundle, Extend Bundle and Approve Bundle
Extension require current Secret
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

`createBundle` receives concatenated 65-byte public keys for at least one other
recipient, without duplicates or the local Identity. Identity adds itself to the
enrollment snapshot. The result contains equal-length encrypted packets in input
order. Identity encrypts all packets before atomically publishing the new key and
snapshot. Monoid reads the result by range and returns one `data[]` packet per
recipient, without repeating the public keys.

`extendBundle` returns a dedicated request binding the local Identity's
public key, Bundle hash and target public key with both a Bundle-root HMAC and an
Identity signature. `approveBundleExtension` checks both proofs, requires an initiator other
than the local Identity and encrypts an enrollment packet only for that target.
Both methods leave the existing Bundle configuration unchanged. The target joins
with `joinBundle`; it can then exchange records and, when its policy permits,
approve future extensions
without synchronizing member lists. The snapshot records enrollment rather than
serving as an authorization list. See [Bundle extension](bundle.md#extension).

The host commands expose these results as `data`. Approve Bundle Extension also
returns the approving Identity's `publicKey`; the complete response is the Join
Bundle request. Join's `publicKey` denotes the enrollment sender: an Identity for
peer packets, or the installed Authority for issued packets. Item Import's
separate `senderPublicKey` field is unchanged.

Authority enrollment uses the same `joinBundle` entry point and HPKE engine.
Identity verifies the supplied sender against its installed Authority and uses
that installed key to authenticate the packet. The authenticated policy is stored
with the root; both extension entry points reject `allowPeerExtension: false`.
Create enables this policy, and peer enrollment preserves it. Packet kind is not
stored as root provenance. See [Authority issuance](authority.md).

The caller must obtain the expected peer public key through its trust mechanism;
the envelope does not establish that trust. Caller AIDs isolate transfer domains but
do not authenticate installed code. Item transfer has no single-use restriction;
joining the same Bundle key and policy is idempotent and retains the local enrollment snapshot. Bundle
creation requires no existing Bundle. Neither method replaces an installed Bundle.
`prepareReset` requires no active transaction and no communication operation in
progress. It generates a candidate key pair, binding secret, unset
Secret PIN and empty token cache without changing the current identity, and returns the candidate
Monoid token in a global array. `reset` requires an active Monoid transaction and
publishes that candidate while clearing the Bundle and references to the old
communication key state. In the same transaction, Monoid replaces its binding,
clears items/derivation cache and replaces Access PIN with unset state; Identity
publishes the new unset Secret PIN in that transaction. The Card ID and installed
Authority public key are preserved.
A failed transaction retains the previous published identity and Monoid state;
the candidate is discarded after the publication attempt or a card power reset.
Successful Reset clears Monoid authorization. These methods implement `0xFF Reset`;
they are not separate host commands.
See [reinitialization](bundle.md#reinitialization) for Reset and the GP lifecycle.

## Card ID

Hello returns the ID stored in Identity. A card power reset, Bundle creation/joining/extension,
Monoid replacement, PIN changes and `0xFF Reset` preserve it. Reset generates a new
key pair and binding secret. Reinstalling Identity restores a supplied ID or generates a new one.
The four-byte value
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

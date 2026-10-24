# Security boundaries

This is the audit baseline for the current Monoid/Identity architecture. It states
the intended protection, required assumptions and deliberately supported recovery
paths. It is not an audit report or a claim of hardware certification. An audit
must identify the source revision, built CAPs and card configuration it covers;
historical tests do not establish the behavior of every later build.

The [command definitions](../README.md#iso-7816-commands),
[architecture](architecture.md), [Identity](identity.md), [item transfer](item-transfer.md)
and [Bundle](bundle.md), including [Authority enrollment](authority.md), specify
the corresponding interfaces and formats. If an
implementation violates the boundaries below, report the discrepancy rather than
reclassifying it as a trusted input or an accepted exception.

## Trust model

- The Java Card runtime, firewall, object ownership, cryptographic primitives and
  random generator are trusted. Private persistent storage is protected by that
  platform; persistence alone does not make an object accessible to other applets.
- The initially installed Monoid and Identity code is trusted. Additional applets
  may be installed and need not be trusted. An AID identifies a runtime caller,
  not the author, binary, firmware version or trustworthiness of its code.
- The host is trusted when collecting PINs, choosing keys and signing inputs, and
  deciding which peer public keys to accept. Once recipients are correctly
  selected, encrypted transfer artifacts can pass through untrusted storage or a
  relay without disclosing their protected contents. That does not authenticate
  peer selection or guarantee delivery.
- Ordinary Monoid APDUs do not provide an encrypted or authenticated host channel.
  PINs and plaintext Create/Set/Get data are not protected by the item-transfer
  envelope. APDU fragmentation is a transport convention, not secure messaging.
- GlobalPlatform management authority is separate from Access PIN and Secret PIN. An
  administrator may delete/reinstall applets, cause data loss or install code
  that captures future user input. Changing a PIN does not change GP keys. The
  applets do not enforce a card-wide signed-code or approved-installer policy.
  Actual GP authorization is a property of the target card's configuration.

The card has no trusted display or per-signature physical confirmation in this
implementation. Sign authenticates access to a key and signs the supplied input;
it does not verify the user's intended recipient, amount or transaction semantics.
Possession of an authorized session is sufficient to request supported signatures.

## Ownership and authorization

Monoid owns Safe items, Access PIN, derivation and signing. Safe is an internal
class in the same applet, not a separately replaceable security authority.
Identity owns Secret PIN and its retry/authorization state, the long-term P-256
private key, binding secret, Bundle key, extension policy and enrollment snapshot. None of those Identity
secrets has a raw export interface.

| Operation                                                                           | Required authorization and scope                                                                                                                         |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hello, System information                                                           | No PIN. Identity ID/public key, Bundle hash, versions, capabilities, memory and PIN status are not confidential.                                         |
| First Secret PIN setup                                                              | No prior PIN when Secret PIN is unset; initializes Access PIN if it is unset. Initial provisioning must be trusted.                                      |
| Change either PIN                                                                   | Secret authorization once Secret PIN is configured. Access authorization is insufficient.                                                                |
| List, View, Get, Set, Create, Remove, Create random key, View Key, Sign             | Access or Secret authorization. Safe storage also requires Secret PIN to be set and unblocked. Get additionally checks `secret`.                         |
| List, Set, Remove applet grants                                                     | Access or Secret authorization. Secret PIN must be set and unblocked; its verification is not required.                                                  |
| Export, Import, Create Bundle, Join Bundle, Extend Bundle, Approve Bundle Extension | Secret authorization, independently checked inside Identity. Bundle management also requires the fixed Monoid caller AID.                                |
| Reset                                                                               | No PIN. Verifies Identity binding and the fixed Monoid caller AID; clears items/cache/Bundle, both PINs and authorization, and generates a new Identity. |
| GP deletion/recreation                                                              | Card-management authorization; not authorized or prevented by either PIN.                                                                                |

Access PIN is not a read-only permission: it permits signing and item mutations,
including replacement and deletion, and delegation through applet grants. Secret PIN includes ordinary access and adds
PIN management, encrypted export/import and Bundle management. See the commands for exact
inputs and error behavior.

APDU authorization is scoped to Monoid selection and is cleared by deselection,
card reset or successful `0xFF Reset`. It can cover multiple commands; it is not
automatically revoked after each response. Identity binds its Secret authorization
to the verified runtime caller. Each Secret PIN check clears the previous Secret
authorization before verification; changing Secret PIN also clears it. Identity
Secret authorization uses reset-scoped storage and survives ordinary SELECT
switches, while Monoid's APDU authorization uses deselect-scoped storage. A different
caller cannot use the retained Secret authorization. Secret PIN
blocking prevents subsequent protected storage operations, including when command
authorization was previously obtained.
Each PIN has a configured five-attempt budget. An Authenticate request checks the
PIN once; redundant checks inspect the result/state rather than consuming three
attempts.

The `0x50`–`0x52` commands manage applet grants under Access or Secret PIN authorization.
Grants belong to Monoid's private directory and cannot be addressed, exported or
imported as ordinary Safe items. Set validates the source descriptors, reads the
installed client's token hash through `MonoidClientShareable`, and rechecks
command authorization and Identity's initialized/unblocked state after each client callback.
It publishes the entire replacement atomically. Remove is idempotent; factory
Reset clears grants in the same transaction as the protected data.

The client privately generates a random 32-byte installation token. Its public
hash is an enrollment identifier, not code attestation or evidence of FIDO PIN
verification. Monoid stores owned bytes and descriptors, not persistent client
AID objects or Shareable references. Reinstalling a client does not update the
stored grant automatically; enrolling its new token requires Access or Secret PIN again.

The public `Monoid` Shareable interface authenticates the private token, binds
the session to the runtime caller and rechecks the current immutable grant on
every operation. Power reset, grant replacement/revocation and Monoid Reset
invalidate existing sessions and item/data/iterator handles. Type grants cannot
read secret data. Writable grants permit replacement and deletion, not revealing
the previous secret bytes. `removeAll(type)` requires an exact writable Type,
even for an empty result, and atomically publishes the filtered directory.
Opt-in session reuse matches the exact caller and current grant, clears authentication
on acquisition and never revives an expired session. Range and direct-data methods
retain the same live authorization, Type and secret checks before copying output.
Index enumeration exposes metadata only; it does not authorize reading secret data.
Direct reads filter exact metadata, including null, before returning data; a metadata mismatch
is not evidence that the caller may read a different item. Direct creation owns
the supplied bytes before normal storage publication and keeps the existing reserve
and transaction boundaries. No global/APDU array reference is retained by these calls.
Client data callbacks are checked before and after invocation; they do not inherit
APDU PIN authorization. Fixed asymmetric Key descriptors remain management data; the first
signing service exposes only the granted seed/domain's Monoid-001/P-256 path.

HMAC uses a built-in key explicitly selected by its full index in `grant.keys`.
It permits SHA-1/SHA-256/SHA-512 MACs without returning the key. Type read/write
access does not authorize HMAC, and a key grant does not permit plaintext secret
reads. OTP account records contain configuration and a readable key reference;
changing that reference cannot authorize another key. HMAC callers choose
arbitrary messages; only delegate this computation to code whose policy the user
trusts.

`Authenticate` may additionally name one granted client AID. This issues one
operation-start permission, held in CLEAR_ON_RESET state and shared by that
grant's SIO sessions. The client authenticates its installation token, then
consumes the permission before starting work. A new Authenticate clears the old
permission, including when it fails; PIN updates and replacement/revocation of
the matching grant also invalidate it. Consumption cannot be repeated. Ordinary
APDU authentication remains CLEAR_ON_DESELECT; no PIN is passed to the client.
This permission has no time-based expiry and does not authenticate host software.

[OTP](otp.md) requires that permission after fixing the time and selected account
indices. With Authority configured, it requires signed challenge-bound time;
without Authority, it accepts APP-provided time. The card's installed configuration
chooses this policy, and a configured Authority never falls back to unsigned time.
The unsigned mode permits the host to choose past or future windows. OTP consumes
the permission before producing three
windows per account and discards the batch even on failure. Its pending state
clears on card reset; a new preparation revokes its old permission. Configuration
and secret data are read at calculation, not frozen item revisions. The signed
time proves issuance, not prompt delivery; old prepared windows can remain
available while powered. No persistent time high-water mark or per-power quota
is claimed. The HMAC SIO itself does not enforce this OTP policy, just as Monoid
does not implement the client's FIDO PIN policy.

Security Key owns its FIDO PIN and protocol-1 PIN token. Its normal CTAP requests
need no Monoid APDU PIN login: Monoid trusts the installed authorized client's
FIDO checks, while enforcing its own token, caller and grant boundary. Private
derived keys remain in Monoid. Resident credential metadata is non-secret Type
`0xF101` data, with RP binding and complete random credential-ID checks.
Non-resident credential IDs carry a 128-bit HMAC tag over the RP under a key derived
from the seed/domain and are not stored; anyone with that seed/domain can mint them.
FIDO Reset does not revoke them. Generic Monoid
management and backup remain permitted; this is not FIDO certification isolation.
Software UP is enabled; UV is set only after valid FIDO PIN-token authentication.
The counter is zero, and self attestation does not establish manufacturer identity.
Access authorization can delegate the same seed/domain to another client. FIDO PIN
protects the Security Key entry point; it is not an additional card-wide factor
for equivalent signing through Monoid's other authorized interfaces.
Local FIDO Reset requires no FIDO PIN but does require writable Type authorization;
it commits removal of FIDO records before separately clearing the FIDO PIN, retaining
Monoid/Identity data, their PINs, the seed and the grant. Revoking the grant prevents
that Reset from removing records or clearing the FIDO PIN.
An interruption between commits can leave the old PIN with no records; retrying
Reset completes the remaining step. It does not clear the PIN before removing
the records.

Resident registration first reduces duplicate resident records for the same
RP/user to one retained old record, then commits a new record before removing
that old record. An interrupted replacement preserves an old or new credential; a successful
retry leaves only its new record and uses a new random credential ID. Duplicate
cleanup may commit without reclaiming enough space for creation in that command.
These workflows do not promise atomicity across their steps; individual storage
updates remain atomic.

## Meaning of `secret`

`secret: true` prohibits returning the stored item data through plaintext Get,
including after Secret PIN authentication. It does not prohibit use of the key for
signing/derivation, public-key queries, metadata enumeration, encrypted Export,
replacement or deletion. List/View expose public fields; index, metadata and alias
must not be used as confidential storage.

Changing `secret` from true to false without supplying replacement data is
rejected. Supplying new data and its flag together is permitted and commits that
pair atomically; it does not expose the previous bytes. Randomly generated items
are always secret. Create defaults to non-secret unless requested otherwise, and
Import preserves the authenticated flag rather than accepting a host override.

Trusted Monoid code can read item bytes internally to sign or export them.
There is no separate Safe firewall protecting data from Monoid itself. The future
export/backup lock is not implemented: neither `secret` nor Bundle means permanent
non-exportability.

## Identity and caller isolation

Identity obtains the complete caller AID from the runtime on each service call.
It does not accept a caller-selected AID for token derivation or cryptographic
contexts. Registered applets may obtain their own binding token and verify
Secret PIN to use encryption/decryption in their own AID domain. Different AIDs cannot decrypt one
another's artifacts; matching AIDs on different cards intentionally interoperate.
Forwarding a Shareable reference must not impersonate the original caller.
Completed communication results are readable only by their original caller.
Identity stores and verifies Secret PIN itself and checks that its current
authorization belongs to the actual caller before encryption/decryption or Bundle
management. A caller-supplied success flag, Access authorization or Monoid
replacement cannot establish that validation. Only the fixed Monoid AID may
initialize/change Secret PIN; an existing PIN must be authenticated to change it.

Monoid binds privately to Identity before creating PINs/items. Later checks reject
a different token and do not automatically rebind retained data. Public-key/ID
spoofing alone is not sufficient to reproduce that private binding token.
These checks guard Identity operations such as identity discovery, Bundle
management and item transfer. Ordinary storage access also reads Identity's
Secret PIN state through this binding check; replacing Identity underneath
retained Monoid data does not preserve that access.
The token is stable for an Identity and caller AID, including after same-AID caller
reinstallation; it is not a per-installation client credential or code attestation.
Its cache changes performance, not these semantics. `0xFF Reset` replaces the
Identity secret and explicitly updates Monoid's binding with removal of its
protected data. Other applets' old tokens become invalid without automatic rebinding.

Caller isolation does not provide resource quotas for other installed applets
or protect availability against card-management operations.

The four-byte Identity ID is a display/lookup label. Hello, an AID, a Bundle hash,
GP capability declarations or a successful signature do not prove genuine card
hardware or approved installed code. Public keys must be bound to the intended
peer through the host's trust decision; the protocol does not supply a manufacturer
certificate chain or prove that a peer keeps its private key inside a card.

## Encrypted transfer and Bundle

The [item envelope](item-transfer.md) protects data and the secret flag, and binds
the complete index, metadata, alias, protocol version and runtime caller AID. Public fields
and length remain visible. Identity verifies the complete authentication tag
before returning plaintext to Monoid; a failed or mismatched artifact must not
publish a result or overwrite an existing item.

Without a Bundle, Secret-authorized Export accepts a recipient P-256 public key.
That key may belong to software, not a card. This is an authorized migration path,
not a guarantee that all exported private material remains in secure hardware.
The asymmetric profile authenticates the sender key selected for Import, not the
human owner's approval or the sender's installed code.

With a Bundle, Identity derives a sending key from the shared root, complete
runtime caller AID and its own public key. The full sender key in the envelope
is bound to payload-key derivation and the GCM tag. Identity chooses the local
sending identity internally; it rejects decryption of its own Bundle artifacts
and mismatched caller domains. Sender-key derivation and tag verification prove
access to the shared root; item transfer does not consult the enrollment snapshot.
A supplied recipient key cannot
switch Export to asymmetric mode. Incoming asymmetric artifacts from other
identities are accepted; old self-addressed artifacts are rejected while bundled.

The asymmetric primitives and shared root do not inherently enforce an
encryption-only key. Trusted Identity code enforces the sender restriction. A
software peer holding the root could derive all member keys; membership must
therefore be restricted to trusted identities. This is not a cryptographic proof
of the sender against a malicious holder of the Bundle root.

Create accepts only other recipients, rejects duplicate keys and the local key,
and rejects an existing Bundle even for the same recipients. It enables
`allowPeerExtension`. Join verifies the enrollment packet, accepts the same key
and policy idempotently while retaining the local snapshot, and rejects a different
key or policy. Extend and Approve both require `allowPeerExtension`, two distinct
existing Bundle identities and each executing card's Secret PIN. The initiating Identity produces
a dedicated Bundle-root HMAC and Identity signature, both binding its actual
public key, the Bundle hash and the target's complete public key. The second
Identity approves the request only after verifying both, then encrypts the root
for that target. Neither a
root MAC alone nor an Identity signature alone satisfies this authorization.
These operations expose neither generic signing nor a caller-selected MAC domain.

The new card uses Join, inherits the policy and may immediately exchange data and,
when permitted, approve further extensions; no member-list synchronization is
required. Enrollment snapshots do
not confer approval authority. Extend and Approve do not change the existing cards'
configuration. Saved requests can be replayed for the same target; this is not
a fresh-presence or revocation protocol. Extension retains the root and permits
historical data recovery, without revoking lost members.

An optional Authority URL and key are fixed together at Identity installation.
Hello exposes the URL for service discovery, while cryptographic verification
continues to use the installed key. Authority enrollment
authenticates that installed key through HPKE Auth and binds the recipient and
`allowPeerExtension` in the authenticated packet header. It requires Secret PIN
and the fixed Monoid caller, and cannot replace an existing root or change its
policy. The policy governs peer extension only; it does not prevent the Authority
from issuing the same root to another recipient without existing cards.

The Authority knows roots it issues and can decrypt captured artifacts in those
groups without either card or PIN. This is a different confidentiality boundary
from a root generated and retained only by trusted card identities. The installed
Authority does not learn or gain an override for card-created roots. Issuers must
keep one policy per root; a Bundle hash covers only the root and does not prove
policy agreement. Cards cannot detect conflicting policies distributed to other
members. Enrollment packets are replayable for the same Identity and have no
expiry or revocation check. See [Authority](authority.md) for issuance and lifecycle.

`0xFF Reset` clears local items,
derivation cache, both PINs, authorization and Bundle together, and generates a
new Identity; it cannot clear only the Bundle while retaining Monoid data. Bundle management is
restricted to the exact Monoid AID, although other applets may use their own
communication domains under the same shared root.

Import is not a freshness protocol: identical records succeed unchanged and
conflicting existing records are rejected, but an older artifact can be imported
after the corresponding item is removed. Each item commits independently.
Encryption does not detect omitted records, prove a complete backup, prevent
replay/rollback or provide an atomic multi-card operation. PINs, sessions and
Identity private state are not part of an item export. A host needing a complete
restore must track and verify its selected item set separately.

## Recovery and reinitialization

For a card-created Bundle, the current interface permits the following, including
for secret records:

1. Obtain an encrypted export from a trusted source Bundle card using its Secret
   PIN, or possess an export obtained earlier.
2. Preserve another member's Identity, Secret PIN and Bundle, then use GP authority
   to replace its Monoid with a recovery implementation under the same fixed AID.
3. Authenticate that receiving Identity's Secret PIN and provide the artifact and
   metadata. The recovery implementation can ask Identity to decrypt and return
   plaintext because the sender is another member.

A fresh complete export/decryption chain requires both cards and their respective
Secret PIN authorizations; the PIN values may be different. Existing artifacts do
not require a new source PIN check, and already released plaintext does not remain
subject to either card's checks. An artifact produced through the second member
can subsequently be recovered on the first. This is not a requirement for both
cards to be physically present at the same time, nor proof of fresh source-card
participation each time an old artifact is decrypted.

Same-card Monoid replacement retains Secret PIN and cannot make Identity decrypt
its own Bundle artifacts. Without a Bundle, Secret-authorized asymmetric export
may target software or the local Identity, so recovery requires Secret PIN rather
than a second card. Self-addressed asymmetric artifacts are no longer accepted
once that Identity joins a Bundle.

Replacing Monoid removes live items, Access PIN and caches; Identity retains
Secret PIN, its retries, the keys and Bundle, but not an item database. Replacement
Monoid code must authenticate the retained Secret PIN before using Identity
cryptography. Replacing Identity too removes that PIN and Bundle and generates a
new identity key and binding secret, even if the Card ID is supplied again. Retained Monoid data never silently binds
to this new Identity. Old asymmetric artifacts and enrollment packets do not
become decryptable merely by using the same AID.

`0xFF Reset` requires no PIN and returns Monoid to its uninitialized state: it clears
all local items, the derivation cache, both PINs and their failed-attempt/blocked
state, current authorization and the Bundle. It preserves the Card ID and installed
Authority key, generates a new Identity key pair and binding secret, clears its
token cache and updates Monoid's binding.
Hello returns the same ID, the new public key and both PINs and Bundle as `false`; ordinary
protected operations require new PIN initialization.
Anyone able to send Monoid APDUs can cause this data loss; availability against
that caller is deliberately not protected by PIN authentication. Reset gives no
permission to read or export the removed data. Identity binding and the fixed
Monoid caller check remain enforced. A blocked card can be initialized again only
after Reset has removed its old protected records. Reset does not replace installed
code or the applet instance, unlike GP reinstallation.
Old asymmetric artifacts and enrollment packets no longer decrypt on this reset
Identity, and its previous Bundle key is gone. Other applets' old binding tokens
are invalid, with no automatic rebinding. Reset does not remove other members'
copies, revoke delivered plaintext or guarantee physical erasure. Ordinary card
power resets and Monoid upgrades preserve Identity, Secret PIN and permitted recovery;
they do not perform `0xFF Reset`.

General GP reinitialization removes dependents before providers and recreates
providers before dependents. Persistent Shareable references may require clients
to release them or be deleted first. CAP import dependencies separately constrain
package deletion. See [Bundle reinitialization](bundle.md#reinitialization).
Deletion/recreation is not a promise of physical storage zeroization or revocation
of ciphertext already held elsewhere.

## Memory, faults and transaction limits

Private persistent arrays and derivation/token caches are intentional. Sensitive
working copies are not comprehensively overwritten after every operation.
Transient arrays clear according to their reset/deselect lifetime, not at every
APDU response. Releasing references or requesting garbage collection is not proof
of immediate erasure. Audits should identify an unauthorized access path rather
than treating private persistence alone as disclosure under the trusted-platform
assumption.

Authorization uses encoded short states, complementary state checks and selected
three-round conservative checks. Bundle creation, first-time joining and asymmetric
export require three checks confirming no Bundle exists. Export accepts only the
defined encoded states when selecting its mode. Public Bundle-status reporting and
the missing-key check during decryption retain ordinary comparisons. These are
selected policy checks, not blanket repetition of every null comparison.
The design targets hardening against a single
fault; it does not claim that every branch or operation resists every single fault,
multiple faults, laser injection, power/EM analysis or invasive extraction.
Functional tests and simulator fault substitutions are not physical fault-injection
or side-channel validation. Correct and suitably isolated native primitives remain
part of the platform assumption.

Do not assume an entire command is one transaction. For example, Set publishes
data/secret together but updates alias separately; a later failure can leave the
earlier update committed. Initial Secret and Access PIN setup also uses separate
updates in their respective applet contexts. These scopes differ from publishing a fully authenticated imported item
or a completed Bundle. Reset prepares a new identity outside the transaction,
then publishes item removal, derivation-cache clearing, both unset PINs, the new
Identity key pair/token secret/cache, Bundle removal and Monoid's new binding
in one transaction across both applet contexts. An aborted transaction preserves
the previous published persistent state. Card ID and Authority configuration remain
unchanged. Successful Reset clears current authorization and requests garbage
collection without promising physical erasure. Multi-command backup, GP deletion/installation and
cross-card enrollment have no shared transaction.

## Audit entry points and open checks

| Boundary                                 | Implementation                                                                                                                                                                                                                                                 | Existing regression coverage                                                                                                                                                        |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PIN/session authorization                | [Command](../src/main/java/monoid/Command.java), [MonoidApplet](../src/main/java/monoid/MonoidApplet.java), [Safe](../src/main/java/monoid/Safe.java), [SecretPIN](../src/main/java/monoididentity/SecretPIN.java)                                             | [CommandAuthenticationTest](../src/test/java/monoid/CommandAuthenticationTest.java), [SafeAuthenticationTest](../src/test/java/monoid/SafeAuthenticationTest.java)                  |
| Secret reads and updates                 | [CommandGet](../src/main/java/monoid/CommandGet.java), [CommandSet](../src/main/java/monoid/CommandSet.java), [SafeItem](../src/main/java/monoid/SafeItem.java)                                                                                                | [MonoidItemTransferTest](../src/test/java/tests/MonoidItemTransferTest.java)                                                                                                        |
| Identity binding and caller domains      | [MonoidIdentityApplet](../src/main/java/monoididentity/MonoidIdentityApplet.java), [CommunicationData](../src/main/java/monoididentity/CommunicationData.java), [ItemCipher](../src/main/java/monoididentity/ItemCipher.java)                                  | [MonoidIdentityAppletTest](../src/test/java/monoididentity/MonoidIdentityAppletTest.java), [IdentityTransferBoundaryTest](../src/test/java/tests/IdentityTransferBoundaryTest.java) |
| Bundle membership and removal boundaries | [Bundle](../src/main/java/monoididentity/Bundle.java), [CommandCreateBundle](../src/main/java/monoid/CommandCreateBundle.java), [CommandJoinBundle](../src/main/java/monoid/CommandJoinBundle.java), [CommandReset](../src/main/java/monoid/CommandReset.java) | [MonoidBundleTest](../src/test/java/tests/MonoidBundleTest.java), [BundleTest](../src/test/java/monoididentity/BundleTest.java)                                                     |
| Redundant checks                         | [LibSecurity](../src/main/java/monoidlib/LibSecurity.java) and its generated Identity counterpart                                                                                                                                                              | [LibSecurityTest](../src/test/java/monoidlib/LibSecurityTest.java)                                                                                                                  |

These tests are evidence for specific software paths, not a complete audit. Physical
firewall, deletion, native-crypto and fault behavior need evidence from the actual
target card/build; jCardSim does not reproduce all runtime restrictions.

PIN input validation remains an audit item, not an accepted security exception:
the current command paths pass decoded lengths through a `byte` cast before
OwnerPIN calls and do not enforce a nonempty PIN at the request boundary.
The configured OwnerPIN capacity must not be mistaken for complete validation of
the original CBOR input. Review empty and oversized inputs in
[CommandSetPIN](../src/main/java/monoid/CommandSetPIN.java), Command authentication,
MonoidApplet and Identity SecretPIN. This document does not claim that those paths
have been fixed.

Record audit findings and their evidence separately from these intended boundaries.
An accepted recovery path does not exempt caller isolation, authentication,
input handling or implementation correctness from review.

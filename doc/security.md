# Security boundaries

This is the audit baseline for the current Monoid/Identity architecture. It states
the intended protection, required assumptions and deliberately supported recovery
paths. It is not an audit report or a claim of hardware certification. An audit
must identify the source revision, built CAPs and card configuration it covers;
historical tests do not establish the behavior of every later build.

The [command definitions](../README.md#iso-7816-commands),
[architecture](architecture.md), [Identity](identity.md), [item transfer](item-transfer.md)
and [Bundle](bundle.md) specify the corresponding interfaces and formats. If an
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
- GlobalPlatform management authority is separate from both Monoid PINs. An
  administrator may delete/reinstall applets, cause data loss or install code
  that captures future user input. Changing a PIN does not change GP keys. The
  applets do not enforce a card-wide signed-code or approved-installer policy.
  Actual GP authorization is a property of the target card's configuration.

The card has no trusted display or per-signature physical confirmation in this
implementation. Sign authenticates access to a key and signs the supplied input;
it does not verify the user's intended recipient, amount or transaction semantics.
Possession of an authorized session is sufficient to request supported signatures.

## Ownership and authorization

Monoid owns Safe items, both PINs, derivation and signing. Safe is an internal
class in the same applet, not a separately replaceable security authority.
Identity owns its long-term P-256 private key, binding secret, Bundle key and
membership. None of those Identity secrets has a raw export interface.

| Operation                                                                       | Required authorization and scope                                                                                            |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Hello, System information                                                       | No PIN. Identity ID/public key, Bundle hash, versions, capabilities, memory and PIN status are not confidential.            |
| First Safe PIN setup                                                            | No prior PIN when neither PIN is configured; initializes Access PIN if it is unset. Initial provisioning must be trusted.   |
| Change either PIN                                                               | Safe authorization once a PIN is configured. Access authorization is insufficient.                                          |
| List, View, Get, Set, Create, Remove, Create random key, Import, View Key, Sign | Access or Safe authorization. Safe storage additionally requires its PIN to be set and unblocked. Get also checks `secret`. |
| Export, Create Bundle, Join Bundle                                              | Safe authorization. Bundle creation/joining also requires the fixed Monoid caller AID inside Identity.                      |
| Reset                                                                           | No PIN. Verifies the Identity binding and fixed Monoid caller AID before atomically clearing local items/cache/Bundle.      |
| GP deletion/recreation                                                          | Card-management authorization; not authorized or prevented by Monoid PINs.                                                  |

Access PIN is not a read-only permission: it permits signing and item mutations,
including replacement and deletion. Safe PIN includes ordinary access and adds
PIN management and encrypted export/Bundle management. See the commands for exact
inputs and error behavior.

APDU authorization is scoped to Monoid selection and is cleared by deselection
or card reset. It can cover multiple commands; it is not automatically revoked
after each response. A failed authentication attempt is not a universal logout
of an already authorized session. Safe PIN blocking prevents subsequent protected
storage operations, including when command authorization was previously obtained.
Each PIN has a configured five-attempt budget. An Authenticate request checks the
PIN once; redundant checks inspect the result/state rather than consuming three
attempts.

The public `Monoid` Shareable interface currently has no service methods.
Third-party signing grants, Type permissions and a Security Key applet are not
implemented security controls in this baseline. Identity's communication
interface does not grant access to Monoid's current item storage.

## Meaning of `secret`

`secret: true` prohibits returning the stored item data through plaintext Get,
including after Safe PIN authentication. It does not prohibit use of the key for
signing/derivation, public-key queries, metadata enumeration, encrypted Export,
replacement or deletion. List/View expose metadata; index, lookup key and alias
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
contexts. Registered applets may obtain their own binding token and use
encryption/decryption in their own AID domain. Different AIDs cannot decrypt one
another's artifacts; matching AIDs on different cards intentionally interoperate.
Forwarding a Shareable reference must not impersonate the original caller.
Completed communication results are readable only by their original caller.
Identity itself stores and verifies no PIN: Safe PIN authorization for Bundle
management and Monoid item export is enforced by trusted Monoid code.

Monoid binds privately to Identity before creating PINs/items. Later checks reject
a different token and do not automatically rebind retained data. Public-key/ID
spoofing alone is not sufficient to reproduce that private binding token.
These checks guard Identity operations such as identity discovery, Bundle
management and item transfer; they are not a global disable switch for local
Get or Sign after Identity replacement.
The token is stable for an Identity and caller AID, including after same-AID caller
reinstallation; it is not a per-installation client credential or code attestation.
Its cache changes performance, not these semantics.

Caller isolation does not provide resource quotas for other installed applets
or protect availability against card-management operations.

The four-byte Identity ID is a display/lookup label. Hello, an AID, a Bundle hash,
GP capability declarations or a successful signature do not prove genuine card
hardware or approved installed code. Public keys must be bound to the intended
peer through the host's trust decision; the protocol does not supply a manufacturer
certificate chain or prove that a peer keeps its private key inside a card.

## Encrypted transfer and Bundle

The [item envelope](item-transfer.md) protects data and the secret flag, and binds
the complete index, key, alias, protocol version and runtime caller AID. Metadata
and length remain visible. Identity verifies the complete authentication tag
before returning plaintext to Monoid; a failed or mismatched artifact must not
publish a result or overwrite an existing item.

Without a Bundle, Safe-authorized Export accepts a recipient P-256 public key.
That key may belong to software, not a card. This is an authorized migration path,
not a guarantee that all exported private material remains in secure hardware.
The asymmetric profile authenticates the sender key selected for Import, not the
human owner's approval or the sender's installed code.

With a Bundle, Identity always encrypts exports under the group key through an
AID-specific derivation. A supplied recipient public key cannot switch an export
back to asymmetric mode. Incoming asymmetric artifacts addressed to the card are
still accepted. Bundle artifacts authenticate the group, not an individual member.

Membership is fixed at creation. Create rejects an existing Bundle even for the
same roster. Join verifies the enrollment packet, accepts an identical key/roster
idempotently and rejects a conflicting one. `0xFF Reset` clears local items,
derivation cache and Bundle together; it cannot clear only the Bundle while
retaining Monoid data. Bundle management is
restricted to the exact Monoid AID, although other applets may use their own
communication domains under the same shared root.

Import is not a freshness protocol: identical records succeed unchanged and
conflicting existing records are rejected, but an older artifact can be imported
after the corresponding item is removed. Each item commits independently.
Encryption does not detect omitted records, prove a complete backup, prevent
replay/rollback or provide an atomic multi-card operation. PINs, sessions and
Identity private state are not part of an item export. A host needing a complete
restore must track and verify its selected item set separately.

## Accepted recovery and reinitialization

The following is intentionally supported, including for secret records:

1. Obtain a fresh encrypted export from a trusted source Bundle card using its
   Safe PIN, or possess an export obtained earlier.
2. Preserve another member's Identity/Bundle and use GP authority to replace its
   Monoid with a recovery implementation under the same fixed Monoid AID.
3. Deliver the artifact and authenticated metadata to that implementation. It
   can ask Identity to decrypt them and return the plaintext.

For a fresh export this requires the source Safe PIN; the receiving card's old
Safe PIN is not required after its Monoid is deleted. Existing artifacts do not
require another source authentication. This is the accepted two-card migration
boundary, not an authentication bypass to eliminate. More generally, any holder
of a matching retained Identity/Bundle, the relevant artifact and management
authority can use same-AID recovery; two physical cards are not a cryptographic
requirement once the ciphertext already exists. Self-addressed asymmetric exports
are similarly recoverable after Monoid replacement.

Replacing Monoid removes its live items, PINs and caches; Identity alone does not
retain an item database. Replacing Identity too removes its Bundle and creates a
new identity key, ID and binding secret. Retaining the old Monoid does not silently
bind it to the replacement. Old asymmetric artifacts and enrollment packets do not
become decryptable by a new Identity with the same AID.

`0xFF Reset` requires no PIN and clears all local items, the derivation cache and
the Bundle while preserving both PINs and Identity's keys, ID and binding token.
Anyone able to send Monoid APDUs can cause this data loss; availability against
that caller is deliberately not protected by PIN authentication. Reset gives no
permission to read or export the removed data. Identity binding and the fixed
Monoid caller check remain enforced. PIN attempts and blocked states are preserved,
so Reset cannot recover a blocked PIN and is not equivalent to GP reinstallation.
It does not remove data from other members or revoke previously exported artifacts.
The retained Identity still accepts asymmetric artifacts addressed to it, and
saved enrollment packets can rejoin the original Bundle. Reset is not a permanent
revocation or secure-erasure operation.

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
earlier update committed. Initial Safe and Access PIN setup also uses separate
updates. These scopes differ from publishing a fully authenticated imported item
or a completed Bundle. Reset publishes item removal, derivation-cache clearing
and Identity's Bundle removal in one transaction across both applet contexts;
an aborted transaction preserves all three. Successful Reset requests garbage
collection without promising physical erasure. Multi-command backup, GP deletion/installation and
cross-card enrollment have no shared transaction.

## Audit entry points and open checks

| Boundary                                 | Implementation                                                                                                                                                                                                                                                 | Existing regression coverage                                                                                                                                                        |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PIN/session authorization                | [Command](../src/main/java/monoid/Command.java), [MonoidApplet](../src/main/java/monoid/MonoidApplet.java), [Safe](../src/main/java/monoid/Safe.java)                                                                                                          | [CommandAuthenticationTest](../src/test/java/monoid/CommandAuthenticationTest.java), [SafeAuthenticationTest](../src/test/java/monoid/SafeAuthenticationTest.java)                  |
| Secret reads and updates                 | [CommandGet](../src/main/java/monoid/CommandGet.java), [CommandSet](../src/main/java/monoid/CommandSet.java), [SafeItem](../src/main/java/monoid/SafeItem.java)                                                                                                | [MonoidItemTransferTest](../src/test/java/tests/MonoidItemTransferTest.java)                                                                                                        |
| Identity binding and caller domains      | [MonoidIdentityApplet](../src/main/java/monoididentity/MonoidIdentityApplet.java), [CommunicationData](../src/main/java/monoididentity/CommunicationData.java), [ItemCipher](../src/main/java/monoididentity/ItemCipher.java)                                  | [MonoidIdentityAppletTest](../src/test/java/monoididentity/MonoidIdentityAppletTest.java), [IdentityTransferBoundaryTest](../src/test/java/tests/IdentityTransferBoundaryTest.java) |
| Bundle membership and removal boundaries | [Bundle](../src/main/java/monoididentity/Bundle.java), [CommandCreateBundle](../src/main/java/monoid/CommandCreateBundle.java), [CommandJoinBundle](../src/main/java/monoid/CommandJoinBundle.java), [CommandReset](../src/main/java/monoid/CommandReset.java) | [MonoidBundleTest](../src/test/java/tests/MonoidBundleTest.java), [BundleTest](../src/test/java/monoididentity/BundleTest.java)                                                     |
| Redundant checks                         | [LibSecurity](../src/main/java/monoid/LibSecurity.java) and its generated Identity counterpart                                                                                                                                                                 | [LibSecurityTest](../src/test/java/monoid/LibSecurityTest.java)                                                                                                                     |

These tests are evidence for specific software paths, not a complete audit. Physical
firewall, deletion, native-crypto and fault behavior need evidence from the actual
target card/build; jCardSim does not reproduce all runtime restrictions.

PIN input validation remains an audit item, not an accepted security exception:
the current command paths pass decoded lengths through a `byte` cast before
OwnerPIN calls and do not enforce a nonempty PIN at the request boundary.
The configured OwnerPIN capacity must not be mistaken for complete validation of
the original CBOR input. Review empty and oversized inputs in
[CommandSetPIN](../src/main/java/monoid/CommandSetPIN.java), Command authentication,
MonoidApplet and Safe. This document does not claim that those paths have been fixed.

Record audit findings and their evidence separately from these intended boundaries.
An accepted recovery path does not exempt caller isolation, authentication,
input handling or implementation correctness from review.

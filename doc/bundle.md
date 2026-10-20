# Bundle

A Bundle shares one random 32-byte key among a fixed set of card identities.
Identity generates and retains the key; Monoid and the host receive only encrypted
enrollment packets and `SHA-256(key)`. The hash is the `bundle` value returned by
Hello and Bundle management. It covers the key alone, not a protocol
version or member list.

Bundle management uses Secret PIN and `0x23 Create Bundle` and `0x24 Join Bundle`,
defined in [README](../README.md#0x23-create-bundle).
Access PIN and item data remain in Monoid; Secret PIN, its retry state, the Bundle
key and membership remain in Identity across Monoid reinstallation.
Identity restricts Bundle creation, joining and clearing to Monoid's exact fixed AID.
Other applets can use encrypted transfer after their own Secret PIN verification,
but cannot change this shared configuration.

## Initialization

1. Read Hello from every intended card and retain its full `publicKey`.
2. On any one card A, authenticate with the Secret PIN and call Create Bundle with
   the complete `publicKeys` list, including A. The response contains `bundle` and all
   recipient `packets`, in request-list order with A omitted. Keep the packets,
   A's public key and the full Bundle hash.
3. Visit the recipients in any order. Authenticate with each card's Secret PIN and
   call Join Bundle with A's `senderPublicKey` and that recipient's
   packet `data`. Compare the returned `bundle` with A's full hash immediately.

No return visit to A, final verification round or extra Hello call is required.
Hello serves ordinary card discovery. The host tracks completion separately for
each card. A matching response hash confirms that the card reports the same stored
key; it is not an authenticated receipt sent back to A.

Generation requires at least two distinct public keys and includes the local
Identity. It sorts the full 65-byte keys lexicographically by unsigned bytes for
the authenticated member list. The response packets retain request order.
Membership is fixed for that key. Create rejects an existing Bundle, including
when the same list is supplied. An enrollment packet must include both the receiving
Identity and its authenticated sender in its membership.

Identity finishes encrypting every recipient packet before publishing the new
local Bundle. A failed packet preparation leaves the card without a Bundle.

Join commits the key and membership together. Rejoining the same key and membership
succeeds unchanged; a different key or list conflicts. Interrupted recipient
initialization can resume with the saved packets. Create cannot be replayed to
recover lost packets once the Bundle exists. There is no atomic commit across all
cards, and one unavailable member does not roll back other members.

## Enrollment packet

Public keys are 65-byte uncompressed SEC 1 P-256 points. `u16` is unsigned
big-endian; labels are ASCII without a terminator.

```text
01 || u16(memberCount) || sortedPublicKeys || encryptedBundleKey

info = SHA-256("Monoid Bundle Enrollment" || 01 || sortedPublicKeys)
```

`encryptedBundleKey` is the 113-byte RFC 9180 Auth envelope described in
[Monoid Identity](identity.md#hpke-profile): `enc[65] || ciphertext[32] || tag[16]`.
The sender is the exporting Identity and the recipient is the selected member.
The HPKE `info` binds the version and complete sorted membership. The total packet
length is `116 + 65 * memberCount` bytes.

The member list is public; the Bundle key is encrypted. Identity checks the list,
recipient, sender and HPKE authentication before committing. Ordinary item
decryption cannot select this enrollment domain or return the Bundle key.
Compatibility is determined by supported packet versions, independently of the
key hash.

## Item transfer

Without a Bundle, Export requires a recipient public key and uses the asymmetric
version `01` envelope. Once enrolled, every Export uses the Bundle version `02`
envelope; a supplied recipient public key is ignored. Identity writes its actual
public key into the artifact and derives a sending key from the Bundle root,
complete runtime caller AID and that public key. The same applet AID on another
member can import the artifact after Secret authentication. The sender key is
inside the envelope, so Import needs no separate sender public key.

Identity rejects its own Bundle artifacts, senders outside the fixed membership
and artifacts from another caller domain. An enrolled card can still import
asymmetric artifacts from another Identity, but cannot recover its own earlier
self-addressed asymmetric artifacts. The host cannot choose another sending
identity for Export. These restrictions are enforced by trusted Identity code;
symmetric keys themselves are not encryption-only keys.

Other applets can exchange records between cards in their own caller domains
without gaining access to Monoid's encrypted records. The root key, membership
and public Bundle hash are shared; the derived sender keys remain inside Identity.

See [item transfer](item-transfer.md) for both formats and key derivation.

The host must verify the intended public keys before creating the membership.
The four-byte display ID is insufficient for that decision. Bundle membership
does not certify card hardware or installed applet code.

## Reinitialization

`0xFF Reset` requires no PIN and returns Monoid to an uninitialized state. It clears
all local items, the derivation cache, both PINs and their failed-attempt/blocked
state, and the local Bundle. It generates a new Identity key pair, ID and binding
secret, clears the token cache and updates Monoid's binding. These persistent
changes commit in one transaction; success clears current authorization and
requests garbage collection. A failed transaction retains the previous persistent
state. It is not a hardware-erasure guarantee.
The request and response are both `{}`. The former `0x25` instruction is unsupported.

Anyone able to send Monoid APDUs can clear these records. This is an intentional
availability boundary, not permission to read or export them. Reset still verifies
Monoid's existing binding to Identity before preparing its replacement. Hello then
returns the new `id` and `publicKey`, `pins: {access: false, secret: false}`
and `bundle: false`; the next user must initialize new PINs before ordinary storage
or Bundle management. Reset recovers from blocked PINs by deleting the protected
data and both PINs together, rather than unlocking access to the old records.

After PIN initialization, Create can establish a new Bundle or Join can accept
an enrollment packet addressed to the new public key. Old asymmetric artifacts
and enrollment packets no longer decrypt on the reset Identity, and the old
Bundle key is gone. Reset does not erase other cards or revoke copies or plaintext
already delivered elsewhere. Other applets' saved binding tokens become invalid;
they are not automatically rebound to the new identity.

GlobalPlatform management can instead delete and recreate applet instances;
their CAP packages can remain loaded. Delete dependent instances first and recreate
their providers first. For Monoid and Identity, delete Monoid before Identity, then
create Identity before Monoid. Clients holding Shareable references must release
them or be deleted first.

Reset retains both installed applet instances and their code while replacing
their identity and local data state. It does not perform a GP uninstall/reinstall.

Recreating Monoid clears its items, Access PIN and derivation cache but retains
Identity's Secret PIN, retries and Bundle. Recreating Identity as well clears the local Bundle and generates a new key
pair, ID and binding secret. Retaining the old Monoid across Identity replacement
does not bypass its identity binding. Reinitialization does not affect other cards
or revoke existing artifacts. The new Identity cannot decrypt old asymmetric
artifacts or use enrollment packets addressed to the previous public key; collect
the new public key before creating a new Bundle.

## Recovery and data migration

The current interface permits using two Bundle members to recover plaintext.
For a fresh export and recovery, use both cards and authenticate each card's
Secret PIN independently:

1. Export the selected source records after Secret PIN authentication.
2. Keep the other card's Identity and Bundle, and replace its Monoid applet with
   a recovery implementation registered under the same fixed Monoid AID.
3. Authenticate the receiving card's retained Secret PIN and give the records
   and metadata to that implementation. Identity permits decryption because the
   sender is another Bundle member; the recovery code can return the plaintext.

Installing the recovery implementation requires the card's management authority.
Replacing the recipient's Monoid deletes its previous items and Access PIN; its
Secret PIN remains in Identity and is still required. Members may use different
Secret PINs. Previously exported artifacts can be reused without a new source PIN
check; this boundary does not require the source card or its PIN to be presented
again each time the recipient decrypts an existing artifact.

Identity binding prevents replacement of Identity underneath a retained Monoid
from silently changing its export policy. Caller isolation prevents an applet
with another AID from reading Monoid artifacts. Neither mechanism forbids the
same-AID recovery workflow above; Bundle is not a permanent non-exportability or
code-authentication guarantee. Same-card Monoid replacement cannot make Identity
decrypt its own Bundle artifact or bypass its retained Secret PIN. Recovery
through another authorized member remains supported, including returning data
encrypted by that second member to the first. Plaintext or artifacts already
released through an authorized chain cannot be revoked by later PIN changes or
Reset. This does not require simultaneous presence of both cards.

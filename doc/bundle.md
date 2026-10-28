# Bundle

A Bundle shares one 32-byte root key among enrolled card identities.
Create Bundle generates a random root inside Identity; an installed
[Authority](authority.md) can instead issue it. Identity retains the root and its
`allowPeerExtension` policy; Monoid and the host receive only encrypted
enrollment packets and `SHA-256(key)`. The hash is the `bundle` value returned by
Hello and Bundle management. It covers the key alone, not the policy, a protocol
version or member list. An issuer must keep the policy fixed for every holder of
the same root.

Hello also returns the flat `allowPeerExtension` boolean, false when not enrolled.
The card alias is separate Identity state and is never included in Bundle state,
enrollment or item export/import; item aliases retain their existing transfer semantics.

Bundle management uses Secret PIN and `0x23 Create Bundle`, `0x24 Join Bundle`,
`0x25 Extend Bundle` and `0x26 Approve Bundle Extension`, defined in
[README](../README.md#0x23-create-bundle).
Access PIN, the installation token and item data remain in Monoid; Secret PIN,
its retry state, the authorized Monoid token hash, the Bundle
key, policy and enrollment snapshot remain in Identity across Monoid reinstallation.
Identity restricts Bundle creation, joining, extension and clearing
to Monoid's exact fixed AID.
Other applets can use encrypted transfer after their own Secret PIN verification,
but cannot change this shared configuration.

## Initialization

1. Read Hello from every intended card and retain its full `publicKey`.
2. On any one card A, authenticate with the Secret PIN and call Create Bundle with
   only the other cards' `publicKeys`. The response contains the newly generated
   `bundle` hash and one encrypted byte-array `data[i]` for each
   `publicKeys[i]`, in the same order. Keep that association, A's public key and
   the full Bundle hash.
3. Visit the recipients in any order. Authenticate with each card's Secret PIN and
   call Join Bundle with A's Identity key as `publicKey` and that recipient's
   packet as `data`. Compare the returned `bundle` with A's full hash immediately.

No return visit to A, final verification round or extra Hello call is required.
Hello serves ordinary card discovery. The host tracks completion separately for
each card. A matching response hash confirms that the card reports the same stored
key; it is not an authenticated receipt sent back to A.

Create requires at least one recipient, rejects duplicates and the local public
key, and adds the local Identity internally. It sorts the full 65-byte keys
lexicographically by unsigned bytes for the authenticated enrollment snapshot.
The response packets retain request order; public keys are not echoed.
Create rejects an existing Bundle, including when the same list is supplied,
and sets `allowPeerExtension` to `true`.
A peer enrollment packet must include both the receiving Identity and its
authenticated sender in its member list.

Identity finishes encrypting every recipient packet before publishing the new
local Bundle. A failed packet preparation leaves the card without a Bundle.

Join commits the key, policy and enrollment snapshot together. Rejoining the same
key and policy succeeds unchanged, retaining the local snapshot; a different key
or policy is rejected with the Monoid RPC error `INTERNAL`, exception
`ISOException` and reason `27013` (`6985`). Join never replaces an existing Bundle. Interrupted
recipient initialization can resume with the saved packets. Create cannot be
replayed to recover lost packets once the Bundle exists. There is no atomic commit
across all cards, and one unavailable member does not roll back other members.

Authority-issued enrollment uses the same Join command, with the installed
Authority's public key as `publicKey`. It targets one recipient and requires no
existing member to participate. The Authority chooses `allowPeerExtension` when
issuing the group's token; see [Authority issuance](authority.md). An Authority
packet cannot replace an existing Bundle or change its policy.

## Extension

Adding C requires two distinct existing members A and B, each verifying its own
Secret PIN inside Identity and permitting `allowPeerExtension`. Identity rejects
both Extend and Approve when this policy is false. The policy does not restrict
Authority issuance. Read C's full Identity public key first, then:

1. On A, call `0x25 Extend Bundle` with `{publicKey: C}`. Retain its `data`.
   Identity authenticates its own public key, the current Bundle hash
   and C's full public key with a dedicated Bundle-root HMAC and Identity signature.
2. On B, retain the `bundle` from Hello and call `0x26 Approve Bundle Extension`
   with A's `{data}` response. B verifies both proofs, including that A is a
   different Identity holding the same Bundle key. It returns `{publicKey, data}`:
   B's actual Identity public key and an encrypted enrollment packet for C.
3. On C, forward B's response unchanged to `0x24 Join Bundle`, under C's own
   Secret PIN. Verify the returned Bundle hash against B's Hello value.

Extend's `data` is an opaque, authenticated request bound to the initiator,
target and Bundle. The host forwards it unchanged; the target cannot be replaced
on B. Approve's `data` is an encrypted enrollment packet addressed to C, and its
`publicKey` identifies B, not C. Neither result gives the host the Bundle key.

Create returns `bundle` because it generates a new key. Extend and Approve keep
the existing key and do not return a separate `bundle` field. Join returns the hash of the key
actually installed, allowing the host to confirm the result without another scan.
Join uses `publicKey` to authenticate the HPKE sender. The approving card returns
that key directly, so the host need not assemble or look up a separate sender field.

Data transfer and approval eligibility are separate checks. Data transfer verifies
the derived sender key and payload tag without consulting the enrollment snapshot.
Extension requires both proof of the same Bundle root and a signature by another
Identity. The HMAC alone cannot prove a second Identity participated; the signature
alone cannot prove that its signer holds the Bundle key. Both bind the actual
initiator and the specified target in a domain unavailable to ordinary item transfer.

After Join, C inherits the root's policy and can immediately exchange data and,
when allowed, participate in further extensions.
No return visit to A, member-list synchronization or final proof installation is
needed. Extend and Approve leave A's and B's persistent Bundle configuration unchanged.
The stored member list records enrollment, not a live authorization roster.

Retain `data` until C joins. Requests bind one target identity and may be retried
for that target; Approve can regenerate its encrypted packet. There is no
simultaneous-presence requirement, request expiry or revocation. One surviving
member cannot authorize another member alone. Ordinary item encryption cannot
produce an extension request or release the Bundle key.

Extension retains the Bundle key, Hello hash and per-sender keys. Existing
ciphertext remains usable, and C can decrypt historical artifacts from other
members. Adding a replacement card does not revoke a lost card; transferring
resources to a new Bundle is a separate operation.

## Enrollment packet

The extension request is encoded separately from enrollment:

```text
statement = 01 || bundleHash[32] || initiatorPublicKey[65] || targetPublicKey[65]
domain = "Monoid Bundle Extension"
mac = HMAC-SHA256(bundleKey, domain || statement)
signature = ECDSA-SHA256(identityPrivateKey, domain || statement || mac)

data = statement || mac[32] || u8(signatureLength) || signature
```

The signature uses ASN.1 DER encoding, at most 72 bytes. The packet must end
exactly after the declared signature. The initiator's actual Identity fills its
public key and Bundle hash; callers supply only the target. The confirming
Identity rejects its own public key as initiator and verifies both MAC and
signature before encrypting the root for the bound target.

The extension enrollment packet uses the same format below. Its snapshot is the
confirming card's stored snapshot plus the target if absent, sorted without
duplicates. This does not update the confirming card's local snapshot.

Public keys are 65-byte uncompressed SEC 1 P-256 points. `u16` is unsigned
big-endian; labels are ASCII without a terminator.

```text
header = 01 || flags || u16(memberCount) || sortedPublicKeys
data = header || encryptedBundleKey

flags bit 0 = allowPeerExtension
flags bit 1 = Authority-issued packet

domain = "Monoid Bundle Enrollment"  when bit 1 is clear
domain = "Monoid Authority Bundle"   when bit 1 is set
info = SHA-256(domain || header)
```

`encryptedBundleKey` is the 113-byte RFC 9180 Auth envelope described in
[Monoid Identity](identity.md#hpke-profile): `enc[65] || ciphertext[32] || tag[16]`.
The HPKE `info` binds the complete header, including policy, packet kind and member
count. Unknown flag bits are rejected. The total packet length is
`117 + 65 * memberCount` bytes.

Peer packets contain at least two sorted, distinct keys, including sender and
recipient. The sender is the exporting Identity and the recipient is the selected
member. Authority packets contain exactly one key, the recipient, and authenticate
the installed Authority as sender. The Authority flag selects packet validation;
it is not persisted as the root's provenance. Peer extension of an Authority-issued
root produces a peer packet with the same policy.

The enrollment snapshot is public; the Bundle key is encrypted. Identity checks the list,
recipient, sender, policy and HPKE authentication before committing. Ordinary item
decryption cannot select this enrollment domain or return the Bundle key.
This replaces the earlier prototype's enrollment layout while retaining version
`01`. Old enrollment packets must be regenerated; no legacy parser is provided.
Item ciphertext is unchanged.

## Item transfer

Without a Bundle, Export requires a recipient public key and uses the asymmetric
version `01` envelope. Once enrolled, every Export uses the Bundle version `02`
envelope; a supplied recipient public key is ignored. Identity writes its actual
public key into the artifact and derives a sending key from the Bundle root,
complete runtime caller AID and that public key. The same applet AID on another
member can import the artifact after Secret authentication. Bound Monoid instances
can instead export/import Bundle artifacts after Access authentication. The sender key is
inside the envelope, so Import needs no separate sender public key.

Identity rejects its own Bundle artifacts and artifacts from another caller
domain. Other senders are authenticated by the shared root and derived sender
key, independently of the local enrollment snapshot. An enrolled card can still import
asymmetric artifacts from another Identity with Secret authentication, but cannot recover its own earlier
self-addressed asymmetric artifacts. The host cannot choose another sending
identity for Export. These restrictions are enforced by trusted Identity code;
symmetric keys themselves are not encryption-only keys.

Other applets can exchange records between cards in their own caller domains
without gaining access to Monoid's encrypted records. The root key and public
Bundle hash are shared; the derived sender keys remain inside Identity.

Successful Secret PIN authentication binds the current Monoid installation's
private random token to Identity. Later Access-authenticated synchronization checks
both Identity's existing binding token and Monoid's installation token. The latter
authorizes only Bundle transfer, not asymmetric transfer or Bundle/PIN management.
Replacing Monoid loses it and requires Secret PIN again; the same AID alone is
insufficient. See [mutual binding](identity.md#mutual-binding).

See [item transfer](item-transfer.md) for both formats and key derivation.

The host must verify the intended public keys before creating the membership.
The four-byte display ID is insufficient for that decision. Bundle membership
does not certify card hardware or installed applet code.

## Reinitialization

`0xFF Reset` requires no PIN and returns Monoid to an uninitialized state. It clears
all local items, the derivation cache, both PINs and their failed-attempt/blocked
state, the authorized Monoid token hash and the local Bundle. It preserves the Card ID, card alias and installed Authority URL and key,
generates a new Identity key pair, binding secret and Monoid installation token,
clears the token cache and updates Monoid's Identity binding. These persistent
changes commit in one transaction; success clears current authorization and
requests garbage collection. A failed transaction retains the previous persistent
state. It is not a hardware-erasure guarantee.
The request and response are both `{}`.

Anyone able to send Monoid APDUs can clear these records. This is an intentional
availability boundary, not permission to read or export them. Reset still verifies
Monoid's existing binding to Identity before preparing its replacement. Hello then
returns the same `id`, the new `publicKey`, `pins: {access: false, secret: false}`
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

Recreating Monoid clears its items, Access PIN, installation token and derivation
cache but retains Identity's card alias, Secret PIN, retries, old token hash and
Bundle. The new instance must authenticate Secret PIN before transfer or rebinding.
Recreating Identity as well clears
the card alias and local Bundle and generates a new key pair and binding secret;
the Card ID can be supplied again in installation parameters.
Retaining the old Monoid across Identity replacement
does not bypass its identity binding. Reinitialization does not affect other cards
or revoke existing artifacts. The new Identity cannot decrypt old asymmetric
artifacts or use enrollment packets addressed to the previous public key; collect
the new public key before creating a new Bundle.

## Recovery and data migration

For a Bundle created on a card, the current interface permits using two members
to recover plaintext. An Authority-issued root additionally trusts its issuer;
see [Authority's trust boundary](authority.md#trust-and-lifecycle).
For a fresh export and recovery, use the source card's Access or Secret PIN and
the receiving card's Secret PIN:

1. Export the selected source records after Access authentication in a bound Monoid
   instance, or after Secret authentication.
2. Keep the other card's Identity and Bundle, and replace its Monoid applet with
   a recovery implementation registered under the same fixed Monoid AID.
3. Authenticate the receiving card's retained Secret PIN and give the records
   and metadata to that implementation. Identity permits decryption because the
   sender is another Bundle member; the recovery code can return the plaintext.

Installing the recovery implementation requires the card's management authority.
Replacing the recipient's Monoid deletes its previous items, Access PIN and
installation token; its Secret PIN remains in Identity and is still required.
The old token cannot be reacquired by the new instance. Members may use different
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

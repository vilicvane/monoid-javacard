# Bundle

A Bundle shares one random 32-byte key among a fixed set of card identities.
Identity generates and retains the key; Monoid and the host receive only encrypted
enrollment packets and `SHA-256(key)`. The hash is the `bundle` value returned by
Hello and Bundle management. It covers the key alone, not a protocol
version or member list.

Bundle management uses the Safe PIN and `0x23 Create Bundle`, `0x24 Import Bundle`
and `0x25 Reset Bundle`, defined in [README](../README.md#0x23-create-bundle).
Both PINs and item data remain in Monoid;
the Bundle key and membership remain in Identity across Monoid reinstallation.

## Initialization

1. Read Hello from every intended card and retain its full `publicKey`.
2. On any one card A, authenticate with the Safe PIN and call Create Bundle with
   the complete `publicKeys` list, including A. The response contains `bundle` and all
   recipient `packets`, in request-list order with A omitted. Keep the packets,
   A's public key and the full Bundle hash.
3. Visit the recipients in any order. Authenticate with each card's Safe PIN and
   call Import Bundle with A's `senderPublicKey` and that recipient's
   packet `data`. Compare the returned `bundle` with A's full hash immediately.

No return visit to A, final verification round or extra Hello call is required.
Hello serves ordinary card discovery. The host tracks completion separately for
each card. A matching response hash confirms that the card reports the same stored
key; it is not an authenticated receipt sent back to A.

Generation requires at least two distinct public keys and includes the local
Identity. It sorts the full 65-byte keys lexicographically by unsigned bytes for
the authenticated member list. The response packets retain request order.
Membership is fixed for that key; generating again creates a new key and replaces
the local Bundle, including when the same list is supplied. It does not update
other members. An enrollment packet must include both the receiving Identity and
its authenticated sender in its membership.

Identity finishes encrypting every recipient packet before publishing the new
local Bundle. A failed packet preparation preserves the previous Bundle.

Import commits the key and membership together. Reimporting the same key and
membership succeeds unchanged; a different key or list conflicts. Clear a
recipient's existing Bundle before importing a different one. Interrupted
recipient initialization can resume with the saved packets; do not replay the
generating request as a retry, because it creates another key. There is no atomic
commit across all cards, and one unavailable member does not roll back other members.

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

## Item transfer and reset

Without a Bundle, Export requires a recipient public key and uses the asymmetric
version `01` envelope. Once enrolled, every Export uses the Bundle version `02`
envelope; a supplied recipient public key is ignored. Any member holding the same
key can import that artifact without a sender public key. This authenticates
membership in the group, not the individual exporting card. An enrolled card can
still import asymmetric artifacts addressed to its Identity.

See [item transfer](item-transfer.md) for both formats and key derivation.

Reset Bundle with `{}` removes the local key and membership while preserving the
Identity key pair, ID, items and both PINs. Hello then returns `bundle: false`, and
Export again requires an asymmetric recipient. Clearing does not change other cards
or revoke existing artifacts. This card cannot decrypt earlier Bundle artifacts
until the same Bundle key is installed again.

The host must verify the intended public keys before creating the membership.
The four-byte display ID is insufficient for that decision. Bundle membership
does not certify card hardware or installed applet code.

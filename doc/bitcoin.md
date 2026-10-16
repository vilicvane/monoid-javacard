# Bitcoin signing

Monoid supports BIP32 derivation and ECDSA or BIP340 Schnorr signing on
`secp256k1`. Taproot uses the existing `0x40` View key and `0x41` Sign commands,
with the same seed, master and independent `secp256k1` Safe items. Hello and
System information advertise `['ecdsa', 'bip340']` under the `secp256k1` curve.
The complete request and response definitions are in the [README](../README.md#0x40--0x4f-key-usage).

## BIP86 single-key accounts

Use a stored seed with `type: 'seed'` and
`derivation: {type: 'bip32', path: bytes}` for the
BIP86 path `m/86'/coin_type'/account'/change/address_index`. For Bitcoin mainnet,
the first receiving key is `m/86'/0'/0'/0/0`. Encode the path using the existing
BIP32 format: four bytes per index in big-endian order, with bit 31 set for
hardened indices. A stored master uses `type: 'master'` with the same derivation.
BIP32 fixes secp256k1 and uses `Bitcoin seed` for master generation.
[BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
defines the account layout and no-script-tree output construction.

1. Call View key with the key description and `taproot: true`. Its `publicKey` is
   the 32-byte output key used to construct the Taproot address.
2. Build the transaction and calculate its 32-byte Taproot signature hash on
   the client.
3. Call Sign with the same key description, `cipher: 'bip340'`, that `digest`
   and `taproot: true`. The result is `{signature}` containing 64 bytes.
4. Assemble the witness and transaction on the client.

An independent `secp256k1` item uses `index` and `type: 'secp256k1'` without derivation.
The card performs TapTweak after any BIP32 derivation. It does not infer the
signature mode or apply a tweak based on the derivation path.

## Taproot options

The optional `taproot` field accepts a boolean or object, with the same meaning
in View key and Sign:

| Request field                    | Key used                                                   |
| -------------------------------- | ---------------------------------------------------------- |
| Omitted or `taproot: false`      | Original stored or derived secp256k1 key, without a tweak. |
| `taproot: true` or `taproot: {}` | BIP86 output key, committing to no script tree.            |
| `taproot: {merkleRoot: bytes}`   | BIP341 output key committing to the supplied script tree.  |

`merkleRoot`, when present, must contain exactly 32 bytes. An omitted root and
a root consisting of 32 zero bytes are different commitments. The client
constructs the script tree and its root; the card applies the BIP341 TapTweak.
Use the same root when querying the output key and signing through its key path.

View key returns a 32-byte x-only output key when `taproot` is enabled and the
existing 33-byte compressed public key when it is omitted or `false`. Seed and
master queries also return the original derived node's 32-byte `chainCode`. The
tweaked public key and that chain code do not form a BIP32 extended public key:
derive child nodes before applying TapTweak. Independent key queries have no
chain code.

Only `secp256k1` View key and `cipher: 'bip340'` Sign accept `taproot`.
Other branches reject the field even when its value is `false`.

## Signature hashes and transaction encoding

For Taproot key-path spending, pass the final 32-byte
`TapSighash` digest defined by
[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message).
The card signs these bytes as the BIP340 message; it does not calculate the
transaction signature hash or parse transaction inputs, outputs, scripts or
amounts. The client also handles address encoding and transaction assembly.

The returned Schnorr signature is always the 64-byte `r || s` encoding. For
`SIGHASH_DEFAULT`, use those 64 bytes as the signature witness element without
appending `00`. For another supported sighash type, append its nonzero byte on
the client, matching the type used to calculate the digest.

Omitting `taproot` or setting it to `false` performs raw BIP340 signing. The
corresponding x-only public key is the existing compressed public key with its
first byte removed. This
can sign a client-prepared [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension)
script-path digest for the selected script key. Script construction, control
blocks and MuSig protocols are outside the card's signing API.

Existing `cipher: 'ecdsa'` requests sign a 32-byte digest and return a 64-byte
`r || s` signature, with each integer encoded as 32 big-endian bytes. For earlier
Bitcoin output types, the client converts it to DER and appends the sighash byte.
The client chooses the transaction signature hash and witness or script encoding.

## Signing implementation

Each Schnorr signature uses 32 bytes of card-generated auxiliary randomness
with BIP340's tagged nonce derivation. Callers do not supply the auxiliary data.
The implementation reuses the existing shared secp256k1 and modular arithmetic
resources and does not depend on transient values surviving between commands.

The card does not verify its own Schnorr signature before returning it, following
the project's trusted execution assumption. [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing)
recommends self-verification and permits omitting it when the computation cost
is prohibitive. This implementation does not provide a card-side Schnorr
verification command.

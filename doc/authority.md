# Authority enrollment

An Authority issues the same secret 32-byte Bundle token to cards belonging to one
group. The token is the Bundle root used by [item transfer](item-transfer.md).
Each card receives a separate authenticated encrypted packet addressed to its
Identity public key; the host never needs the plaintext token.

The Authority's service URL and P-256 public key are configured together at
[Identity installation](identity.md#installation-parameters). Monoid Hello returns
the URL as `authority`, or false when neither is configured. The APP can use a
user-selected service; it obtains the initial public key from that service before
installation. Subsequent responses cannot replace the card's trusted key. Its corresponding
private key authenticates issuance through HPKE Auth. This uses the existing key
pair, without another service key or a separate certificate/signature format.

## Issuance flow

1. Read the card's full `publicKey` from Hello and authenticate the user's account
   with the Authority. The service decides which group the user may join.
2. The Authority obtains that group's token and fixed `allowPeerExtension` policy,
   then encrypts a fresh enrollment packet for this public key.
3. Authenticate the card's Secret PIN and call `0x24 Join Bundle`:

   ```ts
   type Request = {
     /** The Authority public key installed in this Identity. */
     publicKey: byte[];
     /** The recipient-specific packet below. */
     data: byte[];
   };

   type Response = {bundle: byte[]};
   ```

4. Compare `bundle` with the group's full `SHA-256(token)` value. The card verifies
   the Authority, recipient, policy and HPKE tag before publishing the Bundle.

These exchanges can run during one continuous card session. Other members need
not be present. Once enrolled, offline copying uses source Export followed by
destination Import, each under that card's Secret PIN.

Token derivation is owned by the Authority service. A deterministic derivation
must bind a fixed group identifier and its policy in a dedicated cryptographic
domain using a server-held secret. Public account IDs or the Authority public key
alone cannot produce a secret token. The issuer must not distribute one root
under conflicting policies; a policy change requires a distinct root and separate
migration. No server implementation or account-authentication API is defined here.

## Peer extension policy

```ts
type BundlePolicy = {
  allowPeerExtension: boolean;
};
```

- `true`: two existing members may authorize another card through Extend → Approve
  → Join. The new card inherits this policy.
- `false`: Identity rejects both Extend and Approve. Additional cards require
  Authority issuance.

The policy does not restrict the Authority from issuing the group's token to
another card. It is authenticated in every enrollment packet and stored alongside
the root. Join accepts the same root and policy without changing local state;
different roots or policies conflict. There is no setter for an installed policy.
Create Bundle on a card always enables peer extension.

## Issued packet

All public keys are 65-byte uncompressed SEC 1 P-256 points. Labels are ASCII
without a terminator; `||` denotes concatenation.

```text
flags = 02 | (allowPeerExtension ? 01 : 00)
header = 01 || flags || 00 01 || recipientPublicKey[65]
info = SHA-256("Monoid Authority Bundle" || header)

encryptedToken = HPKE-Auth-Seal(
  senderPrivateKey = authorityPrivateKey,
  recipientPublicKey,
  info,
  aad = empty,
  plaintext = token[32]
)

data = header || enc[65] || ciphertext[32] || tag[16]
```

The packet is exactly 182 bytes. `00 01` is the unsigned big-endian member count;
an Authority packet contains only its recipient. Unknown flag bits, other counts
or a different recipient are rejected. Join's `publicKey` must equal the installed
Authority key; Identity uses that installed key for HPKE authentication.

HPKE uses RFC 9180 Auth mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and
AES-128-GCM, with an empty PSK and PSK ID, empty additional data, message sequence
zero and fresh encapsulation per issuance. See the [HPKE profile](identity.md#hpke-profile).
The header is public and authenticated through `info`; altering its policy or
packet kind invalidates the tag. No separate ECDSA signature is appended.

This is the Authority variant of the [Bundle enrollment format](bundle.md#enrollment-packet).
The packet-kind flag is not persistent provenance: an allowed peer extension
produces an ordinary peer enrollment packet carrying the same root and policy.

## Trust and lifecycle

The installation authority chooses the trusted issuer. Identity does not let the
host replace that public key at runtime. An unset Authority rejects Authority
enrollment. Its presence does not authorize replacing an existing Bundle, changing
its policy or exporting a card-created Bundle root to the service. A card-created
Bundle retains its existing two-member recovery boundary.

For an Authority-issued Bundle, the Authority knows the root. It can admit new
recipients and derive the keys needed to decrypt captured Bundle item artifacts
without contacting either card or checking either PIN. Its issuance policy and
server-secret custody are therefore part of the confidentiality boundary. Secret
PIN checks still protect on-card enrollment and data operations; they do not
constrain a party that already knows the root.

Issuance has no challenge, expiry or single-use property. A saved packet may be
retried for its original Identity; it cannot be redirected to another public key.
Monoid reinstallation retains Identity, the Bundle and Secret PIN. `0xFF Reset`
preserves Card ID and Authority configuration but clears the Bundle and both PINs,
and generates a new Identity key pair. Old enrollment packets no longer decrypt;
the Authority may issue a fresh packet for the new key after its account checks.
Restoring a Card ID alone does not restore a private key or enrollment eligibility.

This mechanism does not prove genuine card hardware, trusted applet code, fresh
card presence or revocation of earlier members and ciphertext. Card certificates
are not defined by this protocol.

## Signed time

The same installed Authority key verifies challenge-bound time for [OTP](otp.md).
The APP forwards a card-generated challenge to the service identified by Hello's
`authority` URL:

```text
POST /v1/time
{challenge: base64url(32B)}

-> {publicKey, data, signature} // Unpadded base64url

data = 01 || unixSeconds_u64_BE || challenge[32]
message = ASCII("Monoid Authority Time") || data
signature = ECDSA-P256-SHA256(message) // 64B r || s
```

Identity's `verifyAuthorityTime(data, signature, challenge)` accepts global arrays,
checks the 41-byte data layout, expected challenge and signature, and returns void
on success. It uses the installed key, not the HTTP response's `publicKey`. An
unset Authority rejects verification. The caller owns challenge generation,
single-use state and the allowed operation; Identity retains no challenge or
user authorization from verification.

The signature binds the service's issuance time. Without a card clock, it cannot
prove how promptly the host delivered the response. OTP limits calculations to
the signed window and its next two windows when Authority is configured. It rejects
host-chosen time in that mode, including when the service is unavailable or its
proof fails. Cards without Authority instead accept the APP's unsigned time through
OTP Prepare, as specified in [OTP](otp.md). That mode does not authenticate time.

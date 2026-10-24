# Monoid Security Key

CTAP2.0 over NFC, ES256, resident credentials and ClientPIN protocol 1.

## Installation

Install Monoid Identity, Monoid Library and Monoid first, then:

```sh
gp --install build/javacard/monoidsecuritykey.cap --create A0000006472F0001
```

The CAP module AID is `F06D6F6E6F69640301`; the installed instance uses the standard
FIDO NFC AID `A0000006472F0001`. No default-selection privilege is required by the
applet. Removing Monoid's code package requires removing its dependent Security
Key package first.

Authorize the installed instance through Monoid `0x51 Set Applet Grant`, under
Access PIN:

```typescript
{
  aid: hex('A0000006472F0001'),
  types: [[-3839, true]], // Signed 16-bit encoding of 0xF101.
  seed: {index: seedIndex, domain: applicationDomain},
}
```

`seedIndex` refers to a 64-byte seed. Preserve the seed, domain and resident
credential records together for recovery; non-resident credentials need only the
seed and domain. Security Key reinstallation creates a new private
installation token; enroll it again rather than copying an old token hash.
The FIDO PIN is independent of Access PIN and Secret PIN and is set by the FIDO client.

## Monoid interface

Security Key obtains Monoid's Shareable interface with parameter `1`, which permits
reuse for the same caller and current grant. Every acquisition clears the session's
authentication, and Security Key authenticates its installation token again.
Parameter `0` creates independent sessions. Card reset, Monoid Reset, grant
replacement or revocation invalidates old sessions and their handles permanently.

The [Monoid](../src/main/java/monoid/Monoid.java) and
[iterator](../src/main/java/monoid/SafeItemIteratorShareable.java) interfaces retain
their handle methods and add direct operations:

| Operation       | Contract                                                                                                                                                                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `readData`      | Returns total data length and copies up to the byte capacity; `-1` means absent or different `expectedMetadata`. Null matches only null. No cross-call snapshot.                                                                                                          |
| `getData`       | Returns a data snapshot for an index range and exact `expectedMetadata`; null means absent or different metadata. Snapshot reads retain the current session and data checks.                                                                                              |
| `isDataCurrent` | Checks a previously issued data snapshot through the current authenticated session. Returns false for deleted, replaced or changed data; current Type and nonsecret permissions are required. Does not reactivate the snapshot's old session.                             |
| `nextData`      | Advances once and returns the true index plus a data prefix; `-1` means end. Different `expectedMetadata` fails with `6985`. Output regions must not overlap; restart enumeration after an error that advanced it.                                                        |
| `listIndices`   | Applies the Type/grant and `metadataPrefix` filters; null or empty prefix means no metadata filter. Returns the total count and copies the first `capacity` 10-byte indices. Capacity counts indices. Prefix and output ranges must not overlap; no snapshot is retained. |
| `createData`    | Copies a complete index/metadata/alias/data record without a callback; returns false if the index exists. Requires a writable Type and preserves normal validation and storage publication.                                                                               |

Authentication, derivation, signing and direct reads have offset/length overloads
for global arrays, including the shared APDU buffer. Token and digest inputs remain
32 bytes. Inputs are consumed before overlapping output is written; no caller
buffer is retained. Only the selected client obtains the APDU buffer and passes it
to Monoid. Short creation uses `createData`; larger records retain callback reads
through a separate global window of up to 256 bytes.

Discovery reuses space for four matching indices/IDs, falling back to the iterator
for larger sets. This is an internal buffer budget, not a credential limit.
Four records of up to 320 bytes retain their payload and parsed offsets in
persistent storage. Parsed offsets are restored into RAM after deselection or
reset; filling a slot writes them together.
Every cache hit validates the original data snapshot through the current session,
including after reset and reauthentication. Long records retain stable reads;
larger sets fall back to enumeration. `GetNextAssertion` reconnects and validates
the selected record; caller, grant, Type, secret, full credential ID, RP and
public-key checks remain. These SIO additions do not add CTAP commands.

## Commands

| CTAP command            | Function                                                    |
| ----------------------- | ----------------------------------------------------------- |
| `0x01` MakeCredential   | ES256 packed self attestation; optional resident credential |
| `0x02` GetAssertion     | Known credential ID or resident lookup by RP                |
| `0x04` GetInfo          | `FIDO_2_0`, `rk`, `up`, current `clientPin`, PIN protocol 1 |
| `0x06` ClientPIN        | Retries, key agreement, set/change PIN, encrypted PIN token |
| `0x07` Reset            | Remove `0xF101` records, then clear the FIDO PIN            |
| `0x08` GetNextAssertion | Continue the current resident lookup                        |

Delete an individual resident credential using Monoid `0x35 Remove` on its item
index. Its old credential ID then returns `NO_CREDENTIALS`. Non-resident
credentials have no record to remove; they stop working only when the granted
seed contents or domain change. CTAP2.1 credential management,
U2F and optional extensions are not advertised.

Reset removes credential records from every seed/domain scope and commits their
removal before clearing the FIDO PIN. Non-resident credentials are derived from the
seed and domain, so they remain valid after Reset. If interrupted
between these steps, the records are gone and the PIN remains; retry Reset to
finish. Other Monoid data, PINs and grants are unchanged.

NFC SELECT returns `FIDO_2_0`. Requests use `90 10` intermediate and `80 10` final
frames, or an extended-length APDU, with a maximum complete message of 1200 bytes.
Replies contain one CTAP status byte, CBOR and `9000`; `61xx` requests ISO GET
RESPONSE (`00 C0` or `80 C0`) when the response exceeds the requested length.
Extended APDUs can receive the complete response without GET RESPONSE.
This transport does not use Monoid's custom framing.
`80 12 01 00` disables the applet until a new SELECT.

## Credentials and derivation

Only resident registration stores a record; non-resident registration stores nothing.
Credential records use Type `0xF101`, lookup `metadata = scope || SHA256(rpId)` and
`secret = false`. Their versioned CBOR data contains the random 32-byte credential
ID, RP hash/ID, user ID and optional names, 65-byte public key and 32-byte scope
(integer field `10`). Field `8`, the former resident flag, is no longer written or
read.
The item index is `F101 || credentialId[0:8]`; collisions regenerate the ID.
All 32 ID bytes, the scope and RP hash are checked on lookup. The scope identifies
the granted seed contents and domain independently of card identity, installation
token or local seed index. Switching either input hides the other scope's records
without removing them; switching back makes them available again. Old records
without a scope are not matched or automatically migrated.

A non-resident credential ID is self-authenticating:

```text
idKey        = SHA256("monoid fido2 id: " || scopePoint)
credentialId = nonce[16] || HMAC-SHA256(idKey, SHA256(rpId) || nonce)[0:16]
```

`scopePoint` is the 65-byte public key whose hash is `scope`; it is never returned,
so `idKey` is not derivable from a stored scope. An allow or exclude list entry
whose tag verifies for the current scope and RP is accepted without a lookup,
and its key is derived as below. Otherwise the ID is looked up as a resident record.

Resident registration collects all existing resident records for the same scope,
RP and user. If duplicates exist, it first removes all but the first old record, then
commits the new record and removes the retained old record. Each change commits
independently; an interrupted replacement preserves an old or new credential. A
successful retry leaves only its new record. Every registration generates a new credential
ID, including retries. Other accounts are unchanged.

Duplicate cleanup releases references and requests garbage collection; it does
not guarantee reclaimed space within the same command. Creation can still fail
after cleanup commits and require another attempt.

```text
Monoid-001 context = "monoid applet: " || u16be(domain.length) || domain || clientContext
clientContext     = "monoid fido2: " || SHA256(rpId) || credentialId
scopeContext      = "monoid fido2 scope: " || zeroBytes(58)
scope             = SHA256(Monoid.getMonoid001PublicKey(scopeContext))
```

Labels are ASCII with one trailing space. Scope and credential contexts are both
78 bytes, allowing Monoid to reuse its private context buffer. Scope is checked
again for each registration/assertion, including after an in-place seed update;
`GetNextAssertion` rejects a scope change during an outstanding sequence.
Monoid returns the public key as
a 65-byte uncompressed point `04 || X || Y` and signatures as 64-byte `r || s`; Security Key encodes COSE and DER
for CTAP. Resident credential records are needed for recovery; the seed alone cannot
recreate their random IDs or accounts. Non-resident credentials recover from the
seed and domain alone, because the RP returns their ID.

After user verification, returned account names include ` [0123456789ABCDEF]`,
using the first eight credential-ID bytes in uppercase hex. The fixed `F101`
index prefix is omitted. Names are truncated at a UTF-8 boundary to keep the full
label within 64 bytes; unnamed accounts return the label as `displayName`.
Stored names and user/credential IDs are unchanged. Platforms control which name
fields they display; the label is a lookup aid, not a validity indication.

Software user presence (UP) is enabled. User verification (UV) requires a valid
FIDO PIN-token proof. Account names are omitted when UV is absent. `signCount` is
always zero, permitting copied/restored records without a false monotonic-counter
promise. Packed self attestation uses a zero AAGUID and no attestation certificate.
See [security boundaries](security.md) for the trust and backup model.

## Validation

Target-card tests cover the standard FIDO NFC AID, PIN operations, registration,
assertions, resident discovery, replacement and Reset, including four accounts
under one RP plus one under another. Three injected failures after committed
storage steps verify the documented intermediate states and successful retries.
This does not establish browser/WebAuthn interoperability, FIDO certification,
physical fault resistance, peak RAM requirements or maximum credential capacity.

Reference: [CTAP2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).

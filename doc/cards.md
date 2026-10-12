# Cards

Some information of the cards are not listed by venders, but all of those cards are of **JavaCard 3.0.5** with **ECC support**.

Monoid selects available algorithm APIs at initialization; it does not match card models or run compatibility self-tests on the card. Compatibility results belong in this document and should identify the tested firmware, Monoid revision and operations. The hardware information below does not establish support for every Monoid feature or request size.

## On-demand persistent request overflow — 2026-10-12

The current receiver keeps the first 512B of an assembled request in RAM and
allocates subsequent 256B chunks in persistent storage as data arrives. This
budget applies to the complete CBOR request, not only the Message. A complete
single short APDU still borrows the APDU buffer. There is no full-size payload
reservation or migration of the RAM prefix. Persistent chunk references survive
reset so selection can erase abandoned data. Completion, cancellation, errors
and deselection erase all owned chunks and release their references.

All 69 simulator tests and production/isolated CAP conversion and verification
passed. The same ACS ACR1552 T=1 card passed nine physical test groups and 14
signatures using isolated Monoid CAP SHA-256
`6a8ae584ea69c10702c7a293e5d939450541e9136ba57e006923105e7d2171fc`.
All 55 production source hashes matched the frozen build. Independent Node/OpenSSL
signatures matched exactly and verified for the following requests:

| Key source | Message | Complete CBOR request | Complete Sign time |
| --- | ---: | ---: | ---: |
| Seed | 4032 B | 4128 B | 3.755–3.761 s |
| Stored master | 4032 B | 4110 B | 3.604–3.606 s |
| Seed | 8096 B | 8192 B | 4.689–4.696 s |
| Stored master | 8114 B | 8192 B | 4.525–4.528 s |

Each row was tested with Message first and last in CBOR, using 255B APDU frames
and hardened path `m/44'/501'/0'/0'`. Times include transfer, derivation and
signing, excluding setup, authentication and memory queries. The 8192B request
uses 512B transient and 7680B persistent payload storage, excluding metadata,
array overhead and cryptographic workspace. Message capacity depends on key and
path metadata. This establishes signing capacity, not an 8KB payload guarantee
for other commands that still copy decoded values into RAM.

The card also passed a 600B Create/Get round trip, 4032B signing after that
response, replacement of an abandoned persistent request, invalid continuation,
physical reset/re-authentication and recovery after rejecting an 8193B request
with `6700`. Reset recovery rejected an orphan last frame before authentication.
Simulator tests additionally inspect full and partial persistent chunks to
confirm erasure after reset and selection; hardware APDU tests cannot inspect
the erased bytes directly.

SystemInformation reported 2416B transient RAM before signing and 2320B after
warming the shared context. Repeated maximum requests and all recovery paths
returned to 2320B. The first query after the 600B read returned 2304B, and the
next returned 2320B. These readings include the query's response allocation and
are not signing peaks. Persistent-memory readings saturated at 32767B, so they
do not establish absence of persistent-memory growth. GC remains asynchronous.

Both temporary packages were removed; registry snapshots were byte-identical,
temporary instances returned `6A82`, and original applets returned `9000`. The
reader was released. Evidence is in ignored
`.research/ed25519/persistent-request-card/card-1791787267622.json` and sibling
build/cleanup files. External APIs and APDU framing are unchanged. The following
sections describe earlier implementations.

## Response buffer release verification — 2026-10-12

The subsequent writer fix allocates response storage on demand, retains it only
while response fragments are pending, and erases/releases it after completion,
cancellation, deselection or a send failure. Release requests object deletion;
GC is still asynchronous. The writer object itself remains shared.

All 65 simulator tests and production/isolated CAP conversion and verification
passed. The same card passed six physical test groups using isolated Monoid CAP
`8e1ad8a5d74a23f916ef2ecbe458b28a542473de6355ec1ae1ffaf580fe078a9`.
Seed-derived 1184B and stored-master 1458B messages signed correctly both before
and after reading a 600B value in three response frames. After that read, their
complete Sign APDU times were 3.000s and 2.873s. All seven signatures matched
independent Node/OpenSSL results. Cancelling an unfinished response via Hello,
or deselecting and re-authenticating, also permitted a subsequent 1184B signature.

The baseline SystemInformation transient-memory reading was 2256B. The first
query after the large read returned 2240B, the next returned 2256B, and readings
after subsequent signatures remained 2256B. These include the query's own
response allocation and are not signing peaks. The previous lasting reduction
to 1904B was eliminated. Exact upper limits after this fix were not remeasured;
the capacity table below describes the preceding implementation.

Both temporary packages were removed, registry snapshots were byte-identical,
the removed instances returned `6A82`, and both original applets returned `9000`.
Evidence is under ignored `.research/ed25519/writer-release-card/`, including
`card-1791786261051.json`. The reader was released. External APIs are unchanged.

## RAM-only signing capacity before the writer fix — 2026-10-12

Measured commit `8abf0c5` on the same ACS ACR1552 T=1 card below, using the
unchanged isolated CAP with SHA-256
`6589bff3e712b1a3e4b7e222f175df083d7a510e179e02dd7982ac38788c1a3d`.
All 55 production source hashes matched the CAP's frozen sources. Requests used
255-byte APDU frames, a 64-byte seed or stored master, and hardened path
`m/44'/501'/0'/0'`. Each scenario warmed the shared signing context first.

| Response writer state | Key source | Maximum Message | First failure | Complete request at maximum | Repeated maximum APDU time |
| --- | --- | ---: | ---: | ---: | ---: |
| Normal, before large responses | Seed | 1184 B | 1185 B | 1280 B (5 chunks) | 3.005–3.020 s |
| Normal, before large responses | Stored master | 1458 B | 1459 B | 1536 B (6 chunks) | 2.904–2.917 s |
| After reading a 600-byte value | Seed | 928 B | 929 B | 1024 B (4 chunks) | 3.038–3.054 s |
| After reading a 600-byte value | Stored master | 946 B | 947 B | 1024 B (4 chunks) | 2.861–2.869 s |

These are repeatable boundaries for this card, request metadata and retained
buffer state, not universal API limits. At each boundary, adding one Message
byte requires another 256-byte request chunk. Seed requests have 96 bytes of
CBOR overhead and also perform seed-to-master conversion; stored-master requests
have 78 bytes of overhead and skip that conversion. Other paths or metadata can
change the usable Message length. The 8192-byte ceiling applies to the complete
request and does not describe available RAM.

Each maximum and maximum-plus-one was repeated, including with Message first
and last in CBOR. All 71 successful signatures matched and verified against
independent Node/OpenSSL signatures. All 38 failed probes returned CBOR
`INTERNAL` with ISO status `9000`; each was followed by a successful 150-byte
recovery signature without reset or re-authentication. The uninstrumented CAP
does not expose the underlying exception reason, so these results do not alone
identify the precise failing allocation. Timings above cover complete Sign
transport, derivation and signing, excluding setup and memory queries.

After successful signing, idle transient RAM was 2256 B normally and 1904 B
after the large response. The response writer retains its expanded capacity,
so a previously successful 1167-byte Message failed for both key sources in
the latter state. Erasing response contents does not release that capacity.
These are idle readings, not peak measurements or a worst-case bound for every
possible earlier response.

The temporary Safe and Monoid packages were uninstalled. Before/after registries
were byte-identical; removed applets returned `6A82` and both original applets
returned `9000`. The reader was released. Full evidence is retained in ignored
`.research/ed25519/chunk-limit-card/card-1791785144739.json` and sibling logs.
No production implementation or API changes were made during this measurement.

## Chunked request and signing verification — 2026-10-12

The subsequent implementation retains requests in 256-byte transient chunks and
reads the Message twice through `ByteSource`. It no longer grows a contiguous
request array. The API and short-APDU framing are unchanged. The same ACS card
passed 14 physical test groups using isolated Safe/Monoid packages. Tested
Monoid CAP SHA-256:
`6589bff3e712b1a3e4b7e222f175df083d7a510e179e02dd7982ac38788c1a3d`.

| Complete authenticated Sign request | Result | APDU time |
| --- | --- | ---: |
| Seed → SLIP-0010 → 150-byte Solana transfer Message | Passed, three repetitions | 2.750–2.775 s |
| Stored master → same path and Message | Passed | 2.617 s |
| Seed → 512-byte Message, Message first/last | Passed | 2.913–2.923 s |
| Stored master → 512-byte Message, Message first/last | Passed | 2.731–2.742 s |
| Seed → 1167-byte Message, Message first/last | Passed | 2.980–2.993 s |
| Stored master → 1167-byte Message, Message first/last | Passed | 2.829–2.830 s |
| Seed → BIP32 → secp256k1 digest, alternating with Solana | Passed | 1.196–1.222 s |

Long signatures used 255-byte APDU fragments, with exact signature equality and
verification against independent Node/OpenSSL results. Timings include request
transport, derivation and signing, excluding setup/authentication and memory
queries. They are not primitive-only timings. Compared with the contiguous
baseline below, 150-byte signing took approximately 0.1 seconds longer; 512-byte
signing remained close to the previous result.

The previously failing 600-byte Create now passes, followed by a three-part Get.
A new 1167-byte signing request also succeeds after abandoning 1020 bytes of an
older request. Request/response cancellation, GET RESPONSE protection, and reset
followed by authentication and signing all pass.

Fresh idle transient RAM is 2352 B, 64 B lower than the contiguous baseline due
to the fixed 32-entry chunk reference array. After signing it is 2256 B; after a
large response and subsequent signing it is 1904 B. The response writer still
retains its expanded capacity. These are idle readings, not a complete peak
profile. A 1263-byte request now retains five 256-byte data arrays instead of
the baseline's final-frame 1024+1280-byte arrays; this payload accounting excludes
reference/array overhead and cryptographic workspace. All Message bytes still
remain in RAM until signing ends. The 8192-byte protocol ceiling does not imply
that a physical card can sign an 8192-byte request.

All 60 simulator tests and Java Card 3.0.5 CAP conversion/verification passed.
Both temporary packages were fully uninstalled; before/after registries were
byte-identical, temporary instances returned `6A82`, and original applets returned
`9000`. Source snapshots, hashes and the APDU report are retained in ignored
`.research/ed25519/chunk-integration-card/`.

## Contiguous-buffer baseline integration — 2026-10-12

Tested the working tree based on `42eda62`, including transient request assembly
and Message slices, on the ACS ACR1552 reader using T=1, ATR
`3b8a800150564a434f503453494471`, IC type `D321`, batch `4839`.
The isolated Monoid and Safe packages changed only Java package/import names and
cross-applet AIDs. The tested Monoid CAP SHA-256 is
`197f2b74761e35b7c842ffe33fd35fde5bb18f950a174b225fb4ffa4f8734ec6`.
Source hashes and a frozen source copy are retained with the test evidence.

| Complete authenticated Sign request | Result | APDU time |
| --- | --- | ---: |
| Seed → SLIP-0010 → 150-byte Solana transfer Message | Passed, three repetitions | 2.634–2.660 s |
| Stored master → same path and Message | Passed | 2.507 s |
| Seed → SLIP-0010 → 512-byte Message, Message first/last in CBOR | Passed, three request frames | 2.905–2.915 s |
| Seed → BIP32 → secp256k1 digest, alternating with Solana | Passed, two repetitions | 1.179–1.183 s |
| 1167-byte Message, 255-byte request fragments | Failed: transient RAM exhausted | — |

These times include request transport, derivation and signing, but exclude
authentication, fixture creation, later memory queries and host verification.
They are not primitive-only signing times. Ed25519 signatures and seed/master
public keys and chain codes matched independent Node/OpenSSL results for
`m/44'/501'/0'/0'`; BTC signatures were independently verified against the
host-derived `m/44'/0'/0'/0/0` public key.

An isolated diagnostic build confirmed `SystemException.NO_TRANSIENT_SPACE`
(reason 2). The 1167-byte Message produces a 1263-byte CBOR request. Its final
255-byte frame grows the buffer from 1024 to 1280 bytes; both arrays remain
allocated during that APDU. Only 16 bytes of transient RAM remained after
reception, and zero remained at the exception, before entering the EdDSA branch.
Using 192-byte fragments moved the expansion to an intermediate APDU and the
same message signed correctly. This is a diagnostic control, not a general
workaround or a guarantee of supported size. A 600-byte Create request also
failed with reason 2 at 255-byte fragmentation and succeeded at 192 bytes.

Uninstrumented tests also passed request replacement, GET RESPONSE protection,
three-part reads of a stored 600-byte value, response cancellation followed by
signing, and reset/re-authentication followed by signing. Idle transient RAM
was 2320 bytes after short signing and 1968 bytes after the large response and
subsequent signing; the response writer retains its expanded capacity. These
are idle readings, not a complete peak-memory profile. The two reported
transient memory types overlap and must not be added together.

That tested implementation has working integrated signing and
transport, but long-request acceptance depends on fragment boundaries and
retained buffers. The 8192-byte protocol ceiling is not a physical-card capacity
claim. No transport or memory-policy fix was made during this test.

Both isolated packages (`F06D6F6E6F69647D` and `F06D6F6E6F69647E`) were removed.
Before/after registries matched, both removed applets returned `6A82`, and both
original Monoid applets remained selectable. CAPs, source snapshots, diagnostics
and APDU transcripts are under ignored `.research/ed25519/current-integration-card/`.

## Ed25519 byte-array refactor verification — 2026-10-12

Tested on the ACS ACR1552 1S CL Reader PICC 0 using T=1, with card ATR
`3b8a800150564a434f503453494471`, CPLC IC type `D321` and batch `4839`.
Both builds used the same isolated diagnostic applet, public test inputs and card.
The baseline was the working tree immediately before removing `ECCurve`, `ECPoint`,
`BigNat` and `BigNatInternal`, based on commit `af4f994`. The refactored production
CAP SHA-256 is `5a636229c587676220ef035c4979c0d63dbf2a149eb239607428557b6c7d20e1`.
Measurements below include PC/SC and APDU overhead.
They precede the subsequent move of `MathResources` into `LibMath`; that
organization and per-arithmetic-call cleanup change has not been remeasured on card.

| Measurement | Before refactor | After refactor |
| --- | ---: | ---: |
| Construct shared curve and reusable signer | 1,808 ms | 342 ms |
| SLIP-0010 four-level derivation and Ed25519 key import | 939 ms | 673 ms |
| Sign the 150-byte Solana message with the imported key | 2,088 ms | 1,417 ms |
| Free deselect RAM after constructing the curve and signer | 1,616 B | 3,088 B |
| Free deselect RAM with an imported key | 1,520 B | 2,992 B |

The derivation starts from a 64-byte master and uses `m/44'/501'/0'/0'`.
The host computes seed-to-master and independently checks the derived public key
and signature with Node/OpenSSL. The context and HMAC/deriver are initialized
before the timed derivation and signing calls. These are crypto-component tests;
the Monoid `0x41` EdDSA branch had not yet been connected to Keystore in this measured build.
RAM figures are idle readings, not signing peaks; reset and deselect readings
describe overlapping memory pools and must not be added together.

All ten physical test groups passed: shared construction, four short RFC8032
vectors with repeated signing, explicit clear, deselect, physical reset followed
by reimport, ten key changes, and SLIP-0010 followed by the Solana signature.
The context construction count remained one across clear, deselect and reset.
Ten additional 32/64-byte reduction cases matched independent integer arithmetic.
The simulator passed 39 tests, including the longer RFC vector, base-point
multiplication boundaries, failure cleanup, and roughly 108,000 reduction checks.
Production CAP conversion and verification completed without errors or warnings.

The refactor retains native XY ECDH with a 255-bit EC private key and a shared
512-bit RSA `NOPAD` engine with 64-byte padded operands. Generic point operations,
X-only recovery and unused arithmetic resources have been removed. All number
values are byte arrays. In this measured build, `LibMath` provided the arithmetic
and `MathResources` owned its shared RSA resources and scratch. Explicit transient array payload for
one curve, expanded key and signer fell from 1,563 B to 482 B; this static count
excludes object headers, native engine storage, messages and derivation buffers.

Probe packages `F06D6F6E6F69647A` and `F06D6F6E6F69647B` were removed after testing.
Before/after registries matched; selecting the removed probe returned `6A82`, and
both original Monoid applets remained selectable. Source manifests, CAPs, APDU
transcripts and baseline comparisons are retained locally under the ignored
`.research/ed25519/byte-array-refactor-card/` directory.

## TianAnXin - SCP03 Card

https://item.taobao.com/item.htm?id=797321051069

### Known information

- NXP SmartMX3 chip
- GP2.3
- SCP03
- Usable memories (tested by actually allocating):
  - EEPROM: ~70K
  - RAM: ~3.8K

> This is probably a J3R180 card as I bought one with the same IC batch as the J3R180 card.

### Capabilities

```
Supports SCP03 i=00 i=10 i=20 i=60 i=70 with AES-128 AES-196 AES-256
Supported DOM privileges: SecurityDomain, DAPVerification, DelegatedManagement, CardReset, MandatedDAPVerification, TrustedPath, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration, CipheredLoadFileDataBlock
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: SHA-256
Supported Token Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Supported Receipt Generation ciphers: DES_MAC, CMAC_AES128
Supported DAP Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Version:   1 (0x01) ID:   1 (0x01) type: AES          length:  16 (AES-128)
Version:   1 (0x01) ID:   2 (0x02) type: AES          length:  16 (AES-128)
Version:   1 (0x01) ID:   3 (0x03) type: AES          length:  16 (AES-128)
```

## TianAnXin - J3R180 Card

https://item.taobao.com/item.htm?id=944020539101

### Known information

- J3R180
- GP2.3
- SCP02
- Usable memories (tested by actually allocating):
  - EEPROM: ~73K
  - RAM: ~3.8K

### Capabilities

```
Supports SCP02 i=15 i=35 i=55 i=75
Supported DOM privileges: SecurityDomain, DAPVerification, DelegatedManagement, CardReset, MandatedDAPVerification, TrustedPath, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration, CipheredLoadFileDataBlock
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: SHA-256
Supported Token Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Supported Receipt Generation ciphers: DES_MAC, CMAC_AES128
Supported DAP Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Version:   1 (0x01) ID:   1 (0x01) type: DES3         length:  16
Version:   1 (0x01) ID:   2 (0x02) type: DES3         length:  16
Version:   1 (0x01) ID:   3 (0x03) type: DES3         length:  16
```

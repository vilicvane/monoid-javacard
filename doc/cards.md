# Cards

Some information of the cards are not listed by venders, but all of those cards are of **JavaCard 3.0.5** with **ECC support**.

Monoid selects available algorithm APIs at initialization; it does not match card models or run compatibility self-tests on the card. Compatibility results belong in this document and should identify the tested firmware, Monoid revision and operations. The hardware information below does not establish support for every Monoid feature, including the current Ed25519 integration.

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
the existing Monoid `0x41` EdDSA branch still awaits Keystore integration.
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

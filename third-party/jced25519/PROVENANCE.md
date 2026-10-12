# Ed25519 dependencies

The Ed25519 implementation in `src/main/java/monoid` adapts
[JCEd25519](https://github.com/dufkan/JCEd25519) at commit
`401e447bdc41c68c397e81f3a4fca4e977e2f61c`, including its bundled JCMathLib 2.1-rc.1.

- `CurveED25519` and `CurveWEI25519` adapt JCEd25519's Wei25519 conversion.
- `LibMath` retains the needed right-shift, estimated-quotient long division and
  RSA-based modular arithmetic from the bundled JCMathLib, expressed as operations
  on unsigned big-endian byte arrays.

Monoid uses native XY ECDH directly for multiplication of the fixed Wei25519 base
point. The generic `ECCurve`, `ECPoint`, `BigNat`, `BigNatInternal`, allocator and
status-code classes have been removed. `ED25519Key` holds the expanded key, while
`LibED25519` implements deterministic signing over a complete message. Both message
hashes finish in one synchronous call before the signature is written to the output.
Shared EC and RSA engines survive operation cleanup; their transient work arrays
and operation secrets are cleared separately. `LibMath` privately owns its shared
RSA engine, key and byte-array scratch, initialized and disposed by the Applet.
Each arithmetic method clears its own scratch on success and failure, preserving
the outer operation's intermediate values during nested calls. No arithmetic
method allocates a new object during an operation.

The upstream card profiles and `MathSupport` switches have been removed. XY ECDH
is required, as it already is for Monoid's secp256k1 implementation. The unused
X-only recovery, point addition and ECDSA-assisted recovery paths are absent.
RSA arithmetic uses private-key `ALG_RSA_NOPAD` with fixed 64-byte buffers; native
EC keys use the exact 255-bit field size, without random keypair generation.
These are implementation requirements, not a card compatibility list or on-card
validation procedure. Card compatibility belongs in [the card documentation](../../doc/cards.md).

Host `test` and `run` use generated sources from `gradle/simulator.gradle` to adapt
jCardSim 3.0.6's EC key allocation and RSA key reuse, input length and output padding.
Those adaptations are excluded from CAP compilation. Point multiplication by zero,
one, two and the order minus one is covered independently of signing vectors.

The inherited arithmetic is not constant time and has not been hardened against
side-channel or fault attacks.

The required copyright and permission notices are retained here:

- [JCEd25519 MIT license](LICENSE): Copyright (c) 2022 Antonin Dufka.
- [JCMathLib MIT license](JCMathLib-LICENSE): Copyright (c) 2017 Vasilios Mavroudis
  and Petr Svenda.

Include these notices with distributions containing this implementation.

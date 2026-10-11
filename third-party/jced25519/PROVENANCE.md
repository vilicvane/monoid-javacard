# Ed25519 dependencies

The Ed25519 implementation in `src/main/java/monoid` adapts
[JCEd25519](https://github.com/dufkan/JCEd25519) at commit
`401e447bdc41c68c397e81f3a4fca4e977e2f61c`, including its bundled JCMathLib 2.1-rc.1.

- `ED25519Signer` and `CurveWEI25519` adapt JCEd25519's Wei25519 conversion.
- `BigNat`, `BigNatInternal`, `ECCurve`, `ECPoint`, `MathAllocator`,
  `MathResources`, `MathStatus`, and `MathSupport` adapt the bundled JCMathLib.

Monoid separates the upstream classes, follows the project's naming and formatting,
uses transient EC private keys, and makes workspace constants instance-owned so
the complete context can be collected. The signing layer implements deterministic
nonces and checks that both streamed message passes match before releasing a signature.
The inherited arithmetic is not constant time and has not been hardened against
side-channel or fault attacks.

The required copyright and permission notices are retained here:

- [JCEd25519 MIT license](LICENSE): Copyright (c) 2022 Antonin Dufka.
- [JCMathLib MIT license](JCMathLib-LICENSE): Copyright (c) 2017 Vasilios Mavroudis
  and Petr Svenda.

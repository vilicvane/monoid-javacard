# Monoid Architecture

```mermaid
sequenceDiagram
    participant MonoidApp
    participant MonoidApplet
    participant MonoidSafeApplet
    participant ThirdPartyApplet

    MonoidApp ->> MonoidApplet: provide safe PIN
    MonoidApplet ->> MonoidSafeApplet: verify safe PIN
    MonoidApplet -->> MonoidApplet: save safe PIN

    MonoidApp ->> MonoidApplet: set access PIN

    note over MonoidApp, MonoidSafeApplet: Key Management

    MonoidApp ->> MonoidApplet: list keys
    MonoidApplet -->> MonoidApp: public keys
    MonoidApp ->> MonoidApplet: key management (import, generate, delete)
    MonoidApp ->> MonoidApplet: grant key access to third party (by type or full index)
    MonoidApplet ->> MonoidSafeApplet: grant key access to third party

    note over MonoidApp, MonoidSafeApplet: App Signing

    MonoidApp ->> MonoidApplet: sign (full index)
    MonoidApplet ->> MonoidSafeApplet: sign (full index)
    MonoidSafeApplet -->> MonoidApplet: signature
    MonoidApplet -->> MonoidApp: signature

    note over MonoidApplet, ThirdPartyApplet: Third-Party Signing

    ThirdPartyApplet ->> MonoidApplet: list (by type)
    MonoidApplet -->> ThirdPartyApplet: full indexes
    ThirdPartyApplet ->> MonoidApplet: sign (full index)
    MonoidApplet -->> MonoidApplet: verify access
    MonoidApplet ->> MonoidSafeApplet: sign (full index)
    MonoidSafeApplet -->> MonoidApplet: signature
    MonoidApplet -->> ThirdPartyApplet: signature
```

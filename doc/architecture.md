# Monoid Architecture

```mermaid
sequenceDiagram
    participant MonoidApp
    participant MonoidApplet
    participant MonoidSafeApplet
    participant ThirdPartyApplet

    MonoidApp ->> MonoidApplet: safe PIN
    MonoidApplet ->> MonoidSafeApplet: verify safe PIN
    MonoidApplet -->> MonoidApplet: store safe PIN (safe unlocked)

    MonoidApp ->> MonoidApplet: set access PIN

    note over MonoidApp, MonoidSafeApplet: Safe Management

    MonoidApp ->> MonoidApplet: list safe items
    MonoidApplet -->> MonoidApp: safe items (indexes)
    MonoidApp <<->> MonoidApplet: safe management (get, set, remove)
    MonoidApplet <<->> MonoidSafeApplet: safe management
    MonoidApp ->> MonoidApplet: grant safe item access (sign/verify/direct) to third parties
    MonoidApplet ->> MonoidSafeApplet: store third-party permissions

    note over MonoidApp, MonoidSafeApplet: App Signing

    MonoidApp ->> MonoidApplet: sign
    MonoidApplet ->> MonoidSafeApplet: retrieve safe item (private key)
    MonoidSafeApplet -->> MonoidApplet: private key
    MonoidApplet -->> MonoidApp: signature

    note over MonoidApplet, ThirdPartyApplet: Third-Party Signing

    ThirdPartyApplet ->> MonoidApplet: list access-granted safe items
    MonoidApplet -->> ThirdPartyApplet: safe items (indexes and permissions)
    ThirdPartyApplet ->> MonoidApplet: sign
    MonoidApplet ->> MonoidSafeApplet: retrieve safe item (private key)
    MonoidSafeApplet -->> MonoidApplet: private key
    MonoidApplet -->> ThirdPartyApplet: signature
```

## Some thoughts

### Third-party applet to _Monoid Applet_ authentication nodes

> Under the assumption that third-party applets hold the credentials to access the safe via _Monoid Applet_, so upgrade or reinstallation of _Monoid Applet_ will not reset applets' access to the safe.

~~Consider situation that a malicious user don't have the PIN but want to access the safe, the user could potentially replace the _Monoid Applet_ to intercept interactions from third-party applets.~~

This is not an issue, because all access to the safe is possible only when _Monoid Applet_ has the safe PIN. Replacing _Monoid Applet_ will vanish the safe PIN stored.

# Monoid OTP

An independent TOTP applet using Monoid's HMAC service. It verifies Authority-signed
time when Identity has an Authority configured, and otherwise accepts APP-provided
time. It implements RFC 6238 with SHA-1, SHA-256 or SHA-512, six or eight
digits, and three consecutive windows. It does not implement HOTP or YKOATH.

## Installation and authorization

Install Identity, then the matching Monoid Library and Monoid CAPs. To require
signed time, provide the Authority's service URL and 65-byte P-256 public key
together at [Identity installation](identity.md). Monoid Hello returns the URL as
`authority`, or false for APP-provided time.

```sh
gp --install build/javacard/monoidotp.cap
```

<!-- @inplate
The OTP package AID is `{{hex MONOID_OTP_PACKAGE_AID uppercase=true}}`; its applet AID
is `{{hex MONOID_OTP_AID uppercase=true}}`.
-->

The OTP package AID is `F06D6F6E6F696405`; its applet AID
is `F06D6F6E6F69640501`.

<!-- @end -->

Authenticate to Monoid with Access PIN and use `0x51 Set applet grant`:

```ts
{
  aid: otpAID,
  types: [[-3583, false]], // 0xF201: read account metadata and use its HMAC secret
}
```

The grant binds the OTP installation token. Reinstalling OTP requires granting its
new token again; existing account records remain in Monoid. No seed grant or OTP
PIN is needed. The FIDO PIN and Security Key authorization are independent.
Adding or removing accounts does not require replacing this grant.

## Account records

Create one item per website shared secret through Monoid `0x34 Create`:

```ts
{
  type: -3583, // 0xF201
  alias: 'Issuer: account',
  metadata: byte[5],
  data: byte[], // Base32-decoded website shared secret; 1..255 bytes
  secret: true, // Enforced for this type, even if omitted or false
}
// Response: {index: accountIndex}
```

```text
metadata = 01 || algorithm_u8 || digits_u8 || period_u16_BE
algorithm: 1 = SHA-1, 2 = SHA-256, 3 = SHA-512
digits:    6 or 8
period:    1..32767 seconds; normally 30
```

Safe's fixed custom-type mapping maps `0xF201` to HMAC, supporting all three
algorithms above. The 10-byte index is `F2 01 || SHA-256(secret)[0:8]`, using
the same digest-index path as built-in HMAC keys. Its low type byte is fixed,
not a key length. An explicitly supplied index must match that digest. Creating
another account with the same secret returns `EXISTS`, even with a different
label or configuration.

The immutable five-byte `metadata` holds public configuration; `alias` holds the
label. The account's data is always secret: Get and all client data-reading SIOs
reject it. Set can change the alias, but replacement data must still match the
index and cannot clear the secret flag. To change the secret, create a new item.
To change configuration, remove and recreate the account with the same secret.

Account labels and configuration may be listed with Access PIN. Export returns
encrypted data only; use [Export/Import](item-transfer.md) to copy this single item
to another card. Bound Monoid instances use Access PIN for Bundle synchronization;
asymmetric transfer requires Secret PIN. The target's `0xF201` type grant covers
the imported account without a separate HMAC key grant.

## Commands

Requests and responses use [Monoid short-APDU framing](apdu.md), including fragmented
requests and `00 C0` GET RESPONSE. The command numbers below belong to the OTP
applet. Errors use ISO status words without a CBOR error body.

### `0x20` Hello

```ts
type Request = {};
type Response = {version: byte[]; batchSize: 3};
```

### `0x21` Challenge

```ts
type Request = {};
type Response = {challenge: byte[]}; // 32 random bytes
```

Replaces any pending batch and revokes this client's unconsumed user permission.

### `0x22` Prepare

```ts
type Request = (
  | {
      data: byte[]; // 41-byte Authority time proof; requires Challenge first
      signature: byte[]; // 64-byte r || s
    }
  | {
      time: byte[]; // 8-byte unsigned big-endian Unix seconds; no Authority only
    }
) & {
  indices: byte[][]; // 1..16 distinct 10-byte 0xF201 indices, in output order
};
type Response = {};
```

With Authority configured, verifies the proof against the pending challenge and
installed key. Without Authority, accepts `time` directly and does not require
Challenge. The two input forms cannot be mixed, and the card rejects a form that
does not match its installed configuration. A service error or invalid signature
never enables unsigned time on a configured card.

Fixes the accepted time and selected indices. Preparation consumes any previous
batch/challenge on the attempt, including failure, and revokes this client's old
user permission after parsing and before preparing a new batch. Malformed requests
discard the batch; any subsequent successful preparation revokes the old permission.
Recommended field order is
`data`, `signature`, `indices` or `time`, `indices`.

### `0x23` Calculate

```ts
type Request = {};
type Response = {
  time: byte[]; // 8-byte unsigned big-endian Unix seconds
  items: {
    index: byte[];
    period: number;
    codes: string[]; // Exactly three, with leading zeros
  }[];
};
```

Requires a prepared batch and a new Monoid user permission for this client. The
permission is consumed before calculation; the batch is removed on the attempt,
including failure. Each account yields counters `floor(time / period) + {0,1,2}`
with `T0 = 0`. Configuration and the account's secret are used when calculating;
this is not a snapshot of item revisions. Failed calculations leave no partial response to
retrieve. A successful fragmented response can be read to completion without
another authentication.

## Host flow

List accounts first through Monoid `0x30 List` with `type: -3583` (`0xF201`),
under Access authentication. This returns indices, aliases and public
configuration without computing any codes. Pass only the user-selected indices
to Prepare; one account is a normal request, not a special case. The 16-account
limit is a batch ceiling, not a requirement to calculate the full account list.

```mermaid
sequenceDiagram
    participant App
    participant OTP
    participant Authority
    participant Monoid
    participant Identity
    App->>Monoid: Authenticate {pin}; List {type: -3583}
    Monoid-->>App: account indices, aliases, configuration
    Note over App: Select accounts to calculate
    App->>Monoid: Hello
    Monoid-->>App: authority: URL or false
    alt Authority configured
        App->>OTP: Challenge
        OTP-->>App: challenge
        App->>Authority: POST /v1/time {challenge}
        Authority-->>App: data, signature
        App->>OTP: Prepare {data, signature, indices}
        OTP->>Identity: verifyAuthorityTime(data, signature, challenge)
    else No Authority
        App->>OTP: Prepare {time: APP Unix seconds, indices}
    end
    OTP-->>App: success
    App->>Monoid: Authenticate {pin, aid: otpAID}
    Monoid-->>App: success
    App->>OTP: Calculate
    OTP->>Monoid: consumeUserAuthentication()
    loop Each selected account
        OTP->>Monoid: get(accountIndex), read configuration metadata
        loop Three time windows
            OTP->>Monoid: hmac(algorithm, accountIndex, counter)
            Monoid-->>OTP: MAC
        end
    end
    OTP-->>App: time, items with three codes each
```

SELECT each named applet before its APDUs, keeping the card powered throughout.
The APP sends the PIN only to Monoid. Secret PIN also satisfies Access
authentication. A new challenge or preparation must occur before that
authentication; otherwise it revokes the permission just issued.

The APP decodes `time` without losing unsigned 64-bit precision and displays each
code only in its own window. Preparing future codes does not extend their validity
at the website. Keep pending codes only as long as needed by the user.

## Lifetime and boundaries

The single temporary Monoid permission belongs to a current grant, survives
SELECT, and is shared across that client's SIO sessions. A new Authenticate
replaces it (omitting `aid` clears it). PIN updates, grant replacement/revocation,
Monoid Reset and card reset invalidate it. `consumeUserAuthentication()` succeeds
once; `revokeUserAuthentication()` is idempotent and affects only its own grant.
Ordinary Monoid APDU authentication still clears on deselection.

OTP's pending state survives SELECT but clears on card reset. It fixes
time and indices before user authorization; a later Challenge or Prepare cannot
reuse that authorization. An unused permission has no clock-based expiry, so a
delayed Calculate can still return the prepared old windows. The Authority proof
does not prove elapsed time or prompt delivery. There is no persistent time
high-water mark or per-power quota: each new user authorization permits a new
three-window batch. Without Authority, the APP's time is not authenticated and the
host can select past or future windows. The same one-operation permission and
three-window batch limit apply in both modes.

HMAC is a general service. Built-in `0x05LL` keys require exact `keys` entries.
Mapped items require read access to their exact custom type; for `0xF201`, this
also authorizes HMAC use, with no separate flag. A built-in HMAC key grant never
covers an OTP account, even if both items contain the same secret and have the
same digest suffix. Mapped indices are rejected in `keys` grants. Unmapped custom
types cannot be used for HMAC.

HMAC does not consume user permissions itself or enforce TOTP configuration or
window policy. Granting another client read access to `0xF201` would let that
client compute arbitrary HMAC messages with every OTP account, without exposing
the secrets. Grant that type only to trusted OTP code, which enforces the account's
algorithm, digits, period, one-operation permission and three-window batch. This
boundary assumes trusted installed applet code, as with Security Key.

Common errors: `6982` for missing permission, an unavailable required Authority or invalid proof,
`6985` for an absent challenge, batch or Identity applet,
`6A80` for malformed inputs or account configuration (version, algorithm, digits or period), and
`6A83` for a missing account. Malformed transport headers follow the shared APDU
protocol. Reconnect failures may report `6982` instead of `6985`.

<h1 align="center">
  <p>Monoid JavaCard</p>
  <sup>
    <!-- @inplate-line <code>0x{{hex MONOID_NAMESPACE uppercase=true}}</code> -->
    <code>0xF06D6F6E6F6964</code>
  </sup>
</h1>

<img src="./res/monoid.svg" alt="Monoid" width="80" align="right" />

A JavaCard with Monoid applets installed is:

- [x] A hardware crypto wallet.
- [x] A FIDO2 authenticator.
- [x] A One-Time Password (OTP) generator.
- [ ] A Tesla key.

The goal is to allow third-party Monoid applets to interact with _Monoid Applet_ `Shareable` interface for signing/verifying and data access, so that Monoid can manage those keys and data and make it easy for users to backup, restore or even synchronize securely with unified UX.

## Requirements

JavaCard 3.0.5 with ECC support is required.

See [cards](doc/cards.md) for links to vendors.

## Build & Install

For vscode-based editor, please install the recommended Java extensions pack curated by Microsoft and create symlink `/jdks/jdk-11` to your JDK 11 installation, e.g.:

```sh
ln -s /path/to/jdk-11 /jdks/jdk-11
```

For other editors or terminals, please ensure related configurations accordingly.

Now we can build the project with Gradle:

```sh
./gradlew buildJavaCard
```

Then install applets to a card with [gp] command:

```sh
gp --install build/javacard/monoididentity.cap
gp --load build/javacard/monoidlib.cap
gp --install build/javacard/monoid.cap
```

Keep Monoid Identity and the matching library installed when replacing Monoid. See [architecture](doc/architecture.md).

For FIDO2, install and authorize [Security Key](doc/security-key.md).
For TOTP, install and authorize [OTP](doc/otp.md).

Build and install with PowerShell:

```powershell
.\scripts\build-install.ps1                       # Install (default)
.\scripts\build-install.ps1 -Mode ReinstallMonoid # Clears Safe data and Access PIN; preserves Identity and Secret PIN
.\scripts\uninstall.ps1                          # Removes all Monoid packages, including their data
```

> The gradle plugin task `./gradlew installJavaCard` will try to append multiple `--install` options to `gp` command, which is not supported in my case. So we have to do it manually.

## Development

The development workflow requires Node.js for source code housekeeping and some test case validation.

```sh
npm install
```

Run tests with simulator:

```sh
./gradlew test --info --rerun-tasks
```

Run tests on physical cards:

```sh
# requires a clean installation:
# gp --uninstall build/javacard/monoid.cap

# First installation only; preserve Identity and the matching library across Monoid updates:
# gp --install build/javacard/monoididentity.cap
# gp --load build/javacard/monoidlib.cap
gp --install build/javacard/monoid.cap
```

```sh
CARD_TYPE=physical ./gradlew test --info --rerun-tasks
```

Commands to run:

```sh
# sync some constants like AIDs (and more) across files.
npx inplate --update

# format code with prettier. YES!!!
npx prettier --write .
```

## Architecture

The _Monoid Applet_ owns Safe items, Access PIN, key derivation and signing.
The separate _Monoid Identity Applet_ retains the card's identity and Secret PIN across Monoid reinstallation.

See [architecture](doc/architecture.md) and [security boundaries](doc/security.md).

## Roadmap

### Core features

- [x] _Monoid Applet_ basic commands
- [x] _Monoid Applet_ third-party management commands
- [x] _Monoid Applet_ `Shareable` interface
- [ ] Monoid mobile app
  - [ ] Key management
  - [ ] Crypto transaction signing
  - [ ] Third-party applet management

### Additional mobile app features

- [ ] Keys and data sync
- [ ] Applet gallery

### Applets for typical use cases

- [x] FIDO2
- [ ] One-time password (OTP)
- [ ] Tesla key

### Cryptography

- `"secp256k1"`
  - [x] `"ecdsa"`
  - [x] `"bip340"`
- `"secp256r1"`
  - [x] `"ecdsa"`
- `"ed25519"`
  - [x] `"ed25519"`
- `"hmac"` (Shareable)
  - [x] SHA-1
  - [x] SHA-256
  - [x] SHA-512

See [Bitcoin signing](doc/bitcoin.md).

## ISO-7816 Commands

See [APDU transport](doc/apdu.md).

### Command authentication

The authentication is done within a session, using `0x21` command.

- Access PIN: for commands marked "Requires authentication".
- Secret PIN: for commands requiring Secret PIN, or any command available with access PIN.

### `0x20` ~ `0x2F` System management

See [Cryptography](#cryptography).

```ts
type Features = {
  curves: {
    name: string;
    ciphers: string[];
  }[];
};
```

#### `0x20` Hello

```ts
type Request = {};
```

```ts
type Response = {
  version: number;
  /** Persistent 4-byte Card ID; preserved by Reset and configurable at Identity installation. */
  id: byte[];
  /** Monoid Identity P-256 public key, 65-byte uncompressed SEC 1. */
  publicKey: byte[];
  /** Authority service URL, or false when not configured. */
  authority: string | false;
  /** SHA-256 of the Bundle key, or false when not enrolled. */
  bundle: byte[] | false;
  /** Tries remaining, or false when the PIN is not set. */
  pins: {
    access: number | false;
    secret: number | false;
  };
};
```

### `0x21` Authenticate

```ts
type Request = {
  pin: string;
  secret?: true;
  /** Optional client AID: one operation-start permission, consumed by that client. */
  aid?: byte[];
};
```

```ts
type Response = {};
```

#### `0x22` Set PIN

> Requires authentication with Secret PIN if it is set.

```ts
type Request = {
  pin: string;
  /** Sets the Secret PIN instead of the Access PIN. */
  secret?: true;
};
```

```ts
type Response = {};
```

#### `0x23` Create Bundle

[Bundle initialization and format](doc/bundle.md).

> Requires authentication with Secret PIN.

```ts
type Request = {
  /** Requires no existing Bundle; other recipients only, at least one, without duplicates. */
  publicKeys: byte[][];
};
```

```ts
type Response = {
  /** SHA-256 of the Bundle key. */
  bundle: byte[];
  /** One encrypted packet per publicKeys entry, in the same order. */
  data: byte[][];
};
```

#### `0x24` Join Bundle

> Requires authentication with Secret PIN.

[Authority issuance](doc/authority.md).

```ts
type Request = {
  /** The sending Identity's key, or the installed Authority key for Authority-issued data. */
  publicKey: byte[];
  data: byte[];
};
```

```ts
type Response = {
  /** The same key and allowPeerExtension policy succeed unchanged; differences conflict. */
  bundle: byte[];
};
```

#### `0x25` Extend Bundle

> Requires authentication with Secret PIN and `allowPeerExtension`. [Extension workflow](doc/bundle.md#extension).

```ts
type Request = {
  /** The new member's Identity public key. */
  publicKey: byte[];
};
```

```ts
type Response = {
  /** Authenticated extension request for another Bundle member to approve. */
  data: byte[];
};
```

#### `0x26` Approve Bundle Extension

> Requires authentication with Secret PIN and `allowPeerExtension`.

```ts
type Request = {
  /** Data returned by Extend Bundle on another member. */
  data: byte[];
};
```

```ts
/** Forward unchanged to Join Bundle on the new member. */
type Response = {
  /** The approving Identity's public key. */
  publicKey: byte[];
  data: byte[];
};
```

#### `0x2F` System information

```ts
type Request = {};
```

```ts
type Response = {
  versions: {
    monoid: number;
    javacard: [number, number];
  };
  memories: {
    persistent: {
      available: number;
    };
    transient: {
      reset: {
        available: number;
      };
      deselect: {
        available: number;
      };
    };
  };
  features: Features;
};
```

### `0x30` ~ `0x3F` Safe management

```ts
type SafeItemKeyType = 'entropy' | 'seed' | 'secp256k1' | 'secp256r1' | 'ed25519' | 'hmac';
/** Numeric types use signed 16-bit CBOR integers. */
type SafeItemType = SafeItemKeyType | number;
```

#### `0x30` List items

> Requires authentication.

```ts
type Request = {
  type?: SafeItemType;
  /** Matches item metadata only; omitted or empty means no metadata filter. */
  metadataPrefix?: byte[];
};
```

```ts
type Response = {
  items: {
    index: byte[];
    type: SafeItemType;
    metadata?: byte[];
    alias?: string;
    secret: boolean;
  }[];
};
```

#### `0x31` View

> Requires authentication.

```ts
type Request = {
  index: byte[];
};
```

```ts
type Response = {
  metadata?: byte[];
  alias?: string;
  secret: boolean;
};
```

#### `0x32` Get item

> Requires authentication. Rejects secret items.

```ts
type Request = {
  index: byte[];
};
```

```ts
type Response = {
  data: byte[];
};
```

#### `0x33` Set item

> Requires authentication.

```ts
/** Updates an existing item; omitted fields remain unchanged. */
type Request = {
  index: byte[];
  alias?: string;
  data?: byte[];
  /** Preserved when omitted; changing true to false requires replacement data. */
  secret?: boolean;
};
```

```ts
type Response = {};
```

#### `0x34` Create item

> Requires authentication.

```ts
/** Returns EXISTS if the index is occupied, even by an identical item. */
type Request = (
  | {
      type: SafeItemType;
    }
  | {
      index: byte[];
    }
) & {
  /** Set at creation; searchable and readable with access PIN. */
  metadata?: byte[];
  alias?: string;
  data: byte[];
  /** Disables plaintext Get; defaults to false. */
  secret?: boolean;
};
```

```ts
type Response = {
  index: byte[];
};
```

#### `0x35` Remove item

> Requires authentication.

```ts
type Request = {
  index: byte[];
};
```

```ts
type Response = {
  /** False when the index was already absent. */
  removed: boolean;
};
```

#### `0x36` Export item

[Encrypted payload format](doc/item-transfer.md).

> Requires authentication with Secret PIN.

```ts
type Request = {
  index: byte[];
  /** Required without a Bundle (65-byte SEC 1); ignored when enrolled. */
  recipientPublicKey?: byte[];
};
```

```ts
type Response = {
  metadata?: byte[];
  alias?: string;
  /** Encrypts item data and secret; authenticates index, metadata and alias. */
  data: byte[];
};
```

#### `0x37` Import item

> Requires authentication with Secret PIN.

```ts
/** Creates an item; returns EXISTS if the index is occupied, even by an identical item. */
type Request = {
  /** Original index used for Export. */
  index: byte[];
  /** Required for asymmetric envelopes; not needed for Bundle envelopes. */
  senderPublicKey?: byte[];
  metadata?: byte[];
  alias?: string;
  /** Export response data; index, metadata and alias must match that export. */
  data: byte[];
};
```

```ts
type Response = {};
```

#### `0x38` Create random key

> Requires authentication.

```ts
/** Always creates a secret item; returns EXISTS if its generated index is occupied. */
type Request = {
  type: SafeItemKeyType;
  /** Required for entropy/seed/hmac, in bytes; hmac: 1–255. */
  length?: number;
};
```

```ts
type Response = {
  index: byte[];
};
```

### `0x40` ~ `0x4F` Key usage

```ts
/** type must match the item selected by index. */
type KeySECP256k1 = {
  index: byte[];
} & (
  | {
      type: 'secp256k1';
    }
  | {
      type: 'seed';
      derivation: {
        /** Uses "Bitcoin seed" for seed-to-master generation. */
        type: 'bip32';
        /** 4-byte big-endian indices; high bit means hardened; empty selects master. */
        path: byte[];
      };
    }
);

type KeyED25519 = {
  index: byte[];
} & (
  | {
      type: 'ed25519';
    }
  | {
      type: 'seed';
      derivation: {
        /** Uses "ed25519 seed" for seed-to-master generation. */
        type: 'slip10';
        curve: 'ed25519';
        /** 4-byte big-endian hardened indices; empty selects master. */
        path: byte[];
      };
    }
);

type KeySECP256r1 = {
  index: byte[];
} & (
  | {
      type: 'secp256r1';
    }
  | {
      type: 'seed';
      derivation: {
        type: 'monoid-001';
        /** Opaque bytes; empty context is valid. */
        context: byte[];
      };
    }
);

type KeyHMAC = {
  index: byte[];
  /** Stored shared secret, 1–255 bytes. */
  type: 'hmac';
};

type Key = KeySECP256k1 | KeySECP256r1 | KeyED25519 | KeyHMAC;

/** secp256k1 only; true/{} enables BIP86, false/omitted disables tweaking. */
type Taproot = {
  /** Exactly 32 bytes when present; omit for BIP86 without a script tree. */
  merkleRoot?: byte[];
};
```

[Monoid-001 specification](doc/monoid-001.md)

#### `0x40` View key

> Requires authentication.

```ts
type Request =
  | (KeySECP256k1 & {
      taproot?: Taproot | boolean;
    })
  | KeySECP256r1
  | KeyED25519;
```

```ts
type Response = {
  /** 33-byte compressed EC key; 32 bytes for Ed25519 or Taproot x-only. */
  publicKey: byte[];
  /** Present for BIP32/SLIP-0010 derivation; 32 bytes, before Taproot tweaking. */
  chainCode?: byte[];
};
```

#### `0x41` Sign

> Requires authentication.

```ts
type Request =
  | ((KeySECP256k1 | KeySECP256r1) & {
      cipher: 'ecdsa';
      /** Precomputed 32-byte digest; use SHA-256(message) for ES256. */
      digest: byte[];
    })
  | (KeyED25519 & {
      cipher: 'ed25519';
      /** Original message bytes (pure Ed25519). */
      message: byte[];
    })
  | (KeySECP256k1 & {
      cipher: 'bip340';
      /** Exactly 32 bytes. */
      digest: byte[];
      taproot?: Taproot | boolean;
    });
```

```ts
type Response = {
  /** 64 bytes; ECDSA/BIP340: r || s, each a 32-byte big-endian integer; ECDSA uses low-S. */
  signature: byte[];
};
```

### Applet grants

```ts
type AppletGrantOptions = {
  aid: byte[];
  /** Exact custom types, 0x1000–0xFFFE; encoded as signed 16-bit integers. */
  types?: [type: number, writable: boolean][];
  /** Fixed Key descriptions; HMAC authorizes computation, not plaintext access. */
  keys?: Key[];
  /** A stored 64-byte seed for domain-scoped Monoid-001 derivation. */
  seed?: {index: byte[]; domain: byte[]};
};

type AppletGrant = AppletGrantOptions & {
  /** SHA-256 of the installed client's private 32-byte token. */
  tokenHash: byte[];
};
```

#### `0x50` List applet grants

> Requires Access PIN authentication.

```ts
type Request = {};
type Response = {grants: AppletGrant[]};
```

#### `0x51` Set applet grant

> Requires Access PIN authentication.

```ts
/** Replaces the entire grant for aid; omitted permissions are removed. */
type Request = AppletGrantOptions;
type Response = {};
```

#### `0x52` Remove applet grant

> Requires Access PIN authentication.

```ts
/** Succeeds when the grant is already absent. */
type Request = {aid: byte[]};
type Response = {};
```

### `0xFF` Reset

> No authentication required. Clears all items, applet grants, derivation cache, Bundle, both PINs and authorization; regenerates Identity keys and preserves the Card ID.

```ts
type Request = {};
```

```ts
type Response = {};
```

## Index

A safe item index is a 2 + 8 bytes array.

The first 2 bytes are the type of the item (`0x0000` to `0x0FFF` and `0xFFFF` are reserved), and the remaining 8 bytes are unique per item, typically 8-byte digest of the data if immutable:

- `0x01` `"entropy"` Entropy
  - +1 byte entropy length
  - +8 bytes digest of entropy
- `0x02` `"seed"` Seed key
  - +1 byte seed length
  - +8 bytes digest of seed
- `0x03` Weierstrass key
  - `0x0301` `"secp256k1"` SECP256K1 key
    - +8 bytes digest of key
  - `0x0302` `"secp256r1"` P-256 key (32-byte big-endian scalar, `1 <= d < n`)
    - +8 bytes digest of key
- `0x04` Edwards key
  - `0x0401` `"ed25519"` Ed25519 key (32-byte private-key seed)
    - +8 bytes digest of key
- `0x05` `"hmac"` HMAC key
  - +1 byte key length (1–255)
  - +8 bytes digest of key
- `0x0FFF` Generic data (draft, not implemented yet)
  - +8 bytes unique identifier

## Credits

Monoid JavaCard is a [javacard-gradle-template] fork, which uses projects like [javacard-gradle-plugin] and [ant-javacard] under the hood.

As this is my first JavaCard project, it would not be possible without great open-source works like these. 🎉

Especially, during prototyping, I was extensively using [keycard] as a manual for verified technical details, which saved me a lot of time and effort for trial-and-error. Keycard is also the reason that I know JavaCard is the ancient technology behind many card-based hardware crypto wallets. 🫡

## License

MIT License.

[gp]: https://github.com/martinpaljak/GlobalPlatformPro
[javacard-gradle-template]: https://github.com/ph4r05/javacard-gradle-template
[javacard-gradle-plugin]: https://github.com/ph4r05/javacard-gradle-plugin
[ant-javacard]: https://github.com/martinpaljak/ant-javacard
[keycard]: https://github.com/keycard-tech/status-keycard

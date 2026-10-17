<h1 align="center">
  <p>Monoid JavaCard</p>
  <sup>
    <!-- @inplate-line <code>0x{{hex MONOID_NAMESPACE uppercase=true}}</code> -->
    <code>0xF06D6F6E6F6964</code>
  </sup>
</h1>

<img src="./res/monoid.png" alt="Monoid" width="80" align="right" />

A JavaCard with Monoid applets installed is:

- [x] A hardware crypto wallet.
- [ ] A FIDO2 authenticator.
- [ ] A One-Time Password (OTP) generator.
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
gp --install build/javacard/monoidsafeidentity.cap
gp --install build/javacard/monoidsafe.cap
gp --install build/javacard/monoid.cap
```

Keep Safe Identity installed when replacing Safe. See [Safe Identity](doc/safe-identity.md).

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
# gp --uninstall build/javacard/monoidsafe.cap

# First installation only; preserve this applet across Safe updates:
# gp --install build/javacard/monoidsafeidentity.cap
gp --install build/javacard/monoidsafe.cap
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

The _Monoid Applet_ stores the safe PIN required by _Monoid Safe Applet_. When it has the safe PIN, the safe is considered **unlocked**, meaning:

1. _Monoid Applet_ itself can access the safe freely (commands probably have their own authentication requirements though).
2. Applets with granted permissions can interact (sign/verify) with keys and access data in _Monoid Safe Applet_ (via _Monoid Applet_).

See [architecture](doc/architecture.md) for more details.

## Roadmap

### Core features

- [x] _Monoid Applet_ basic commands
- [ ] _Monoid Applet_ third-party management commands
- [ ] _Monoid Applet_ `Shareable` interface
- [ ] Monoid mobile app
  - [ ] Key management
  - [ ] Crypto transaction signing
  - [ ] Third-party applet management

### Additional mobile app features

- [ ] Keys and data sync
- [ ] Applet gallery

### Applets for typical use cases

- [ ] FIDO2
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

See [Bitcoin signing](doc/bitcoin.md).

## ISO-7816 Commands

See [APDU transport](doc/apdu.md).

### Command authentication

The authentication is done within a session, using `0x21` command.

- Access PIN: for commands marked "Requires authentication".
- Safe PIN: for commands requiring safe PIN, or any command available with access PIN.

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
type Request = {
  /** Includes Safe information; defaults to false. */
  safe?: boolean;
};
```

```ts
type Response = {
  version: number;
  /** A 4-byte random id generated on _Monoid Applet_ installation. */
  id: byte[];
  features: Features;
  /** Tries remaining for the PIN, or `false` if the PIN is not set. */
  pin: number | false;
  safe?: {
    /** Persistent 4-byte random ID owned by Safe Identity. */
    id: byte[];
    /** Safe Identity P-256 public key, 65-byte uncompressed SEC 1. */
    publicKey: byte[];
    /** Tries remaining for the PIN, or `false` if the PIN is not set. */
    pin: number | false;
    /** Whether the safe is unlocked (i.e., Monoid Applet stores a validated safe PIN). */
    unlocked: boolean;
  };
};
```

### `0x21` Authenticate

```ts
type Request = {
  pin: string;
  safe?: true;
};
```

```ts
type Response = {};
```

#### `0x22` Set PIN

> Requires authentication with safe PIN if it is set.

```ts
type Request = {
  pin: string;
  /** Also unlocks Safe after Monoid Applet reinstallation. */
  safe?: true;
};
```

```ts
type Response = {};
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
type SafeItemKeyType = 'entropy' | 'seed' | 'master' | 'secp256k1' | 'secp256r1' | 'ed25519';
type SafeItemType = SafeItemKeyType | byte;
```

#### `0x30` List items

> Requires authentication.

```ts
type Request = {
  type?: SafeItemType;
  /** Matches item key only; omitted or empty means no key filter. */
  keyPrefix?: byte[];
};
```

```ts
type Response = {
  items: {
    index: byte[];
    type: SafeItemType;
    key?: byte[];
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
  key?: byte[];
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
type Request = (
  | {
      type: SafeItemType;
    }
  | {
      index: byte[];
    }
) & {
  /** Set at creation; searchable and readable with access PIN. */
  key?: byte[];
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
type Response = {};
```

#### `0x36` Export item

[Encrypted payload format](doc/item-transfer.md).

> Requires authentication with safe PIN.

```ts
type Request = {
  index: byte[];
  /** Recipient Safe Identity public key (65-byte uncompressed SEC 1). */
  recipientPublicKey: byte[];
};
```

```ts
type Response = {
  key?: byte[];
  alias?: string;
  /** Encrypts item data and secret; authenticates index, key and alias. */
  data: byte[];
};
```

#### `0x37` Import item

> Requires authentication.

```ts
/** Creates an item; identical existing items succeed unchanged, differing items conflict. */
type Request = {
  /** Original index used for Export. */
  index: byte[];
  /** Expected sender's Safe Identity public key (65-byte uncompressed SEC 1). */
  senderPublicKey: byte[];
  key?: byte[];
  alias?: string;
  /** Export response data; index, key and alias must match that export. */
  data: byte[];
};
```

```ts
type Response = {};
```

#### `0x38` Create random key

> Requires authentication.

```ts
/** Always creates a secret item. */
type Request = {
  type: SafeItemKeyType;
  /** Required for entropy/seed/master, in bytes; master stores twice this length. */
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
      type: 'seed' | 'master';
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
      type: 'seed' | 'master';
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
      type: 'seed' | 'master';
      derivation: {
        /** Monoid-001; master is its 64-byte HKDF PRK. */
        type: 'monoid-001';
        /** Opaque bytes; empty context is valid. */
        context: byte[];
      };
    }
);

type Key = KeySECP256k1 | KeySECP256r1 | KeyED25519;

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

## Index

A safe item index is a 2 + 8 bytes array.

The first 2 bytes are the type of the item (`0x0000` to `0x0FFF` and `0xFFFF` are reserved), and the remaining 8 bytes are unique per item, typically 8-byte digest of the data if immutable:

- `0x00` Monoid applet data (draft, not implemented yet)
  - `0x0001` Third-party applet permission data
    - +8 bytes digest of third-party AID
- `0x01` `"entropy"` Entropy
  - +1 byte entropy length
  - +8 bytes digest of entropy
- `0x02` `"seed"` Seed key
  - +1 byte seed length
  - +8 bytes digest of seed
- `0x03` `"master"` Master key
  - +1 byte master key length (note data length is master key length \* 2)
  - +8 bytes digest of master key
- `0x04` Weierstrass key
  - `0x0401` `"secp256k1"` SECP256K1 key
    - +8 bytes digest of key
  - `0x0402` `"secp256r1"` P-256 key (32-byte big-endian scalar, `1 <= d < n`)
    - +8 bytes digest of key
- `0x05` Edwards key
  - `0x0501` `"ed25519"` Ed25519 key (32-byte private-key seed)
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

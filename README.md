# Monoid <sup><span style="color: #ea9d34">Java</span><span style="color: #5e82a0">Card</span></sup>

Monoid is a secure gateway that connects your keys and data to end-user applications.

**A JavaCard with Monoid applets is already a hardware crypto wallet itself.** However, the goal is to allow third-party applets to interact with Monoid `Shareable` interface for signing/verifying and data access, so that Monoid can manage those keys and data and make it easy for users to backup, restore or even synchronize securely with unified UX.

## Requirements

- JavaCard 3.0.5+ SecID variant (supports ECC algorithms)

## Build & Install

```sh
./gradlew buildJavaCard
```

> Make sure `JAVA_HOME` is set to JDK 11. I use VSCode-based editor, checkout [.vscode/settings.json](.vscode/settings.json) for reference.

Then install applets to a card using [gp] command:

```sh
gp --install build/javacard/monoidsafe.cap
gp --install build/javacard/monoid.cap
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
# gp --uninstall build/javacard/monoidsafe.cap

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

See [ARCHITECTURE.md](ARCHITECTURE.md) for more details.

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

- [ ] Keys and data synchronization
- [ ] Applet gallery
- [ ] One-time password (OTP)

### Applets for typical use cases

- [ ] FIDO2
- [ ] Tesla key

### Cryptography

- Elliptic curves:
  - [x] `"secp256k1"`
  - [ ] `"ed25519"`
- Ciphers:
  - [x] `"ecdsa"`

## ISO-7816 Commands

_Monoid Applet_ uses a minimal CBOR-based RPC protocol.

### Command authentication

Command authentication is done by PIN validation. A request must provide either an access PIN or a safe PIN.

- Access PIN: for commands that would not result in keys/data revealed.
- Safe PIN: for commands that could result in keys/data revealed.

```ts
type AuthRequest = {
  auth: {
    pin: string;
  };
};

type SafeAuthRequest = {
  auth: {
    pin: string;
    safe: true;
  };
};
```

### `0x20` ~ `0x2F` System management

#### `0x20` Hello

```ts
type Request = {};
```

```ts
type Response = {
  version: number;
  features: {
    curves: string[];
    ciphers: string[];
  };
  /** Tries remaining for the PIN, or `false` if the PIN is not set. */
  pin: number | false;
  safe: {
    /** Tries remaining for the PIN, or `false` if the PIN is not set. */
    pin: number | false;
    /** Whether the safe is unlocked (i.e., Monoid Applet stores a validated safe PIN). */
    unlocked: boolean;
  };
};
```

#### `0x21` Set PIN

- Requires authentication with safe PIN if it is set.

```ts
type Request = (SafeAuthRequest | {}) & {
  pin: string;
  safe?: true;
};
```

```ts
type Response = {};
```

> In case of _Monoid Applet_ reinstallation resulting in its losing the safe PIN, setting safe PIN again (to either the same or a different PIN) will restore the safe PIN stored in _Monoid Applet_ (thus "unlocking" the safe).

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
};
```

### `0x30` ~ `0x3F` Safe management

#### `0x30` List safe items

```ts
type SafeItemKeyType = 'entropy' | 'seed' | 'master' | 'secp256k1';
type SafeItemType = SafeItemKeyType | byte;
```

```ts
type Request = AuthRequest & {
  type?: SafeItemType;
};
```

```ts
type Response = {
  items: {
    type: SafeItemType;
    index: byte[];
  }[];
};
```

#### `0x31` Get item

```ts
type Request = SafeAuthRequest & {
  index: byte[];
};
```

```ts
type Response = {
  data: byte[];
};
```

#### `0x32` Set item

```ts
type Request = AuthRequest & {
  index: byte[];
  data: byte[];
};
```

```ts
type Response = {};
```

#### `0x33` Clear item

```ts
type Request = AuthRequest & {
  index: byte[];
};
```

```ts
type Response = {};
```

#### `0x38` Create random key

```ts
type Request = AuthRequest & {
  type: SafeItemKeyType;
};
```

```ts
type Response = {
  index: byte[];
};
```

### `0x40` ~ `0x4F` Key usage

```ts
type Key = {
  index: byte[];
} & (
  | {
      // seed
      seed: string;
      curve: string;
      path: byte[];
    }
  | {
      // master
      curve: string;
      path: byte[];
    }
  | {
      // key
    }
);
```

#### `0x40` View key

```ts
type Request = AuthRequest & Key;
```

```ts
type Response = {
  publicKey: byte[];
} & (
  | {
      // seed / master
      chainCode: byte[];
    }
  | {
      // key
    }
);
```

#### `0x41` Sign

```ts
type Request = AuthRequest &
  Key & {
    cipher: string;
    digest: byte[];
  };
```

```ts
type Response = {
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
- `0x04` EC key
  - `0x0401` `"secp256k1"` SECP256K1 key
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

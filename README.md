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

- Elliptic curves:
  - [x] `"secp256k1"`
  - [x] `"ed25519"`
- Ciphers:
  - [x] `"ecdsa"`
  - [x] `"eddsa"`

## ISO-7816 Commands

_Monoid Applet_ uses a minimal CBOR-based RPC protocol.

### APDU transport

Encode the complete request as CBOR, then send it in short APDUs with 1–255 data bytes per frame. Requests of up to 8192 bytes can be split using these CLA values:

| Frame  | CLA  | Behavior                                                          |
| ------ | ---- | ----------------------------------------------------------------- |
| Single | `00` | Replace any unfinished request and execute this complete request. |
| First  | `90` | Replace any unfinished request and begin receiving a new one.     |
| Middle | `B0` | Append to the active request.                                     |
| Last   | `A0` | Append to the active request and execute it.                      |

Every frame carries the business command's INS, P1 and P2. Middle and last frames must match the first frame's header. First and middle frames return an empty `9000`; business commands run only after a single or last frame. The transport layer handles framing without changing command request or response schemas. Extended APDUs are not supported.

A new request cancels any unread response. Responses retain the existing continuation convention: `61xx` means more response data is available, in chunks of up to 256 bytes; send `00 C0 00 00 Le` until `9000`. Always use CLA `00` for GET RESPONSE, including after an `A0` request. Disable middleware that automatically reuses the previous CLA. GET RESPONSE with no pending response returns `6985`; during an unfinished request it returns `6883` and leaves that request intact. Invalid GET RESPONSE headers also leave the pending transfer intact.

An orphan or mismatched middle/last frame returns `6883`. Empty or oversized input returns `6700`; unsupported CLA/INS return `6E00`/`6D00`. Request reception errors discard the unfinished request, so retry with a single or first frame. Selecting or deselecting the applet, or resetting the card, cancels pending transfers.

Fragmented requests use 256-byte chunks allocated as needed without copying previous chunks. The first 512 bytes of the complete CBOR request use RAM; additional chunks use plaintext persistent storage. Single-frame requests can use the APDU buffer directly. CBOR parsing reads across chunk boundaries; Ed25519 signing traverses the Message range twice without joining the chunks or making a separate Message copy. Completion, cancellation, errors and deselection erase every owned chunk and release its reference. Persistent chunk references survive reset so selection can also erase an interrupted request.

The 8192-byte limit applies to the complete request; payload storage is not preallocated to that size. Decoded fields and cryptographic workspaces still require RAM, so capacity depends on the command and card. Replacing an unfinished request releases its chunks and requests garbage collection; reclamation is not synchronous. Simulator and physical-card tests cover signing at the 8192-byte request limit, including Message fields before other fields. See [card validation](doc/cards.md) for message sizes, timings and memory measurements. Actual repeated `receiveBytes` delivery within one short APDU remains unverified.

### Command authentication

The authentication is done within a session, using `0x21` command.

- Access PIN: for commands that would not result in keys/data revealed.
- Safe PIN: for commands that could result in keys/data revealed, or commands that requires access PIN.

### `0x20` ~ `0x2F` System management

#### `0x20` Hello

```ts
type Request = {};
```

```ts
type Response = {
  version: number;
  /** A 4-byte random id generated on _Monoid Applet_ installation. */
  id: byte[];
  features: {
    curves: {
      name: string;
      ciphers: string[];
    }[];
  };
  /** Tries remaining for the PIN, or `false` if the PIN is not set. */
  pin: number | false;
  safe: {
    /** A 4-byte random id generated on _Monoid Safe Applet_ installation. */
    id: byte[];
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
  features: {
    curves: {
      name: string;
      ciphers: string[];
    }[];
  };
};
```

### `0x30` ~ `0x3F` Safe management

```ts
type SafeItemKeyType = 'entropy' | 'seed' | 'master' | 'secp256k1';
type SafeItemType = SafeItemKeyType | byte;
```

#### `0x30` List items

> Requires authentication.

```ts
type Request = {
  type?: SafeItemType;
};
```

```ts
type Response = {
  items: {
    index: byte[];
    type: SafeItemType;
    alias?: string;
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
  alias?: string;
};
```

#### `0x32` Get item

> Requires authentication with safe PIN.

```ts
type Request = {
  index: byte[];
};
```

```ts
type Response = {
  alias?: string;
  data: byte[];
};
```

#### `0x33` Set item

> Requires authentication.

```ts
type Request = {
  index: byte[];
  alias?: byte[];
  data?: byte[];
};
```

```ts
type Response = {};
```

#### `0x34` Create item

> Requires authentication.

```ts
type Request = {
  (
    | {
        type: SafeItemType;
      }
    | {
        index: byte[];
      }
  ) & {
    alias?: byte[];
    data: byte[];
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

#### `0x38` Create random key

> Requires authentication.

```ts
type Request = {
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

> Requires authentication.

For `curve: 'ed25519'`, derives from a stored seed or master using hardened SLIP-0010 and returns the 32-byte encoded public key and 32-byte chain code. A stored seed uses `seed: 'ed25519 seed'` as the master derivation label.

```ts
type Request = Key;
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

> Requires authentication.

```ts
type Request = Key &
  (
    | {
        cipher: 'ecdsa';
        digest: byte[];
      }
    | {
        cipher: 'eddsa';
        message: byte[];
      }
  );
```

EdDSA takes the original message bytes and signs with Ed25519 after hardened SLIP-0010 derivation from a stored seed or master.

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

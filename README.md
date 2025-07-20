# Monoid JavaCard

Monoid is a secure gateway that connects your keys and end-user applications.

**A JavaCard with Monoid applets is already a hardware crypto wallet itself.** However, the goal is to allow third-party applets to interact with Monoid `Shareable` interface for signing/verifying and data access, so that Monoid can manage those keys and data and make it easy for users to backup, restore or even synchronize securely with unified UX.

## Architecture

The Monoid Applet stores the safe PIN required by Monoid Safe Applet. When it has the safe PIN, the safe is considered **unlocked**, meaning:

1. Monoid Applet itself can access the safe freely (commands probably have their own authentication requirements though).
2. Applets with granted permissions can interact (sign/verify) with keys and access data in Monoid Safe Applet (via Monoid Applet).

See [ARCHITECTURE.md](ARCHITECTURE.md) for more details.

## Roadmap

Core features:

- [x] Monoid Applet basic commands
- [ ] Monoid Applet third-party management commands
- [ ] Monoid Applet `Shareable` interface
- [ ] Monoid mobile app
  - [ ] Key management
  - [ ] Crypto transaction signing
  - [ ] Third-party applet management

Additional mobile app features:

- [ ] Keys and data synchronization
- [ ] Applet gallery
- [ ] One-time password (OTP)

Also some applets for typical use cases:

- [ ] FIDO2
- [ ] Tesla key

## ISO-7816 Commands

Monoid Applet uses a minimal CBOR-based RPC protocol.

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

> In case of Monoid Applet reinstallation resulting in its losing the safe PIN, setting safe PIN again (to either the same or a different PIN) will restore the safe PIN stored in Monoid Applet (thus "unlocking" the safe).

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
type SafeItemKeyType = 'seed' | 'master' | 'key';
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
  curve: string;
} & (
  | {
      // seed
      seed: string;
      path: byte[];
    }
  | {
      // master
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

## License

MIT License.

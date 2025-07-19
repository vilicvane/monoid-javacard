# Monoid Applet

Monoid Applet is the gateway between apps (e.g., the Monoid App), the Monoid Safe Applet, and Monoid Ecosystem Applets.

## ISO-7816 Commands

### Command authentication

Command authentication is done by PIN validation. A request must provide either an access PIN (for MonoidApplet-managed access) or a safe PIN.

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

> In case of Monoid Applet reinstallation, it loses the safe PIN. Setting safe PIN again (to either the same or a different PIN) will store the PIN in Monoid Applet (and essentially unlock the safe).

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

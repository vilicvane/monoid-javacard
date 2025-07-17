# Monoid Applet

Monoid Applet is the gateway between apps (e.g., the Monoid App), the Monoid Safe Applet, and Monoid Ecosystem Applets.

## ISO-7816 Commands

### Command Authentication

Command authentication is done by PIN validation. A request must provide either an access PIN (for MonoidApplet-managed access) or a safe PIN.

```ts
type AuthRequest = {
  auth: {
    pin: string;
    safe: boolean;
  };
};
```

### `0x20` ~ `0x2F` Security Management

#### `0x20` Hello

```ts
type Request = never;
```

```ts
type Response = {
  versions: {
    monoid: number;
    javacard: [number, number];
  };
  /** Tries remaining for the PIN, or `false` if the PIN is not set. */
  pin: number | false;
  safe: {
    /** Tries remaining for the PIN, or `false` if the PIN is not set. */
    pin: number | false;
    /** Whether the safe is unlocked (i.e., MonoidApplet stores a validated safe PIN). */
    unlocked: boolean;
  };
};
```

#### `0x21` Set PIN

```ts
type Request = AuthRequest & {
  pin: string;
  safe: boolean;
};
```

```ts
type Response = {
  error?: {
    code: 'INVALID_PIN';
    tries: number;
  };
};
```

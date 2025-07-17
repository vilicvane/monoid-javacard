# Monoid Applet

Monoid Applet is the gateway between apps (e.g., the Monoid App), the Monoid Safe Applet, and Monoid Ecosystem Applets.

## ISO-7816 Commands

### `0x20` Hello

```json

```

```ts
type Response = {
  versions: {
    monoid: number;
    javacard: number;
  };
  pin: number | false;
  safe: {
    pin: number | false;
    unlocked: boolean;
  };
};
```

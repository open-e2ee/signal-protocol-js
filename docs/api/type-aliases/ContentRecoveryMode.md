[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ContentRecoveryMode

# Type Alias: ContentRecoveryMode

> **ContentRecoveryMode** = `"require-protected"` \| `"allow-co-located-key"` \| `"off"`

Which local store protection lets the client keep resendable content.

- `require-protected`: keep it only when the store is encrypted and its
  key is in an operating system keychain or a declared application vault.
- `allow-co-located-key`: also keep it when the key is in storage that
  the data shares, such as the same browser origin. Use it only after a
  product review accepts that custody.
- `off`: never keep it.

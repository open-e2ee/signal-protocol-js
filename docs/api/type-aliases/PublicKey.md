[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PublicKey

# Type Alias: PublicKey

> **PublicKey** = [`Base64`](Base64.md) & `object`

Base64-encoded public key.

Branded type prevents accidentally using a private key where the API needs a
public key, or vice versa. TypeScript catches these errors at compile time.

Extends Base64, so a function that expects Base64 accepts it.

## Type Declaration

### \[\_\_\_brand\_public\]

> `readonly` **\[\_\_\_brand\_public\]**: `true`

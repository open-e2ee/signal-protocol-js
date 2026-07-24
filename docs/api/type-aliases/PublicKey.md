[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PublicKey

# Type Alias: PublicKey

> **PublicKey** = [`Base64`](Base64.md) & `object`

Base64-encoded public key.

Branded type prevents accidentally using a private key where a public key
is expected, or vice versa. TypeScript will catch these errors at compile time.

Extends Base64, so can be passed to functions expecting Base64.

## Type Declaration

### \[\_\_\_brand\_public\]

> `readonly` **\[\_\_\_brand\_public\]**: `true`

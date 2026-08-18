[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PrivateKey

# Type Alias: PrivateKey

> **PrivateKey** = [`Base64`](Base64.md) & `object`

Base64-encoded private key (stored only in SecureStore).

Branded type prevents a private key from reaching a parameter that needs a
public key.

Extends Base64, so a function that expects Base64 accepts it.

## Type Declaration

### \[\_\_\_brand\_private\]

> `readonly` **\[\_\_\_brand\_private\]**: `true`

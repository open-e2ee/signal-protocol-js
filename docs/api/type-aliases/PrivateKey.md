[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PrivateKey

# Type Alias: PrivateKey

> **PrivateKey** = [`Base64`](Base64.md) & `object`

Base64-encoded private key (stored only in SecureStore).

Branded type ensures private keys aren't accidentally passed where
public keys are expected.

Extends Base64, so can be passed to functions expecting Base64.

## Type Declaration

### \[\_\_\_brand\_private\]

> `readonly` **\[\_\_\_brand\_private\]**: `true`

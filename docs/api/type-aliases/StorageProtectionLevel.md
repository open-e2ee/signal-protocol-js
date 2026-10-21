[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / StorageProtectionLevel

# Type Alias: StorageProtectionLevel

> **StorageProtectionLevel** = `"protected"` \| `"co-located"` \| `"none"`

How well a local store protects resendable content.

- `protected`: the store is encrypted, and its key is in an operating
  system keychain or a declared application vault.
- `co-located`: the store is encrypted, and its key is in storage that the
  data shares, such as the same browser origin. This is weaker key
  custody, not missing encryption.
- `none`: the store has no encryption or no key.

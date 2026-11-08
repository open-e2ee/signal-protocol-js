[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliverySource

# Type Alias: DeliverySource

> **DeliverySource** = `"relay"` \| `"signal-relay"` \| `"e2ee"`

A source that reports that a recipient device has a message.

- `'relay'`: the Relay handed the message to the device. The device has not
  yet decrypted it.
- `'signal-relay'`: the same source as `'relay'`. SDK 15.0.0 reports the
  Relay source with this value. This release reports `'relay'`, so code
  that compares the source must accept both values.
- `'e2ee'`: the device decrypted the message and sent an encrypted delivery
  receipt.

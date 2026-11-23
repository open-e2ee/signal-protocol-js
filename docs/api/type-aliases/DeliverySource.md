[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliverySource

# Type Alias: DeliverySource

> **DeliverySource** = `"relay"` \| `"signal-relay"` \| `"e2ee"`

A source that reports that a recipient device has a message.

- `'signal-relay'`: the Relay handed the message to the device. The device
  has not yet decrypted it.
- `'relay'`: the same source as `'signal-relay'`. SDK 14 reported the Relay
  source with this value. This release does not report it. The type keeps
  it, so code that compares the source with both values compiles.
- `'e2ee'`: the device decrypted the message and sent an encrypted delivery
  receipt.

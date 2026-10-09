[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliverySource

# Type Alias: DeliverySource

> **DeliverySource** = `"relay"` \| `"e2ee"`

A source that reports that a recipient device has a message.

- `'relay'`: the Relay handed the message to the device. The device has not
  yet decrypted it.
- `'e2ee'`: the device decrypted the message and sent an encrypted delivery
  receipt.

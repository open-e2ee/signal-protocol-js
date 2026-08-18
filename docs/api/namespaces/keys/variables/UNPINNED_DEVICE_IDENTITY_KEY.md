[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / UNPINNED\_DEVICE\_IDENTITY\_KEY

# Variable: UNPINNED\_DEVICE\_IDENTITY\_KEY

> `const` **UNPINNED\_DEVICE\_IDENTITY\_KEY**: `Uint8Array`

SESAME `DeviceRecord.identityKey` bytes for a device with no observed
composite identity yet.

Zero length is the only way to say "not pinned". It must stay distinct
from a pinned tuple, so that first contact makes a TOFU pin rather than
reporting an identity change. It must also never be a partial key. Pinning
only the X25519 half would silently accept a peer that kept its DH key and
swapped its Ed25519 signing key.

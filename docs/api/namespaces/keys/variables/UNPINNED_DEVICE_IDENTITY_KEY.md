[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / UNPINNED\_DEVICE\_IDENTITY\_KEY

# Variable: UNPINNED\_DEVICE\_IDENTITY\_KEY

> `const` **UNPINNED\_DEVICE\_IDENTITY\_KEY**: `Uint8Array`

SESAME `DeviceRecord.identityKey` bytes for a device whose composite identity
has not been observed yet.

Zero length is the only representation of "not pinned". It must stay distinct
from a pinned tuple so that first contact performs a TOFU pin rather than
reporting an identity change, and it must never be a partial key: pinning
only the X25519 half would silently accept a peer that kept its DH key and
swapped its Ed25519 signing key.

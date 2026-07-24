[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupChangeEntry

# Interface: GroupChangeEntry

Group change log entry returned by getGroupChanges().
All content is opaque to the server.

## Properties

### encryptedChange

> **encryptedChange**: `Uint8Array`

Serialized GroupChange (opaque to server)

***

### serverSignature

> **serverSignature**: `Uint8Array`

Server's binding signature for this change

***

### timestamp

> **timestamp**: `number`

When the server accepted this change

***

### version

> **version**: `number`

Revision number this change produces

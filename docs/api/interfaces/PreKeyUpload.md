[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PreKeyUpload

# Interface: PreKeyUpload

Prekey upload (batch).
Server stores in appropriate table based on `type`.

## Properties

### keyId

> **keyId**: `number`

Key ID (unique per type per device)

***

### publicKey

> **publicKey**: `string`

Public key (base64 encoded)

***

### signature?

> `optional` **signature?**: `string`

Signature (for signed keys only)

***

### type

> **type**: `"ecPreKey"` \| `"ecSignedPreKey"` \| `"kemOneTimePreKey"` \| `"kemLastResortPreKey"`

Table to store in

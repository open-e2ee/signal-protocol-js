[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / EcSignedPreKeyUpload

# Interface: EcSignedPreKeyUpload

EC signed prekey upload for key rotation.
Contains the full key including private key for local storage.

## Properties

### deviceId

> **deviceId**: `number`

Device ID (1=primary, 2-5=linked)

***

### keyId

> **keyId**: `number`

Key ID

***

### publicKey

> **publicKey**: `string`

Public key (base64 encoded)

***

### signature

> **signature**: `string`

Signature from identity key (base64 encoded)

***

### timestamp

> **timestamp**: `number`

Timestamp when generated

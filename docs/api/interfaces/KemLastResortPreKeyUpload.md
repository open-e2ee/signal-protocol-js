[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KemLastResortPreKeyUpload

# Interface: KemLastResortPreKeyUpload

KEM last-resort prekey upload for key rotation.
Contains the full key including private key for local storage.

## Properties

### deviceId

> **deviceId**: `number`

Device ID (1=primary, 2-5=linked)

***

### keyId

> **keyId**: `number`

Key ID (always 1 per PQXDH spec Section 3.2)

***

### publicKey

> **publicKey**: `string`

Public key (base64 encoded, ~1.5KB for ML-KEM-1024)

***

### signature

> **signature**: `string`

Signature from identity key (base64 encoded)

***

### timestamp

> **timestamp**: `number`

Timestamp when generated

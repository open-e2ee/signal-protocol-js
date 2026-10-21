[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SenderKeyHandoffRecord

# Interface: SenderKeyHandoffRecord

The Relay accepted a distribution of the local device's own sender key for
this recipient device. A row records a handoff. It is never proof that the
recipient installed the key.

## Properties

### acceptedAt

> **acceptedAt**: `number`

***

### generation

> **generation**: `number`

***

### groupId

> **groupId**: `string`

***

### recipientDeviceId

> **recipientDeviceId**: `number`

***

### recipientRegistrationId

> **recipientRegistrationId**: `number`

The registration ID of the recipient's current session when the Relay accepted the post.

***

### recipientUserId

> **recipientUserId**: `string`

***

### senderKeyId

> **senderKeyId**: `string`

[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientHooks

# Interface: SignalProtocolClientHooks

Event hooks that can be registered with SignalProtocolClient

All hooks are optional and support both sync and async implementations.

## Properties

### onDecryptionError?

> `optional` **onDecryptionError?**: (`sessionId`, `error`) => `void` \| `Promise`\<`void`\>

Called when decryption fails

Allows app to handle errors, log issues, or show user feedback.

#### Parameters

##### sessionId

`string`

The session where decryption failed

##### error

`Error`

The encryption error that occurred

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onDecryptionError: (sessionId, error) => {
  // Log to monitoring service
  Sentry.captureException(error, {
    tags: { sessionId, errorCode: error.code }
  });
  // Show user-friendly message
  showError('Failed to decrypt message');
}
```

***

### onDeliveryReceiptReceived?

> `optional` **onDeliveryReceiptReceived?**: (`senderId`, `timestamps`) => `void` \| `Promise`\<`void`\>

Called when a delivery receipt is received

Allows the app to update message status from 'sent' to 'delivered'.
The timestamps array contains server timestamps of delivered messages.

#### Parameters

##### senderId

`string`

The user who sent the delivery receipt (message recipient)

##### timestamps

`number`[]

Array of message timestamps that were delivered

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onDeliveryReceiptReceived: async (senderId, timestamps) => {
  for (const timestamp of timestamps) {
    await updateMessageStatus(timestamp, 'delivered');
  }
}
```

***

### onEncryptionError?

> `optional` **onEncryptionError?**: (`sessionId`, `error`) => `void` \| `Promise`\<`void`\>

Called when encryption fails

Allows app to handle errors, log issues, or retry logic.

#### Parameters

##### sessionId

`string`

The session where encryption failed

##### error

`Error`

The encryption error that occurred

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onEncryptionError: (sessionId, error) => {
  // Log error
  console.error('Encryption failed:', error);
  // Attempt recovery
  if (error.code === 'SESSION_CORRUPTED') {
    reestablishSession(sessionId);
  }
}
```

***

### onKeyRotated?

> `optional` **onKeyRotated?**: (`keyType`) => `void` \| `Promise`\<`void`\>

Called after a key rotation completes successfully

#### Parameters

##### keyType

`"ecSignedPreKey"` \| `"kemLastResortPreKey"`

Type of key that was rotated

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onKeyRotated: (keyType) => {
  console.log(`${keyType} rotated successfully`);
  analytics.track('Key Rotation', { keyType });
}
```

***

### onKeysCleanedUp?

> `optional` **onKeysCleanedUp?**: (`sessionId`, `removedCount`) => `void` \| `Promise`\<`void`\>

Called during key cleanup (expired message keys removed)

Useful for monitoring storage usage and cleanup operations.

#### Parameters

##### sessionId

`string`

The session where cleanup occurred

##### removedCount

`number`

Number of expired keys removed

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onKeysCleanedUp: (sessionId, removedCount) => {
  console.log(`Cleaned up ${removedCount} expired keys`);
  analytics.track('Keys Cleaned', { sessionId, removedCount });
}
```

***

### onMessageDecrypted?

> `optional` **onMessageDecrypted?**: (`envelope`) => `void` \| `Promise`\<`void`\>

Called after a message is successfully decrypted

This is the primary hook for ContentManager integration.
The hook receives the full decrypted envelope with all metadata
needed to store the message in the encrypted content database.

#### Parameters

##### envelope

[`DecryptedEnvelope`](DecryptedEnvelope.md)

The decrypted message envelope

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onMessageDecrypted: async (envelope) => {
  // Store in encrypted content database
  await contentDb.storeMessage({
    messageId: envelope.messageId,
    conversationId: envelope.conversationId,
    senderId: envelope.senderId,
    senderDeviceId: envelope.senderDeviceId,
    content: envelope.content,
    timestamp: envelope.timestamp,
    receivedAt: envelope.receivedAt,
    isOutgoing: false,
  });
  // Send read receipt
  sendReadReceipt(envelope.sessionId);
}
```

***

### onMessageEncrypted?

> `optional` **onMessageEncrypted?**: (`sessionId`, `counter`) => `void` \| `Promise`\<`void`\>

Called after a message is successfully encrypted

Useful for analytics, monitoring, or cache warming.

#### Parameters

##### sessionId

`string`

The session used for encryption

##### counter

`number`

The message counter (Ns) - matches the libsignal proto field name

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onMessageEncrypted: (sessionId, counter) => {
  analytics.track('Message Encrypted', {
    sessionId,
    counter
  });
}
```

***

### onReadReceiptReceived?

> `optional` **onReadReceiptReceived?**: (`senderId`, `timestamps`) => `void` \| `Promise`\<`void`\>

Called when a read receipt is received

Allows the app to update message status from 'delivered' to 'read'.
The timestamps array contains server timestamps of read messages.

#### Parameters

##### senderId

`string`

The user who sent the read receipt (message recipient who viewed messages)

##### timestamps

`number`[]

Array of message timestamps that were read

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onReadReceiptReceived: async (senderId, timestamps) => {
  for (const timestamp of timestamps) {
    await updateMessageStatus(timestamp, 'read');
  }
}
```

***

### onSessionArchived?

> `optional` **onSessionArchived?**: (`sessionId`) => `void` \| `Promise`\<`void`\>

Called after a session is archived (moved to inactive list)

Stale-device recovery archives the session so delayed messages can still
attempt decryption.
Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"

#### Parameters

##### sessionId

`string`

The session identifier that was archived

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onSessionArchived: (sessionId) => {
  console.log(`Session ${sessionId} archived, will be replaced with fresh session`);
}
```

***

### onSessionDeleted?

> `optional` **onSessionDeleted?**: (`sessionId`) => `void` \| `Promise`\<`void`\>

Called after a session is deleted

#### Parameters

##### sessionId

`string`

The session identifier that was deleted

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onSessionDeleted: (sessionId) => {
  // Clear cache
  ContentManager.clearSession(sessionId);
  // Update UI
  removeSessionFromList(sessionId);
}
```

***

### onSessionEstablished?

> `optional` **onSessionEstablished?**: (`sessionId`, `remoteAddress`) => `void` \| `Promise`\<`void`\>

Called after a new session is successfully established

#### Parameters

##### sessionId

`string`

The session identifier

##### remoteAddress

`string`

The remote user's address

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onSessionEstablished: (sessionId, remoteAddress) => {
  // Invalidate cache
  ContentManager.invalidateSession(sessionId);
  // Update UI state
  setSessionStatus(sessionId, 'active');
}
```

***

### onTypingIndicatorReceived?

> `optional` **onTypingIndicatorReceived?**: (`senderId`, `conversationId`, `action`) => `void` \| `Promise`\<`void`\>

Called when a typing indicator is received

Allows the app to update UI to show who is typing.
Typing indicators are transient - they auto-expire after 15 seconds.

#### Parameters

##### senderId

`string`

The user who sent the typing indicator

##### conversationId

`string`

The conversation where typing is occurring

##### action

[`TypingAction`](../enumerations/TypingAction.md)

Whether user STARTED or STOPPED typing

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onTypingIndicatorReceived: async (senderId, conversationId, action) => {
  if (action === TypingAction.STARTED) {
    typingManager.setTyping(conversationId, senderId);
  } else {
    typingManager.clearTyping(conversationId, senderId);
  }
}
```

***

### onViewedReceiptReceived?

> `optional` **onViewedReceiptReceived?**: (`senderId`, `timestamps`) => `void` \| `Promise`\<`void`\>

Called when a viewed receipt is received (e.g., view-once media)

Allows the app to update message status to 'viewed'.
The timestamps array contains server timestamps of viewed messages.

#### Parameters

##### senderId

`string`

The user who sent the viewed receipt (message recipient who viewed media)

##### timestamps

`number`[]

Array of message timestamps that were viewed

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onViewedReceiptReceived: async (senderId, timestamps) => {
  for (const timestamp of timestamps) {
    await updateMessageStatus(timestamp, 'viewed');
  }
}
```

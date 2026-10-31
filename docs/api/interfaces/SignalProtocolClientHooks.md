[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientHooks

# Interface: SignalProtocolClientHooks

Event hooks that SignalProtocolClient accepts

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

### onDelivered?

> `optional` **onDelivered?**: (`event`) => `void` \| `Promise`\<`void`\>

Runs when a recipient device gets one of this client's messages

A message to one device goes from accepted (the send resolved) to
delivered. The hook runs for each source that reports the delivery:
`'relay'` when the Relay hands the message to the device, and `'e2ee'`
when the device decrypts it and sends an encrypted delivery receipt. A
receipt that arrives before the send resolves runs the hook after the
send resolves.

The hook runs at least once for each source. The client marks a source
announced only after the hook returns. An error from the hook fails the
receipt, so the relay delivers it again. A hook that throws, a client
stop during the hook, or a crash leaves the source unannounced, and the
hook runs again for it with the next receipt for the message. A second
report from the same source after the hook returned does not run the
hook. Make the hook idempotent for one `clientMessageId`,
`recipientDeviceId`, and `source`.

#### Parameters

##### event

[`DeliveredEvent`](DeliveredEvent.md)

The delivery and its sources so far

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onDelivered: async (event) => {
  await updateMessageStatus(event.clientMessageId, event.recipientDeviceId, {
    status: 'delivered',
    decryptionConfirmed: event.decryptionConfirmed,
  });
}
```

***

### onDeliveryError?

> `optional` **onDeliveryError?**: (`event`) => `void` \| `Promise`\<`void`\>

Runs when an incoming message failed to decrypt and its content did not
come back

A failed decrypt asks the sender device for a resend and acknowledges
the failed envelope. The content hint of the envelope sets when the
hook runs. With the `Default` hint, or no hint, it runs at the first
failure. With the `Resendable` hint, it runs when the content did not
come back within `RETRY_PLACEHOLDER_DEADLINE_MS`, one hour, of the
first failure. With the `Implicit` hint, it never runs. A rate limit
that refuses the retry request, and the end of the request, make it run
at once. The client checks the time at each redelivery of the envelope
and at each retry family write. With a relay, it also checks at
create() and, while the client runs, at the time when the error is due.

The hook runs at least once for each failed envelope, also across a
restart. The client marks the error shown only after the hook returns.
A hook that throws, a client stop during the hook, or a crash leaves the
error not shown, and the hook runs again at the next retry request
pass, start, or redelivery. The receive path does not acknowledge a
failed envelope whose hook threw. Make the hook idempotent for one
`failedEnvelopeId`. The error deletes nothing: the retry request
continues, and when the content comes back, `onDeliveryRecovered` runs.

#### Parameters

##### event

[`DeliveryErrorEvent`](DeliveryErrorEvent.md)

The failed envelope, its sender and the cause

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onDeliveryError: async (event) => {
  await messageStore.showUndelivered(event.failedEnvelopeId, event.senderUserId);
}
```

***

### onDeliveryRecovered?

> `optional` **onDeliveryRecovered?**: (`event`) => `void` \| `Promise`\<`void`\>

Runs when the content of a failed incoming message comes back after
`onDeliveryError` ran for it

The content comes back in a resend from the sender device, or in a
redelivery of the failed envelope that now decrypts. The application
gets the content as for any message, and then this hook runs. Its
event carries the time of the first failure, so the application can put
the message back in its first place.

The hook runs at least once for each failed envelope, also across a
restart. The client marks the recovery only after the hook returns. A
hook that throws, a client stop during the hook, or a crash leaves the
recovery not marked, and the hook runs again at the next retry request
pass, start, or receive of an envelope of the same retry family. An
error from the hook after the content does not fail that receive. Make
the hook idempotent for one `failedEnvelopeId`.

#### Parameters

##### event

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md)

The failed envelope and its sender

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onDeliveryRecovered: async (event) => {
  await messageStore.clearUndelivered(event.failedEnvelopeId);
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

### onGroupInitStatus?

> `optional` **onGroupInitStatus?**: (`groupId`, `status`) => `void` \| `Promise`\<`void`\>

Runs when a client write to the record of a group changes the init
status of the group.

The hook gets the status after the write. It does not run when a write
keeps the same status, or when a write deletes the record. When two
writes to one group run at the same time, the hook can miss the status
between them. The hook calls run in order, and no write waits for a hook
call. So the hook can call a client method for the same group.

The hook does not run for the statuses that the store holds when the
client starts, or for a write that the application makes to the group
store. Read each status with `getGroupInitStatus` when the application
starts.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

The group whose status changed

##### status

[`GroupInitStatus`](../type-aliases/GroupInitStatus.md)

The status after the change

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onGroupInitStatus: (groupId, status) => {
  groupList.setInitStatus(groupId, status);
}
```

***

### onKeyRotated?

> `optional` **onKeyRotated?**: (`keyType`) => `void` \| `Promise`\<`void`\>

Called after a key rotation completes successfully

#### Parameters

##### keyType

`"ecSignedPreKey"` \| `"kemLastResortPreKey"`

Type of the rotated key

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

Delivery is at least once. The client stores the content before it
acknowledges the Relay message and runs the hook after that. A stop or
a crash before the client records the delivery runs the hook again
with the same `messageId`. Deduplicate on `messageId`.

The hook must settle. The receive queue runs one hook call at a time,
so a hook that never settles stops the queue and `processPendingReceives`
until the process restarts.

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

The message counter (Ns) - matches the reference implementation's proto field name

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

Runs when the client receives a read receipt

Allows the app to update message status from 'delivered' to 'read'.
The timestamps array contains server timestamps of read messages.

#### Parameters

##### senderId

`string`

The user who sent the read receipt (message recipient who viewed messages)

##### timestamps

`number`[]

Array of message timestamps for the read messages

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

### onReceiveExpired?

> `optional` **onReceiveExpired?**: (`event`) => `void` \| `Promise`\<`void`\>

Runs when received content waited on this device for 30 days, before
the client drops it.

Content waits when its group state is not current, or when a helper
receive is not completed. The hook runs at least once: a stop or a
crash before the client records the expiry runs it again for the same
`workId`. The client sends no delivery receipt and no retry request for
expired content.

#### Parameters

##### event

[`ReceiveExpiredEvent`](ReceiveExpiredEvent.md)

The expired content, without its plaintext

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onReceiveExpired: async (event) => {
  await messageStore.markLost(event.messageId ?? event.workId);
}
```

***

### onRelayProtocolError?

> `optional` **onRelayProtocolError?**: (`error`) => `void` \| `Promise`\<`void`\>

Runs once for a completed send whose Relay accepted a declared post
without the `deviceSetChecked` mark. A declared post is a post to a
recipient device or a sync copy to another device of the own account.

The client declares the device set of each recipient account only to a
Relay that compares device sets. Such a Relay marks each post that it
compared. An accepted post without the mark is a Relay defect: the Relay
did not check the declared devices. The send is delivered, so its result
does not change and the client does not post it again. The error carries
the code `DEVICE_SET_UNCHECKED`, the `clientMessageId` of the send, and
the route of the post. The route is `identified-direct`,
`anonymous-direct`, or `anonymous-group`. A sync copy is an
`identified-direct` post. The client also logs one warning with the code
and the route.

The hook also runs once for a sync payload of a method such as
`syncReadToLinkedDevices`. That error has no `clientMessageId`.

The hook runs after the send completes. An error from the hook does not
change the send result. The client logs the error.

#### Parameters

##### error

[`RelayProtocolError`](../classes/RelayProtocolError.md)

The protocol error of the send

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onRelayProtocolError: (error) => {
  monitoring.report('relay-protocol', { code: error.code, route: error.route });
}
```

***

### onRetryTerminal?

> `optional` **onRetryTerminal?**: (`event`) => `void` \| `Promise`\<`void`\>

Runs when a retry request ends with no resend

A failed decrypt asks the sender device for a resend. The request ends
when the Relay gives a conclusive answer to its post, when it does not
get its content before its deadline, 14 days after the first failure,
when a post of it is due at or after its posting deadline, 24 hours
after the first failure, when the Relay refuses its post with
OPERATION_EXPIRED, when the resend of the fifth attempt also fails, when the sender used up
its retry allowance, when the sender device has no prekey bundle of the
requester, or when the sender device refuses group content to a
requester that is not a current member of the group. The content of the
failed envelope is then lost. The hook runs at least once for each
request. The SDK marks the end emitted only after the hook returns. A
hook that throws, a client stop during the hook, or a crash leaves the
end not emitted, and the hook runs again at the next retry request pass,
start, or redelivery. Make the hook idempotent for one
`failedEnvelopeId`.

Before the hook, an `expired-content` or `posting-deadline` end resets
the session with the device that sent the failed envelope, and
`event.recovery` tells what the reset did. The other classes, and a post
that fails and can be posted again, reset nothing. `onSessionArchived`
runs for the archive.

A `posting-deadline` end posts no replacement request. The session
resets, and the request might have arrived at the sender. A request
whose post the Relay accepted posts nothing after its posting deadline,
and waits for its content until its deadline.

#### Parameters

##### event

[`RetryTerminalEvent`](RetryTerminalEvent.md)

The class of the end, the failed envelope, and the reset

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onRetryTerminal: async (event) => {
  await messageStore.markUndecryptable(event.failedEnvelopeId, event.class);
}
```

***

### onSendOutcome?

> `optional` **onSendOutcome?**: (`event`) => `void` \| `Promise`\<`void`\>

Runs once for each end of a send

A send ends when the Relay accepts it (`completed`), or at its posting
deadline (`failed` or `acceptance-unknown`). With a store that implements
`listMetadataKeys`, as every built-in store does, the SDK replays each
open send at start and when the Relay connection returns, until its
deadline, and the hook reports each end of that replay. The hook also
reports each end of a `send()` call of the application, before the call
returns or throws. A replay of a send that already ended reports nothing.

The driver also reports `content-required` once for each client run
when it cannot find the plaintext of an open send. The send stays open,
and its end at the deadline is reported too.

An event can carry the ID of a sender key distribution that an earlier
SDK version stored, which the application never sent. Ignore an ID that
the application does not know.

The hook runs at most once for each end. The driver records the report
before it calls the hook, so a crash or a client stop between the two
loses the event. A crash before that record reports the end at the next
start. A hook that throws is logged, and it does not run again for that
end. The `send()` call still returns or throws its own result.

#### Parameters

##### event

[`SendOutcomeEvent`](SendOutcomeEvent.md)

The client message ID, the outcome and the deadline of the send

#### Returns

`void` \| `Promise`\<`void`\>

#### Example

```typescript
onSendOutcome: async (event) => {
  if (event.outcome === 'completed') await messageStore.markSent(event.clientMessageId);
  else if (event.outcome === 'content-required') await messageStore.resend(event.clientMessageId);
  else await messageStore.markFailed(event.clientMessageId, event.outcome);
}
```

***

### onSessionArchived?

> `optional` **onSessionArchived?**: (`sessionId`) => `void` \| `Promise`\<`void`\>

Runs after the client archives a session (moved to inactive list)

Stale-device recovery archives the session so delayed messages can still
attempt decryption. When the recovery refreshes the session of a receipt
or a retry request, the new session archives the stale one in the same
write, and the hook runs after that session start succeeds. A failure
in the SESAME registration after that write keeps the new session and
runs no hook.
Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"

#### Parameters

##### sessionId

`string`

The identifier of the archived session

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

Runs after the client deletes a session

#### Parameters

##### sessionId

`string`

The identifier of the deleted session

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

Runs when the client receives a typing indicator

Allows the app to update UI with the users who type.
Typing indicators are transient - they auto-expire after 15 seconds.

#### Parameters

##### senderId

`string`

The user who sent the typing indicator

##### conversationId

`string`

The conversation the typing indicator belongs to

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

Runs when the client receives a viewed receipt (e.g., view-once media)

Allows the app to update message status to 'viewed'.
The timestamps array contains server timestamps of viewed messages.

#### Parameters

##### senderId

`string`

The user who sent the viewed receipt (message recipient who viewed media)

##### timestamps

`number`[]

Array of message timestamps for the viewed messages

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

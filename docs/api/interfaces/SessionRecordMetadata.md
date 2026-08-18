[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SessionRecordMetadata

# Interface: SessionRecordMetadata

Metadata for a session record.

Combines UI/management metadata with SESAME session lifecycle tracking.
This lets the SESAME layer use SessionRecord directly, without a separate
SesameSessionRecord wrapper.

## See

https://signal.org/docs/specifications/sesame/

## Properties

### createdAt?

> `optional` **createdAt?**: `number`

Timestamp of the moment this session began (milliseconds since epoch).
Used for session expiration calculations (MAXSEND, MAXRECV thresholds).

#### See

SESAME spec Section 4.2 (Session expiration)

***

### isActive?

> `optional` **isActive?**: `boolean`

Whether this session counts as active

***

### isInitiator?

> `optional` **isInitiator?**: `boolean`

Whether we created this session (initiating) or they did (responding).
Initiator sends PreKeyMessages until first response received.

#### See

SESAME spec Section 2.2 (Session creation for senders/recipients)

***

### label?

> `optional` **label?**: `string`

Human-readable label for debugging

***

### lastReceivedAt?

> `optional` **lastReceivedAt?**: `number` \| `null`

Timestamp when this session last successfully received/decrypted a message.
Null if never used to receive. Used for MAXRECV expiration check.

#### See

SESAME spec Section 4.2 (Session expiration)

***

### lastSentAt?

> `optional` **lastSentAt?**: `number` \| `null`

Timestamp when this session was last used to send a message.
Null if never used to send. Used for MAXSEND expiration check.

#### See

SESAME spec Section 4.2 (Session expiration)

***

### lastUsedAt?

> `optional` **lastUsedAt?**: `number`

When the current session was last used

***

### messagesReceived?

> `optional` **messagesReceived?**: `number`

Total number of messages received in current session

***

### messagesSent?

> `optional` **messagesSent?**: `number`

Total number of messages sent in current session

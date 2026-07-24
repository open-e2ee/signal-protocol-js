[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SessionHealthResult

# Interface: SessionHealthResult

Result from session health check

Provides detailed diagnostics about session state, key validity,
and any issues that may affect encryption.

## Properties

### checkedAt

> **checkedAt**: `number`

When this check was performed

***

### issues

> **issues**: `SessionHealthIssue`[]

List of issues found

***

### keyStatus

> **keyStatus**: `object`

Key status information

#### hasIdentityKey

> **hasIdentityKey**: `boolean`

#### hasKyberPreKey

> **hasKyberPreKey**: `boolean`

#### hasSignedPreKey

> **hasSignedPreKey**: `boolean`

#### kyberPreKeyAgeDays

> **kyberPreKeyAgeDays**: `number`

#### needsRotation

> **needsRotation**: `boolean`

#### signedPreKeyAgeDays

> **signedPreKeyAgeDays**: `number`

***

### message

> **message**: `string`

Summary message for UI display

***

### sessionExists

> **sessionExists**: `boolean`

Whether a session exists with this user

***

### sessionStatus?

> `optional` **sessionStatus?**: `object`

Session-specific status (only if session exists)

#### ageDays

> **ageDays**: `number`

#### createdAt

> **createdAt**: `number`

#### isExpiredForReceiving

> **isExpiredForReceiving**: `boolean`

#### isExpiredForSending

> **isExpiredForSending**: `boolean`

#### lastUsedAt

> **lastUsedAt**: `number`

#### messagesReceived

> **messagesReceived**: `number`

#### messagesSent

> **messagesSent**: `number`

***

### status

> **status**: `SessionHealthStatus`

Overall health status

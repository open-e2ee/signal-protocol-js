[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionState](../README.md) / getSessionId

# Function: getSessionId()

> **getSessionId**(`session`): `string`

Returns the session identifier for display and logging.

This is the SESAME SessionID concept - a human-readable string
that identifies which remote device this session is with.
Format: "userId:deviceId" (equals ProtocolAddress.toString(remoteAddress))

Note: For cryptographic state identification, use `baseKey` instead.
The baseKey distinguishes multiple session instances with the same device.

## Parameters

### session

[`SessionState`](../../../interfaces/SessionState.md)

## Returns

`string`

## See

https://signal.org/docs/specifications/sesame/

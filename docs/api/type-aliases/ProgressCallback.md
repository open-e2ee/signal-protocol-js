[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ProgressCallback

# Type Alias: ProgressCallback

> **ProgressCallback** = (`progress`) => `void`

Progress callback for initialization operations

## Parameters

### progress

#### detail?

\{ `current`: `number`; `total`: `number`; \}

Optional sub-stage progress for granular UI (e.g., "32 of 100 keys")

#### detail.current

`number`

#### detail.total

`number`

#### message

`string`

#### percent

`number`

#### stage

`"generating-keys"` \| `"generating-kyber"` \| `"uploading"` \| `"complete"`

## Returns

`void`

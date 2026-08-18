[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / UserRecord

# Interface: UserRecord

Record of a remote user and all their devices
Top-level organizational structure in SESAME

## Properties

### createdAt

> **createdAt**: `number`

Timestamp of the moment this user record began

***

### deviceListVersion?

> `optional` **deviceListVersion?**: `number`

Server's device list version for this user
Used for Phase 3 validation to detect stale device lists

#### See

SESAME spec §3.3 (Sending Messages - Phase 3)

***

### devices

> **devices**: `Map`\<`number`, [`DeviceRecord`](DeviceRecord.md)\>

Map of device ID to device record
Contains all known devices for this user

***

### stale?

> `optional` **stale?**: `boolean`

Whether this UserRecord's device list is stale and needs a fresh fetch.
Set to true when sending meets a StaleDeviceListError.
When true, the next send operation should refetch the device list before proceeding.
Cleared after a successful device list sync.

#### See

SESAME spec §3.3 (Sending Messages - Phase 3)

***

### updatedAt

> **updatedAt**: `number`

Timestamp when this user record was last updated

***

### userId

> **userId**: `string`

Unique user identifier

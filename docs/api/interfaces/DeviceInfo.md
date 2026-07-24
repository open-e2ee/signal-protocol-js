[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceInfo

# Interface: DeviceInfo

Device info returned by getDevices()

## Properties

### active

> **active**: `boolean`

Whether device is currently online (system-controlled)

***

### createdAt

> **createdAt**: `number`

***

### deviceId

> **deviceId**: `number`

***

### deviceType?

> `optional` **deviceType?**: [`DeviceType`](../type-aliases/DeviceType.md)

***

### enabled

> **enabled**: `boolean`

Whether device can receive messages (user-controlled)

***

### encryptedDeviceName?

> `optional` **encryptedDeviceName?**: `ArrayBuffer`

***

### lastSeen

> **lastSeen**: `number`

***

### linked

> **linked**: `boolean`

Secondary device linked to primary (always false for primary deviceId=1)

***

### linkedAt?

> `optional` **linkedAt?**: `number`

When the device was linked (for secondary devices)

***

### registered

> **registered**: `boolean`

Device completed setup (has keys) - false = soft deleted

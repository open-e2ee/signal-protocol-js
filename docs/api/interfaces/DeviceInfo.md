[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceInfo

# Interface: DeviceInfo

Device info returned by getDevices()

## Properties

### active?

> `optional` **active?**: `boolean`

Whether device is currently online, when the relay exposes presence.

***

### createdAt?

> `optional` **createdAt?**: `number`

Registration time, when the relay exposes device observations.

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

### lastSeen?

> `optional` **lastSeen?**: `number`

Last observed activity, when the relay exposes device observations.

***

### linked

> **linked**: `boolean`

Secondary device linked to primary (always false for primary deviceId=1)

***

### linkedAt?

> `optional` **linkedAt?**: `number`

When the user linked the device (for secondary devices)

***

### registered

> **registered**: `boolean`

Device completed setup (has keys) - false = soft deleted

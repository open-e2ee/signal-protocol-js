[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceSetUnresolved

# Interface: DeviceSetUnresolved

The terminal record of a phase that ended without reconciliation.

## Properties

### lastRefusal?

> `readonly` `optional` **lastRefusal?**: [`DeviceSetLastRefusal`](DeviceSetLastRefusal.md)

Absent when the phase resumed from a stored count and ended before a refusal.

***

### phase

> `readonly` **phase**: [`DeviceSetPhase`](../type-aliases/DeviceSetPhase.md)

***

### reason

> `readonly` **reason**: [`DeviceSetUnresolvedReason`](../type-aliases/DeviceSetUnresolvedReason.md)

***

### restarts

> `readonly` **restarts**: `number`

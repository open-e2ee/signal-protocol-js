[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PreKeyPublicationPlan

# Type Alias: PreKeyPublicationPlan

> **PreKeyPublicationPlan** = (`inventory`) => `Promise`\<readonly [`PreKeyUpload`](../interfaces/PreKeyUpload.md)[]\>

The uploads one rotation decision calls for, decided from the inventory the
relay adapter read for it. The adapter publishes the returned uploads in one
publication. An empty array publishes nothing.

## Parameters

### inventory

[`PreKeyInventory`](../interfaces/PreKeyInventory.md)

## Returns

`Promise`\<readonly [`PreKeyUpload`](../interfaces/PreKeyUpload.md)[]\>

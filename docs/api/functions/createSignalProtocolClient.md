[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / createSignalProtocolClient

# Function: createSignalProtocolClient()

> **createSignalProtocolClient**(`options`): `Promise`\<[`SignalProtocolClient`](../classes/SignalProtocolClient.md)\>

Create and initialize a Signal Protocol client from the app-facing composition shape.

This is the recommended entry point for application code.

## Parameters

### options

[`SignalProtocolClientCompositionOptions`](../interfaces/SignalProtocolClientCompositionOptions.md)

## Returns

`Promise`\<[`SignalProtocolClient`](../classes/SignalProtocolClient.md)\>

## Example

```typescript
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';

const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});

await signal.send('bob', 'hello');
```

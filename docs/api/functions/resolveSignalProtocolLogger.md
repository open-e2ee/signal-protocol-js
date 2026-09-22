[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / resolveSignalProtocolLogger

# Function: resolveSignalProtocolLogger()

> **resolveSignalProtocolLogger**(`logger?`): `Required`\<[`Logger`](../interfaces/Logger.md)\>

Logging utilities for app composition

Pass a logger into `createSignalProtocolClient()` to route Signal Protocol logs through
your app logger or custom diagnostics pipeline.

## Parameters

### logger?

[`Logger`](../interfaces/Logger.md)

## Returns

`Required`\<[`Logger`](../interfaces/Logger.md)\>

## Example

**Using custom logger with DefaultSignalProtocolClient**

```typescript
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';

const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage },
  logger: {
    info: (msg, data) => myLogger.log('info', msg, data),
    error: (msg, err) => myLogger.log('error', msg, err),
    warn: (msg, data) => myLogger.log('warn', msg, data)
  }
});
```

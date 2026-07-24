[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ProtocolAddress

# Interface: ProtocolAddress

Protocol Address for type-safe device addressing

ProtocolAddress represents a unique device in the Signal Protocol.
Format: userId:deviceId (e.g., "bob:1" for Bob's first device)

## Example

```typescript
import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';

const bob = ProtocolAddress.create('bob', 1);
const parsed = ProtocolAddress.parse('alice:2');
const str = ProtocolAddress.toString(bob); // "bob:1"
```

## Properties

### deviceId

> `readonly` **deviceId**: `number`

Device identifier (unique per user, typically 1 for primary device)

***

### userId

> `readonly` **userId**: `string`

User identifier (UUID, username, or application-specific ID)

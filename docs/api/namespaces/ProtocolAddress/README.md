[**@open-e2ee/signal-protocol-sdk**](../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../README.md) / ProtocolAddress

# ProtocolAddress

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

## Functions

- [create](functions/create.md)
- [equals](functions/equals.md)
- [fromStorageKey](functions/fromStorageKey.md)
- [isUser](functions/isUser.md)
- [isValid](functions/isValid.md)
- [parse](functions/parse.md)
- [toStorageKey](functions/toStorageKey.md)
- [toString](functions/toString.md)

[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / acceptContactIdentityRotation

# Function: acceptContactIdentityRotation()

> **acceptContactIdentityRotation**(`record`, `candidate`, `now`, `suppliedCommitment?`): [`ContactIdentityRecord`](../interfaces/ContactIdentityRecord.md)

Explicit user/application acceptance path; automatic save must not call this.

## Parameters

### record

[`ContactIdentityRecord`](../interfaces/ContactIdentityRecord.md)

### candidate

[`CompositeIdentityV1`](../interfaces/CompositeIdentityV1.md)

### now

`number`

### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

## Returns

[`ContactIdentityRecord`](../interfaces/ContactIdentityRecord.md)

[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / unverifyContactIdentityRecord

# Function: unverifyContactIdentityRecord()

> **unverifyContactIdentityRecord**(`record`, `candidate`, `now`): [`ContactIdentityRecord`](../interfaces/ContactIdentityRecord.md)

Clear the verification of the exact current tuple. The pin, its revision,
and its rollback history stay. A record that is not verified comes back
unchanged.

## Parameters

### record

[`ContactIdentityRecord`](../interfaces/ContactIdentityRecord.md)

### candidate

[`CompositeIdentityV1`](../interfaces/CompositeIdentityV1.md)

### now

`number`

## Returns

[`ContactIdentityRecord`](../interfaces/ContactIdentityRecord.md)

## Throws

Error when `candidate` is not the current tuple of `record`

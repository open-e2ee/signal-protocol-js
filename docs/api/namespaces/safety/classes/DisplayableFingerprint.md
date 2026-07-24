[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / DisplayableFingerprint

# Class: DisplayableFingerprint

Displayable fingerprint for manual verification.

Represents the fingerprint as a 60-digit numeric string formatted
in groups of 5 digits for easy reading and comparison.

## Example

```typescript
const displayable = fingerprint.displayable();
console.log(displayable.toString());
// "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
```

## Constructors

### Constructor

> **new DisplayableFingerprint**(`numeric`): `DisplayableFingerprint`

Create a DisplayableFingerprint.

#### Parameters

##### numeric

`string`

60-digit numeric string

#### Returns

`DisplayableFingerprint`

## Methods

### equals()

> **equals**(`other`): `boolean`

Compare this fingerprint with another.

#### Parameters

##### other

`DisplayableFingerprint`

Another DisplayableFingerprint

#### Returns

`boolean`

true if fingerprints match

***

### formatted()

> **formatted**(): `string`

Get formatted fingerprint with grouping for readability.

Formats as groups of 5 digits separated by spaces.

#### Returns

`string`

Formatted string like "12345 67890 12345 ..."

***

### getGroups()

> **getGroups**(): `string`[]

Get individual digit groups for UI display.

Returns array of 12 groups of 5 digits each.

#### Returns

`string`[]

Array of 12 digit groups

***

### toString()

> **toString**(): `string`

Get the raw 60-digit string.

#### Returns

`string`

60-digit numeric string

[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KeyTransparencyFailureEvent

# Type Alias: KeyTransparencyFailureEvent

> **KeyTransparencyFailureEvent** = \{ `detectedAt`: `number`; `error`: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md); `subject`: `"contact"`; `userId`: `string`; \} \| \{ `detectedAt`: `number`; `error`: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md); `subject`: `"self"`; \}

A key transparency check that failed.

- `subject: 'contact'`: the check of a contact identity that the client
  fetched. `userId` is the contact. The client raises one event for each
  failed `(userId, identity)` pair for the life of the client. A key
  mismatch or a not-logged result raises the event only when a second
  check 2 hours later gives one of them again.
- `subject: 'self'`: the weekly check of the own account. The client
  raises the event on the second consecutive failure, once for each
  failing streak. A not-logged result is a failure.
- A pending append raises the event only when the append still waits 24
  hours after the first pending result.

A failed check never refuses a send. A result that the client cannot get,
such as a network error, raises no event.

## Union Members

### Type Literal

\{ `detectedAt`: `number`; `error`: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md); `subject`: `"contact"`; `userId`: `string`; \}

#### detectedAt

> `readonly` **detectedAt**: `number`

The local time of the failure, Unix milliseconds.

#### error

> `readonly` **error**: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md)

The failure. `error.code` names the step that failed.

#### subject

> `readonly` **subject**: `"contact"`

#### userId

> `readonly` **userId**: `string`

The contact whose identity failed the check.

***

### Type Literal

\{ `detectedAt`: `number`; `error`: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md); `subject`: `"self"`; \}

#### detectedAt

> `readonly` **detectedAt**: `number`

The local time of the failure, Unix milliseconds.

#### error

> `readonly` **error**: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md)

The failure. `error.code` names the step that failed.

#### subject

> `readonly` **subject**: `"self"`

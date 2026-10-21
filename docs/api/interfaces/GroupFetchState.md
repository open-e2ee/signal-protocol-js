[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupFetchState

# Interface: GroupFetchState

The fetch backoff and the last verified denial of one group.

## Properties

### attempts

> **attempts**: `number`

Consecutive fetches that reached no head, or that the server denied.
Zero after a fetch reaches the server head.

***

### denied?

> `optional` **denied?**: `object`

The last verified denial, and the highest claim it answered: the claim
of its fetch or the required revision then, whichever is higher.

#### atRevision

> **atRevision**: `number`

#### reason

> **reason**: [`GroupFetchDenial`](../type-aliases/GroupFetchDenial.md)

***

### fetchedClaims?

> `optional` **fetchedClaims?**: `number`[]

The claimed revisions already fetched in the current window.

***

### head?

> `optional` **head?**: `number`

The server head that the last fetch reached. A failed fetch clears it.

***

### nextAttemptAt

> **nextAttemptAt**: `number`

The end of the current backoff window, in epoch milliseconds.

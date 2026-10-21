[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ReceiveQueuePolicy

# Interface: ReceiveQueuePolicy

The receive queue policy of a client.

## Properties

### blockedGroupShare?

> `optional` **blockedGroupShare?**: `number`

The part of `maxItems` and `maxBytes` that the waiting records of one
group can fill. A sender-key message of a group at its part is not
decrypted, so other conversations keep room. Pairwise group content
counts toward its group after decrypt. The value must be above 0 and at
most 1.

#### Default

```ts
0.25
```

***

### maxBytes?

> `optional` **maxBytes?**: `number`

The most plaintext bytes that the queue holds. It acts as `maxItems`.

#### Default

```ts
786432000 (750 MiB)
```

***

### maxItems?

> `optional` **maxItems?**: `number`

The most receive records that the queue holds. At the bound, the client
decrypts nothing more and does not acknowledge the message, so the
Relay keeps it. A message that the Relay keeps expires at the TTL of
the Relay project, and no local hook reports that expiry. While the
mailbox of the device is full, the Relay refuses a new message to it
with `MAILBOX_FULL` to its sender. The value is provisional until a
measurement sets it.
Two processes over one store, such as two tabs, can each pass the check
and overshoot it.

#### Default

```ts
3000
```

***

### receiveHookTimeoutMs?

> `optional` **receiveHookTimeoutMs?**: `number`

The longest time, in milliseconds, that a receive pass waits for one
hook, such as `onMessageDecrypted`. At the bound, the client logs `RECEIVE_HOOK_TIMEOUT` and stops waiting for
the call. A timeout of `onMessageDecrypted` or `onDelivered` counts as
one failed attempt, so the content runs again after the backoff. A
timeout of another hook ends that call, and the pass continues. The
client ignores a result that the call gives after the bound. The value
must be a positive integer of at most 2147483647 ms.

#### Default

```ts
120000 (2 minutes)
```

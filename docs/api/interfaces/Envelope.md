[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / Envelope

# Interface: Envelope

Envelope for delivery.

Server treats ciphertext as opaque bytes (zero-knowledge).

## Properties

### ciphertext

> **ciphertext**: `string` \| `Uint8Array`\<`ArrayBufferLike`\>

Encrypted payload (base64 or Uint8Array)

***

### clientMessageId?

> `optional` **clientMessageId?**: `string`

Stable client-generated send identifier for idempotent retry.

If a client retries after an unknown relay result, it should reuse the
same value. The relay then returns the original accept metadata, instead
of inserting a duplicate pending envelope.

MUST be globally unique. A UUID, not a counter or timestamp. On the
identified path the relay scopes deduplication by sender. A sealed sender
is anonymous by design, so every sealed send to a device shares one dedup
namespace. Two sealed senders reusing the same value would silently
collapse into one stored message. The second sender would receive the
first message's receipt.

A relay that assigns its own `id` delivers this value with the
envelope. A retry request names its attempt here.

***

### contentHint?

> `optional` **contentHint?**: [`ContentHint`](../enumerations/ContentHint.md)

The content hint of the sender. It sets what the receiver does when a
decrypt fails with an error that a resend can repair.

- `Default`: the client sends a retry request and runs
  `onDeliveryError` at once.
- `Resendable`: the client sends a retry request. It runs
  `onDeliveryError` one hour after the receive
  (`RETRY_PLACEHOLDER_DEADLINE_MS`) if the content has not arrived. It
  runs it at once when a rate limit refuses the request, when the
  request allowance for the sender is used up, or when the request
  ends.
- `Implicit`: disposable content, such as typing indicators and
  receipts. The client sends no retry request and never runs
  `onDeliveryError`. A resend that answers a retry request of this
  device still asks again.

With no hint, the client uses the `Default` behavior.

***

### contentKind?

> `optional` **contentKind?**: [`ContentKind`](../type-aliases/ContentKind.md)

Cleartext label that a relay can count by. The SDK sets `receipt` on
each E2EE receipt that it sends. An envelope without it is a `message`.

***

### declaredDeviceIds?

> `optional` **declaredDeviceIds?**: readonly `number`[]

The device IDs that the sender declares for the target account, sent as
the wire field `deviceSets` with one entry for `targetUserId`. A sync
copy to the sender's own account leaves out the sender device. A relay
that compares refuses the post with `DEVICE_SET_MISMATCH` when the
declared set differs from the account's device list, and with a
declared `STALE_DEVICE` when a registration changed. Without it, the
relay does not compare.

***

### deliveryClass

> **deliveryClass**: [`DeliveryClass`](../type-aliases/DeliveryClass.md)

Exact persistence and wake behavior for this encrypted envelope.

***

### id?

> `optional` **id?**: `string`

Server-assigned envelope ID (set by server). A relay gives an envelope
one `id` and keeps it on every redelivery of that envelope. The client
records each processed envelope by this `id`, so a redelivery decrypts
no second time, and the content hook carries it as `messageId` for
application deduplication. Hook delivery is at least once.

***

### messageType

> **messageType**: `"ciphertext"` \| `"prekey_bundle"` \| `"sender_key"` \| `"unidentified_sender"` \| `"retry_request"`

Relay-visible envelope type.
A ciphertext envelope holds the client-to-client types (delivery_receipt,
typing_indicator, sender_key_distribution) as encrypted content types. The
relay contract carries only the outer envelope type.

- ciphertext: Standard Double Ratchet message (contains encrypted Content)
- prekey_bundle: Session initiation (PQXDH)
- sender_key: Group message encrypted with sender keys
- unidentified_sender: Sealed sender protocol messages
- retry_request: A request that the original sender device resend a
  message that the requester could not decrypt. The payload is not
  encrypted. The envelope sender is the requester.

`sender_key` tells the receiver to decrypt the payload as a framed
SenderKeyMessage rather than as a pairwise ratchet message. It names no
group: the receiver reads the opaque distribution identifier out of the
frame and resolves the group from its own sender key store. The relay
therefore learns that an envelope is group traffic, which its fan-out
pattern already implies, but not which group.

***

### operationEpochMilliseconds?

> `optional` **operationEpochMilliseconds?**: `number`

The operation epoch that the relay admits the post by. Without it, the
relay uses `timestamp`. A retry resend keeps the original `timestamp`, so
it posts the time of its first attempt here.

***

### recipientRegistrationId?

> `optional` **recipientRegistrationId?**: `number`

The registration ID of the recipient device's current session. All six
post kinds name it: a direct message, a sync copy, a sender-key
distribution, a group device message, a receipt, and a retry request.
A post to a device with no session names none.
Server validates this matches recipient's current registration.
If mismatch (device reinstalled), server returns STALE_DEVICE error (equivalent to HTTP 410).

***

### senderDeviceId

> **senderDeviceId**: `number`

Sender device ID

***

### senderUserId

> **senderUserId**: `string`

Sender user ID

***

### serverTimestamp?

> `optional` **serverTimestamp?**: `number`

Server timestamp (set by server)

***

### targetDeviceId

> **targetDeviceId**: `number`

Target device ID (1-5)

***

### targetUserId

> **targetUserId**: `string`

Target user ID

***

### timestamp

> **timestamp**: `number`

Client timestamp for message identification.
Set by sender BEFORE encryption. Same value embedded in dataMessage.timestamp.
Used for: retry request matching, delivery receipt correlation, replay prevention.

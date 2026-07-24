[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SendOptions

# Interface: SendOptions

Options for SignalProtocolClient.send()

Extensible for future features like disappearing messages and threads.

## Properties

### attachment?

> `optional` **attachment?**: [`AttachmentTransferOptions`](AttachmentTransferOptions.md)

Upload/download lifecycle controls for attachment operations.

***

### blurHash?

> `optional` **blurHash?**: `string`

BlurHash for instant placeholder (~25 chars, base-83 encoded)

***

### caption?

> `optional` **caption?**: `string`

Caption text for attachment

***

### cdnNumber?

> `optional` **cdnNumber?**: `number`

Optional CDN number when the remote object backend distinguishes CDN tiers

***

### clientMessageId?

> `optional` **clientMessageId?**: `string`

Stable client-generated send identifier for retry idempotency.

Retries of the same logical send should reuse this value with the same
timestamp. Relay adapters that support it can return the original accept
result instead of inserting a duplicate envelope after an unknown result.

***

### clientUuid?

> `optional` **clientUuid?**: `string`

Optional client-generated media identifier for cross-device reconciliation

***

### contentHint?

> `optional` **contentHint?**: [`ContentHint`](../enumerations/ContentHint.md)

Content hint for recipient retry behavior.

Used for protocol/no-op payloads (for example NullMessage resend responses)
that should be treated as IMPLICIT and silently discarded on failure.

***

### durationMs?

> `optional` **durationMs?**: `number`

Media duration in milliseconds for video/audio attachments

***

### expiresIn?

> `optional` **expiresIn?**: `number`

Disappearing message duration in milliseconds (future feature)

***

### fileName?

> `optional` **fileName?**: `string`

Original file name

***

### flags?

> `optional` **flags?**: `number`

Media attachment flags bitmap, for example MediaAttachmentFlag.VoiceMessage

***

### groupMemberUserIds?

> `optional` **groupMemberUserIds?**: `string`[]

Pre-resolved group member user IDs (local-first member resolution).
The caller provides the member list from local SQLite since group membership
is not stored on the server. The cipher resolves these to device IDs via
relay.getActiveDevices().

***

### height?

> `optional` **height?**: `number`

Media height in pixels (for layout before download)

***

### isBinary?

> `optional` **isBinary?**: `boolean`

Marks Uint8Array content as binary file data (vs protobuf/text bytes).
When true with Uint8Array content, routes to blob encryption flow.

***

### isViewOnce?

> `optional` **isViewOnce?**: `boolean`

Whether this is a view-once attachment

***

### mimeType?

> `optional` **mimeType?**: `string`

MIME type for binary content (e.g., 'image/jpeg', 'application/pdf')

***

### replyTo?

> `optional` **replyTo?**: `string`

Message ID to reply to for thread support (future feature)

***

### thumbnail?

> `optional` **thumbnail?**: `string`

Base64-encoded preview thumbnail stored inside encrypted attachment metadata

***

### timestamp?

> `optional` **timestamp?**: `number`

Client timestamp for receipt matching.
Same timestamp should be stored locally for delivery receipt lookup.

***

### waveform?

> `optional` **waveform?**: `number`[]

Voice-message waveform samples, each represented as an integer from 0 to 255

***

### width?

> `optional` **width?**: `number`

Media width in pixels (for layout before download)

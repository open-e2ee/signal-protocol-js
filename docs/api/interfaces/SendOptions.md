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

The SDK generates this value when it is omitted. An application that
retries a failed send explicitly must reuse the identifier. If it also
supplies a timestamp, that timestamp must match the original send. The SDK
persists the exact encrypted transmission before it contacts the Relay, so
an unknown result never advances the protocol ratchet twice.

***

### clientUuid?

> `optional` **clientUuid?**: `string`

Optional client-generated media identifier for cross-device reconciliation

***

### contentHint?

> `optional` **contentHint?**: [`ContentHint`](../enumerations/ContentHint.md)

Content hint for recipient retry behavior.

Used for protocol/no-op payloads (for example NullMessage resend responses)
that the client treats as IMPLICIT and silently discards on failure.

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

Application user IDs of the group's members, for local-first fan-out.

**Required for every group send**. A group send without it throws rather
than delivering to nobody. The relay keeps no `groupId -> member` map by
design, so it cannot supply the roster. The SDK cannot derive it either.
Decrypted group state identifies members by ACI
(`DecryptedMember.aciBytes`), while the relay routes by application
`userId`, and only the application holds that mapping.

Resolve the roster from local group state, map each member's ACI to your
own account identifier, and pass the result. The cipher expands these to
devices via `relay.getActiveDevices()`.

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
Store the same timestamp locally for delivery receipt lookup.

***

### waveform?

> `optional` **waveform?**: `number`[]

Voice-message waveform samples, each represented as an integer from 0 to 255

***

### width?

> `optional` **width?**: `number`

Media width in pixels (for layout before download)

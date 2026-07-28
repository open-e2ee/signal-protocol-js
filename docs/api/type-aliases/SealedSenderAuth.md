[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SealedSenderAuth

# Type Alias: SealedSenderAuth

> **SealedSenderAuth** = \{ `type`: `"accessKey"`; `unidentifiedAccessKey`: `string`; \} \| \{ `groupSendToken`: `Uint8Array`; `recipientAciBytes`: `Map`\<`string`, `Uint8Array`\>; `type`: `"groupSendToken"`; \}

Discriminated union for sealed sender authentication.

Two auth paths for anonymous delivery:
- accessKey: Derived from recipient's profile key (pairwise messages)
- groupSendToken: ZK group send endorsement token (group messages)

## Union Members

### Type Literal

\{ `type`: `"accessKey"`; `unidentifiedAccessKey`: `string`; \}

***

### Type Literal

\{ `groupSendToken`: `Uint8Array`; `recipientAciBytes`: `Map`\<`string`, `Uint8Array`\>; `type`: `"groupSendToken"`; \}

#### groupSendToken

> **groupSendToken**: `Uint8Array`

#### recipientAciBytes

> **recipientAciBytes**: `Map`\<`string`, `Uint8Array`\>

ACI bytes per recipient user ID — the identities the token endorses.

The token is a signature over ACIs, not user IDs, and the relay
verifies it before reading any account. It therefore needs the
claimed ACI for each recipient up front; it then binds each claim to
the recipient's stored account after the token checks out. The
endorsement manager supplies these from its cache, which records the
exact identities the endorsements were issued over.

#### type

> **type**: `"groupSendToken"`

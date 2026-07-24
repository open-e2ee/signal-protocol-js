[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SealedSenderAuth

# Type Alias: SealedSenderAuth

> **SealedSenderAuth** = \{ `type`: `"accessKey"`; `unidentifiedAccessKey`: `string`; \} \| \{ `groupSendToken`: `Uint8Array`; `type`: `"groupSendToken"`; \}

Discriminated union for sealed sender authentication.

Two auth paths for anonymous delivery:
- accessKey: Derived from recipient's profile key (pairwise messages)
- groupSendToken: ZK group send endorsement token (group messages)

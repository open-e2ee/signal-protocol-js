[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ReceiveOutcome

# Type Alias: ReceiveOutcome

> **ReceiveOutcome** = [`ProcessedReceive`](../interfaces/ProcessedReceive.md) \| \{ `kind`: `"pending"`; `messageId`: `string`; `reason`: `string`; \} \| \{ `kind`: `"duplicate"`; \} \| \{ `kind`: `"null-message"`; \} \| \{ `kind`: `"denied"`; `reason`: `string`; \} \| \{ `kind`: `"refused"`; `persisted`: `false`; `reason`: `string`; \}

The outcome of `processIncomingEnvelope`.

- `processed`: the client gives the content. Save it, then call
  `completeReceive`, or pass `onPersist`. Acknowledge the envelope.
- `pending`: the client stored the content, and it waits for its group
  state. The client resumes it and `listPendingReceives({ ready: true })`
  lists it when it is ready. Acknowledge the envelope.
- `duplicate`: the client processed the envelope before, or the
  application already has its content. Acknowledge the envelope.
- `null-message`: the envelope carries no content. Acknowledge it.
- `denied`: the client refused the content and ran `onDecryptionError`,
  except for a group that the user blocked (reason `blocked`), which has
  no report. Acknowledge the envelope.
- `refused`: the receive queue has no room, so the client decrypted
  nothing. Do not acknowledge the envelope. Give it again later.

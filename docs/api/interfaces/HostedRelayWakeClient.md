[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayWakeClient

# Interface: HostedRelayWakeClient

## Methods

### processIncomingEnvelopes()

> **processIncomingEnvelopes**(`envelopes`, `options?`): `Promise`\<(\{ `envelope`: [`IncomingEnvelope`](IncomingEnvelope.md); `plaintext`: `string`; \} \| \{ `envelope`: [`IncomingEnvelope`](IncomingEnvelope.md); `error`: `Error`; \})[]\>

#### Parameters

##### envelopes

[`IncomingEnvelope`](IncomingEnvelope.md)[]

##### options?

[`ProcessEnvelopeOptions`](ProcessEnvelopeOptions.md)

#### Returns

`Promise`\<(\{ `envelope`: [`IncomingEnvelope`](IncomingEnvelope.md); `plaintext`: `string`; \} \| \{ `envelope`: [`IncomingEnvelope`](IncomingEnvelope.md); `error`: `Error`; \})[]\>

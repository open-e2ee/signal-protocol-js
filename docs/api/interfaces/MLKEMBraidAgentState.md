[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MLKEMBraidAgentState

# Interface: MLKEMBraidAgentState

Unified ML-KEM Braid agent state

The state name determines the current role — no `role` field needed.
This matches the `SPQR` pattern where the state variant
is the role.

Use isInAliceRole(state) / isInBobRole(state) to check current role.

## Extends

- `MLKEMBraidBaseState`

## Properties

### auth

> **auth**: `AuthenticatorState`

Authenticator state

#### Inherited from

`MLKEMBraidBaseState.auth`

***

### ct1?

> `optional` **ct1?**: `Uint8Array`\<`ArrayBufferLike`\>

First ciphertext component (960 bytes)

***

### ct1\_decoded?

> `optional` **ct1\_decoded?**: `Uint8Array`\<`ArrayBufferLike`\>

Decoded CT1 stored for combined MAC verification with CT2

***

### ct1\_for\_mac?

> `optional` **ct1\_for\_mac?**: `Uint8Array`\<`ArrayBufferLike`\>

CT1 copy stored for combined MAC computation with CT2 (libsignal authenticates ct1||ct2)

***

### ct1Decoder?

> `optional` **ct1Decoder?**: `DecoderState`

CT1 decoder state

***

### ct1Encoder?

> `optional` **ct1Encoder?**: `EncoderState`

CT1 encoder state

***

### ct2?

> `optional` **ct2?**: `Uint8Array`\<`ArrayBufferLike`\>

Second ciphertext component (128 bytes)

***

### ct2Decoder?

> `optional` **ct2Decoder?**: `DecoderState`

CT2 decoder state

***

### ct2Encoder?

> `optional` **ct2Encoder?**: `EncoderState`

CT2 encoder state

***

### dk?

> `optional` **dk?**: `Uint8Array`\<`ArrayBufferLike`\>

Decapsulation key (private, 2400 bytes)

***

### ek\_seed?

> `optional` **ek\_seed?**: `Uint8Array`\<`ArrayBufferLike`\>

Encapsulation key seed (32 bytes)

***

### ek\_vector?

> `optional` **ek\_vector?**: `Uint8Array`\<`ArrayBufferLike`\>

Encapsulation key vector (1152 bytes)

***

### ekDecoder?

> `optional` **ekDecoder?**: `DecoderState`

EK vector decoder state

***

### ekEncoder?

> `optional` **ekEncoder?**: `EncoderState`

EK vector encoder state

***

### encaps\_secret?

> `optional` **encaps\_secret?**: `Uint8Array`\<`ArrayBufferLike`\>

One-shot Encaps1 state; owned bytes are consumed and best-effort overwritten by Encaps2.

***

### epoch

> **epoch**: `bigint`

Current epoch number

#### Inherited from

`MLKEMBraidBaseState.epoch`

***

### headerDecoder?

> `optional` **headerDecoder?**: `DecoderState`

Header decoder state

***

### headerEncoder?

> `optional` **headerEncoder?**: `EncoderState`

Header encoder state

***

### hek?

> `optional` **hek?**: `Uint8Array`\<`ArrayBufferLike`\>

Specification HEK: SHA3-256(ek_seed || ek_vector)

***

### state

> **state**: `MLKEMBraidState`

Current state machine state

#### Inherited from

`MLKEMBraidBaseState.state`

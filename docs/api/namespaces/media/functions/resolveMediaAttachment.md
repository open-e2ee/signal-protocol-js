[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / resolveMediaAttachment

# Function: resolveMediaAttachment()

> **resolveMediaAttachment**(`attachment`, `options`): `Promise`\<[`ResolvedMediaAttachment`](../interfaces/ResolvedMediaAttachment.md)\>

Download, verify, and decrypt a Signal media attachment pointer.

This is the safe receive-side counterpart to attachment upload. It validates
pointer metadata, downloads opaque ciphertext from the object store, verifies
length and SHA-256 digest before decryption, then decrypts with the package's
streaming AEAD format.

## Parameters

### attachment

[`CreateMediaAttachmentPointerInput`](../type-aliases/CreateMediaAttachmentPointerInput.md)

### options

[`ResolveMediaAttachmentOptions`](../interfaces/ResolveMediaAttachmentOptions.md)

## Returns

`Promise`\<[`ResolvedMediaAttachment`](../interfaces/ResolvedMediaAttachment.md)\>

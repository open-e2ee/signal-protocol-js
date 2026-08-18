[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / downloadMediaAttachment

# Variable: downloadMediaAttachment

> `const` **downloadMediaAttachment**: (`attachment`, `options`) => `Promise`\<[`ResolvedMediaAttachment`](../interfaces/ResolvedMediaAttachment.md)\> = `resolveMediaAttachment`

Download, verify, and decrypt a Signal Protocol media attachment pointer.

This is the safe receive-side counterpart to attachment upload. It validates
pointer metadata, downloads opaque ciphertext from the object store, and
verifies length and SHA-256 digest before decryption. It then decrypts with
the package's streaming AEAD format.

## Parameters

### attachment

[`CreateMediaAttachmentPointerInput`](../type-aliases/CreateMediaAttachmentPointerInput.md)

### options

[`ResolveMediaAttachmentOptions`](../interfaces/ResolveMediaAttachmentOptions.md)

## Returns

`Promise`\<[`ResolvedMediaAttachment`](../interfaces/ResolvedMediaAttachment.md)\>

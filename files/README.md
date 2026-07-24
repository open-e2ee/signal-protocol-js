# Encrypted Files

The files module exposes streaming encryption and decryption for application
files and attachments.

## Why it exists

Large payloads should not be embedded directly in Signal Protocol messages.
The application encrypts bytes locally, uploads only ciphertext, and sends the
decryption key plus integrity metadata inside an end-to-end encrypted message.

## Usage

```ts
import {
  streamingDecrypt,
  streamingEncrypt,
} from "@open-e2ee/signal-protocol-sdk/files";

const encrypted = await streamingEncrypt(keyBytes, plaintextBytes);
const plaintext = await streamingDecrypt(
  keyBytes,
  encrypted.ciphertext,
  new Uint8Array(0),
  { segmentSize: encrypted.segmentSize },
);
```

For a complete attachment workflow with upload brokering, retries, pointer
validation, and cleanup, use the
[`media`](../media/README.md) module with a
[`SignalRemoteObjectStore`](../remote/object-store/README.md).

Applications remain responsible for file-system permissions, cache lifetime,
content rendering, and securely disposing of decrypted temporary files.

See the [API reference](../docs/api/README.md).

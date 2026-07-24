# Encoding

The encoding module provides the package's public byte, Base64, URL-safe
Base64, UTF-8, and hexadecimal conversion helpers.

## Why it exists

Protocol and adapter boundaries exchange both strings and bytes. A single
public codec surface prevents callers from depending on implementation-only
modules or silently mixing standard and URL-safe Base64.

## Usage

```ts
import {
  bytesToBase64,
  bytesToHex,
  bytesToUrlSafeBase64,
  hexToBytes,
  stringToBytes,
} from "@open-e2ee/signal-protocol-sdk/encoding";

const bytes = stringToBytes("hello");
const base64 = bytesToBase64(bytes);
const urlToken = bytesToUrlSafeBase64(bytes);
const roundTrip = hexToBytes(bytesToHex(bytes));
```

Treat encoded cryptographic values as opaque. Encoding changes representation;
it does not encrypt, authenticate, or validate the meaning of the bytes.

See the [API reference](../docs/api/namespaces/encoding/README.md).

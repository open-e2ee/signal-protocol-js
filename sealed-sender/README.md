# Sealed-Sender Access Keys

The sealed-sender module exposes delivery access-key derivation for backends
that support authenticated sender-anonymous envelope delivery.

## Why it exists

A relay may need to authorize delivery without learning sender identity from
the outer request. The access key is derived from profile-key material and can
be presented through the relay's sealed-sender authorization contract.

## Usage

```ts
import {
  ACCESS_KEY_BYTES,
  deriveAccessKey,
} from "@open-e2ee/signal-protocol-sdk/sealed-sender";

const accessKey = await deriveAccessKey(profileKey);

if (accessKey.length !== ACCESS_KEY_BYTES) {
  throw new Error("Unexpected sealed-sender access-key length");
}
```

The helper does not implement relay authorization by itself. The application
backend must validate credentials, enforce rate limits and abuse controls, and
avoid logging sensitive tokens.

See the [remote guide](../remote/README.md) and
[API reference](../docs/api/README.md).

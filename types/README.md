# Public Types

The types module contains the stable contracts shared by clients, stores,
relays, protocol addresses, messages, trust policy, errors, and protocol
configuration.

## Why it exists

Adapters can depend on public interfaces without importing concrete client or
implementation modules. Runtime helpers and branded encodings live beside the
contracts they validate.

## Usage

```ts
import type {
  ISignalProtocolLocalStore,
  ISignalProtocolClient,
  SignalProtocolConfig,
} from "@open-e2ee/signal-protocol-sdk/types";
import { ProtocolAddress } from "@open-e2ee/signal-protocol-sdk/types/address";
import { asBase64 } from "@open-e2ee/signal-protocol-sdk/types/utils";

const address = ProtocolAddress.create("bob", 1);
const encodedKey = asBase64(valueFromValidatedStorage);
```

TypeScript brands document validated representation; they do not validate at
runtime by themselves. Use the provided validators or validate at the
untrusted boundary before applying a brand.

Application code should prefer the narrowest package subpath and must not
import declarations from `internal/*`.

See the [interface guide](../docs/INTERFACES.md) and
[API reference](../docs/api/README.md).

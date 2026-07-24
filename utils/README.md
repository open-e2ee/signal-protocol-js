# Utilities

The utilities subpaths contain small framework-neutral helpers used by adapter
and application code.

## Why they exist

Cross-cutting behavior such as retry classification must remain consistent at
network and persistence boundaries without coupling callers to client
internals.

## Retry usage

```ts
import {
  isRetryableError,
  withRetry,
} from "@open-e2ee/signal-protocol-sdk/utils/retry";

const bundle = await withRetry(
  () => relay.fetchPreKeyBundle(userId, deviceId),
  {
    operationName: "fetch prekey bundle",
    maxRetries: 2,
  },
);
```

`withRetry()` uses bounded exponential backoff with optional jitter. Known
protocol and identity failures are not retried; transient network, timeout,
database-lock, and concurrency failures are.

Retrying is only safe when the operation is read-only or idempotent. The caller
must not wrap an arbitrary mutation without an idempotency contract.

See the [error-handling guide](../docs/ERROR_HANDLING.md) and
[API reference](../docs/api/README.md).

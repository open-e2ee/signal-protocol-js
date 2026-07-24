# Zero-Knowledge Credentials and Groups

The `zk` subpaths expose credential issuance, presentation, verification, and
group cryptographic primitives used by privacy-preserving application
features.

## Why it exists

These APIs deliberately sit below the high-level client. They let an
application prove authorized attributes or group membership without placing
group secrets and profile keys on the service.

## Usage

```ts
import {
  computeProfileKeyVersion,
  deriveGroupSecretParams,
  getGroupPublicParams,
} from "@open-e2ee/signal-protocol-sdk/zk/groups";

const secretParams = deriveGroupSecretParams(groupMasterKey);
const publicParams = getGroupPublicParams(secretParams);
const profileKeyVersion = computeProfileKeyVersion(
  profileKeyBytes,
  accountIdentifierBytes,
);
```

Credential issuers and verifiers must use one agreed parameter set, validate
expiration, and bind presentations to the intended application context. These
low-level APIs do not supply authentication, persistence, replay prevention, or
product authorization policy.

See the [groups guide](../groups/README.md), [protocol policy](../docs/PROTOCOL_POLICY.md),
and [API reference](../docs/api/README.md).

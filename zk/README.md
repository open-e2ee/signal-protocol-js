# Zero-Knowledge Credentials and Groups

The `zk` subpaths expose client credential requests, response verification,
presentation creation, and group cryptographic primitives.

## Why it exists

These APIs deliberately sit below the high-level client. They let an
application prove authorized attributes or group membership without placing
group secrets and profile keys on the service.

## Usage

<!-- doc-snippet:skip requires-external-context -->
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

Clients use trusted public parameters to verify credential responses and create
presentations. Credential issuance and server-side presentation checks belong
to the relay. The published package excludes server secret-key generation,
credential issuance, and server signing implementations.

See the [groups guide](../groups/README.md), [protocol policy](../docs/PROTOCOL_POLICY.md),
and [API reference](../docs/api/README.md).

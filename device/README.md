# Device Lifecycle, Linking, and Transfer

The device module contains the platform-bound workflows for device identity,
registration, QR-based account linking, device-name encryption, and encrypted
device-to-device state transfer.

## Why it exists

Signal Protocol sessions address individual devices. The application therefore
needs a lifecycle that coordinates a locally persisted device ID with the
authenticated backend's device registry.

The two onboarding operations are deliberately separate:

- **Provisioning** adds a linked device. It transfers account identity material
  and optional account metadata, but not existing sessions or message history.
- **Transfer** migrates local cryptographic state to replacement hardware. It
  can include identity keys, prekeys, and sessions in an encrypted backup.

The primary device uses ID `1`. The backend allocates linked device IDs from
`2` through `5`. A client must not choose its own linked-device ID.

## Platform requirements

The top-level device module currently uses Expo and React Native platform APIs.
Install the optional peer dependencies required by the exports you use. The
framework-neutral lifecycle core is available from:

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  DeviceLifecycleManager,
  type DeviceLifecycleDeps,
} from "@open-e2ee/signal-protocol-sdk/device/lifecycle";
```

`DeviceLifecycleManager` receives storage, generated backend references, key
operations, logging, and device metadata through `DeviceLifecycleDeps`. The
application remains responsible for authenticated backend functions and for
placing initialization in its own startup lifecycle.

## Device ID access

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  getDeviceId,
  preloadDeviceId,
} from "@open-e2ee/signal-protocol-sdk/device/device-id";

await preloadDeviceId();
const deviceId = await getDeviceId();
```

`getDeviceIdSync()` returns the cached value or the primary-device default. Use
it only after preload or in code that can safely tolerate that fallback.

## Link a device

The primary device creates a short-lived provisioning session:

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  generateProvisioningQR,
  provisionDevice,
} from "@open-e2ee/signal-protocol-sdk/device/provisioning";

const {
  sessionId,
  qrCodeUrl,
  ephemeralKeyPair,
} = await generateProvisioningQR(relay, userId);

await appQr.show(qrCodeUrl);

const { newDeviceEphemeralPublicKey } =
  await appProvisioning.waitForLinkedDevice(sessionId);

await provisionDevice(
  relay,
  appProfile,
  sessionId,
  ephemeralKeyPair.privateKey,
  newDeviceEphemeralPublicKey,
  userId,
  { identityStore, groupStateStore },
);
```

The new device parses the QR data, joins the session, and stores the encrypted
provisioning result:

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  connectToProvisioningSession,
  parseProvisioningQR,
  receiveProvisioningMessage,
} from "@open-e2ee/signal-protocol-sdk/device/provisioning";
// Reads `react-native` and `expo-constants`, so it is imported separately from
// the protocol itself. Off Expo, build the same four fields by hand.
import { getDeviceMetadata } from "@open-e2ee/signal-protocol-sdk/device/expo-metadata";

const {
  sessionId,
  primaryEphemeralPublicKey,
} = parseProvisioningQR(scannedQrCode);

const deviceMetadata = getDeviceMetadata("Alice's tablet");
const linkedKeys = await connectToProvisioningSession(
  relay,
  sessionId,
  deviceMetadata,
);

const provisioning = await receiveProvisioningMessage(
  relay,
  sessionId,
  linkedKeys.privateKey,
  primaryEphemeralPublicKey,
  {
    identityStore,
    localStateStore,
    groupStateStore,
    usernameStateStore,
    deviceMetadata,
  },
);

console.log(provisioning.deviceId);
```

Provisioning requires an ACI identity. It includes PNI identity and
group/username state only when the host application enables and supplies them.

## Transfer cryptographic state

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  prepareNewDeviceTransfer,
  prepareOldDeviceTransferWithBackup,
} from "@open-e2ee/signal-protocol-sdk/device";

const receiving = await prepareNewDeviceTransfer();
await appQr.show(receiving.qrCode);

const sending = await prepareOldDeviceTransferWithBackup(backupStorage);
const backup = await sending.getBackup(sessionIds);
```

The application owns transport selection, peer confirmation, progress UI,
interruption recovery, and wiping old-device state after a successful
replacement. Do not erase the old device before the new device validates and
durably restores the backup.

## Security boundaries

- Provisioning sessions expire after five minutes.
- Ephemeral ECDH keys derive the provisioning/transfer encryption keys.
- The SDK encrypts identity and backup material before it reaches a relay or
  transport.
- The QR channel authenticates the session only to the extent that the
  application protects what the user scans or shares.
- The SDK encrypts device names for backend storage.
- Backend authentication must bind registration, provisioning, unlink, and
  removal to the owning account.
- Account reset must clear the device-ID cache, platform secret storage, and
  protocol store as one product-level lifecycle.

See the [client guide](../client/README.md), [remote guide](../remote/README.md),
and [API reference](../docs/api/README.md).

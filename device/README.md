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
- **Transfer** sends the same identity-only provisioning bundle over an
  application-owned encrypted device-to-device channel. The receiving device
  generates fresh prekeys and sessions after import.

The primary device uses ID `1`. The backend allocates linked device IDs from
`2` through `5`. A client must not choose its own linked-device ID.

## Platform requirements

The shared device entries import no platform package. They keep the device ID
and lifecycle state in the `SignalProtocolLocalSecretVault` that the
application passes, and they take platform metadata as an input. They omit each
metadata field that the application does not supply.

Two platform entries read that metadata. Install the peers of the entry that
you use.

`@open-e2ee/signal-protocol-sdk/device/expo` reads `react-native` 0.83.6 or
later, `expo-constants` 55.0.7 or later, and `expo-device` 55.0.15 or later.

```sh
npx expo install react-native expo-constants expo-device
```

`@open-e2ee/signal-protocol-sdk/device/react-native` reads `react-native`
0.83.6 or later and `react-native-device-info` 15.0.1 or later.

```sh
npm install react-native react-native-device-info
```

The lifecycle core is available from:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { DeviceLifecycleManager } from "@open-e2ee/signal-protocol-sdk/device/lifecycle";
import { getDeviceLifecyclePlatform } from "@open-e2ee/signal-protocol-sdk/device/expo";
import { ExpoSecureStoreSignalProtocolSecretVault } from "@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store";

const manager = new DeviceLifecycleManager(userId, {
  vault: new ExpoSecureStoreSignalProtocolSecretVault(),
  convex,
  api,
  keyStorage,
  logger,
  ...getDeviceLifecyclePlatform(),
});
```

`DeviceLifecycleManager` takes the user ID and a `DeviceLifecycleDeps` object.
That object holds the secret vault, the Convex client, the generated backend
references, key operations, logging, and device metadata. The constructor
throws an `EncryptionError` with code `SECRET_VAULT_REQUIRED` when the vault
is absent. The application remains responsible for authenticated backend
functions and for placing initialization in its own startup lifecycle.

## Device ID access

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  getDeviceId,
  preloadDeviceId,
} from "@open-e2ee/signal-protocol-sdk/device/device-id";

await preloadDeviceId(secretVault);
const deviceId = await getDeviceId(secretVault);
```

Both functions read the device ID from the application's
`SignalProtocolLocalSecretVault`. With no vault, they throw an
`EncryptionError` with code `SECRET_VAULT_REQUIRED`.

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

The new device parses the QR data, joins the session, and then receives,
decrypts, and stores the provisioning message:

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  connectToProvisioningSession,
  parseProvisioningQR,
  receiveProvisioningMessage,
} from "@open-e2ee/signal-protocol-sdk/device/provisioning";
// Reads the local platform, so it is imported separately from the protocol
// itself. Use `./device/react-native` off Expo, or build the fields by hand.
import { getDeviceMetadata } from "@open-e2ee/signal-protocol-sdk/device/expo";

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
import { getTransferDeviceInfo } from "@open-e2ee/signal-protocol-sdk/device/expo";

const device = getTransferDeviceInfo();

const receiving = await prepareNewDeviceTransfer(device);
await appQr.show(receiving.qrCode);

const sending = await prepareOldDeviceTransferWithBackup(backupStorage, device);
const backup = await sending.getBackup();
```

The QR code and the backup carry only the metadata fields that `device`
supplies. Pass `{}` to send none.

The application owns transport selection, peer confirmation, progress UI,
interruption recovery, and wiping old-device state after a successful
replacement. Do not erase the old device before the new device validates and
durably restores the backup.

## Security boundaries

- Provisioning sessions expire after five minutes.
- Ephemeral ECDH keys derive the provisioning/transfer encryption keys.
- The SDK encrypts identity material before it reaches a relay or transport.
- Linked-device bundles never contain signed prekeys, one-time prekeys,
  ratchet sessions, sender-key state, message state, or retry outbox state.
- The QR channel authenticates the session only to the extent that the
  application protects what the user scans or shares.
- The SDK encrypts device names for backend storage.
- Backend authentication must bind registration, provisioning, unlink, and
  removal to the owning account.
- Account reset must clear the device-ID cache, platform secret storage, and
  protocol store as one product-level lifecycle.

See the [client guide](../client/README.md), [remote guide](../remote/README.md),
and [API reference](../docs/api/README.md).

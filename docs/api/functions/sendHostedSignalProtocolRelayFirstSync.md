[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / sendHostedSignalProtocolRelayFirstSync

# Function: sendHostedSignalProtocolRelayFirstSync()

> **sendHostedSignalProtocolRelayFirstSync**(`client`, `deviceId`, `bundle`, `options?`): `Promise`\<\{ `bundleId`: `string`; \}\>

Send a first-sync bundle from device 1 to a newly linked own device
(wire contract section 11.4). Call it after the new device joined, for
example when `hosted.onOwnDevicesChanged` reports the device as added.
The new device gets the bundle in `hosted.onFirstSync`.

The call encrypts one copy for the device. On a Relay that compares
device sets, the copy declares each own device. The Relay meters the
accepted copy as one message.

Serialized content of 140,000 bytes or less fits in the copy, also in
the first message to the new device, which carries the PQXDH material.
The encrypted copy is about 1.8 times the serialized content. Larger
content can fail with a `RangeError` after the encryption.

The call is not idempotent. Each call gives a new bundle ID, and the new
device applies each new bundle that is not older than the newest bundle
that it applied.

## Parameters

### client

[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

The client of device 1

### deviceId

`number`

The device ID of the new device. A safe integer of 2 or
  more.

### bundle

[`HostedSignalProtocolRelayFirstSyncBundle`](../interfaces/HostedSignalProtocolRelayFirstSyncBundle.md)

The snapshot. It has at least one part.

### options?

[`HostedSignalProtocolRelayFirstSyncOptions`](../interfaces/HostedSignalProtocolRelayFirstSyncOptions.md) = `{}`

## Returns

`Promise`\<\{ `bundleId`: `string`; \}\>

The ID of the bundle: 16 random bytes, as base64url with no
  padding

## Throws

HostedSignalProtocolRelayDeviceProvisioningError `NOT_PRIMARY`
  when the client is not device 1, `DEVICE_NOT_FOUND` when the own device
  list does not hold the device or the Relay accepted no copy for it, and
  `CANCELLED` when the signal fires or the client stops before the Relay
  accepted the copy

## Throws

TypeError for a bundle value of the wrong type, or for a content
  adapter with no `serializeFirstSync`. Each type check runs before each
  range check.

## Throws

RangeError for a device ID that is not a safe integer of 2 or
  more, for a bundle value out of range, for serialized content larger
  than 196,608 bytes, and for an encrypted copy whose delivery wire is
  larger than 262,144 bytes. The content check is an early check before
  the encryption, so content of 196,608 bytes or less can still fail the
  wire check. The wire check runs after the encryption and before the
  post.

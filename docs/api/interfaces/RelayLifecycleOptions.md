[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RelayLifecycleOptions

# Interface: RelayLifecycleOptions

Options for `bindRelayLifecycle`.

## Properties

### keepOpenInBackground?

> `readonly` `optional` **keepOpenInBackground?**: `boolean`

Keep the relay socket open in the background, for example while an Android
foreground service runs. The binding then does nothing. Default: `false`.
